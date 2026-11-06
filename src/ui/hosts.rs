//! Hosts screen: folder tree on the left, host editor on the right, connect actions.
use super::app::LzApp;
use crate::connect::{launch_in_terminal, prepare_connect};
use crate::model::{Auth, Folder, Host};
use crate::vault::SecretKind;
use uuid::Uuid;

#[derive(Default)]
pub struct HostsState {
    /// Host being edited (a draft copy) and whether it is new.
    draft: Option<(Host, bool)>,
    new_folder: Option<String>,
    rename: Option<(Uuid, String)>,
    confirm_delete: Option<Uuid>,
    /// Set by the folder context menu; picked up by the send dialog (Task 8).
    pub send_request: Option<Option<Uuid>>,
}

/// Actions collected while drawing, applied afterwards (avoids borrowing app twice).
enum Action {
    Connect(Uuid, bool),
    Edit(Uuid),
    NewHost(Option<Uuid>),
    DeleteHost(Uuid),
    DeleteFolder(Uuid),
    Send(Option<Uuid>),
}

fn auth_kind(a: &Auth) -> SecretKind {
    match a {
        Auth::Password { .. } => SecretKind::Password,
        Auth::Key { .. } => SecretKind::SshKey,
        Auth::Fido { .. } => SecretKind::FidoKey,
    }
}

fn auth_with(kind: SecretKind, secret_id: Uuid) -> Auth {
    match kind {
        SecretKind::Password => Auth::Password { secret_id },
        SecretKind::SshKey => Auth::Key { secret_id },
        SecretKind::FidoKey => Auth::Fido { secret_id },
    }
}

fn new_host(folder_id: Option<Uuid>) -> Host {
    Host {
        id: Uuid::new_v4(),
        folder_id,
        name: String::new(),
        ipv4: None,
        ipv6: None,
        port: 22,
        username: String::new(),
        auth: Auth::Key { secret_id: Uuid::nil() },
    }
}

pub fn connect(app: &mut LzApp, id: Uuid, prefer_v6: bool) {
    let Some(host) = app.store.hosts.iter().find(|h| h.id == id).cloned() else { return };
    let Some(vault) = app.vault.as_ref() else { return };
    let r = prepare_connect(&host, vault, &app.run_dir, prefer_v6, &app.askpass).and_then(|inv| launch_in_terminal(&host.name, &inv));
    if let Err(e) = r {
        app.toast(format!("{}: {e}", host.name));
    }
}

fn host_row(ui: &mut egui::Ui, h: &Host, selected: bool, missing: bool, actions: &mut Vec<Action>) {
    let label = if missing { format!("{}  (secret missing)", h.name) } else { h.name.clone() };
    let r = ui.selectable_label(selected, label);
    if r.double_clicked() {
        actions.push(Action::Connect(h.id, false));
    } else if r.clicked() {
        actions.push(Action::Edit(h.id));
    }
    r.context_menu(|ui| {
        if ui.button("Connect").clicked() {
            actions.push(Action::Connect(h.id, false));
            ui.close();
        }
        if h.has_both() && ui.button("Connect via IPv6").clicked() {
            actions.push(Action::Connect(h.id, true));
            ui.close();
        }
        if ui.button("Edit").clicked() {
            actions.push(Action::Edit(h.id));
            ui.close();
        }
        if ui.button("Delete").clicked() {
            actions.push(Action::DeleteHost(h.id));
            ui.close();
        }
    });
}

fn tree(app: &mut LzApp, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
    let selected = app.hosts_ui.draft.as_ref().map(|(h, _)| h.id);
    let secret_ids: Vec<Uuid> = app.vault.as_ref().map(|v| v.list().iter().map(|m| m.id).collect()).unwrap_or_default();
    let missing = |h: &Host| !secret_ids.contains(&h.auth.secret_id());

    ui.horizontal(|ui| {
        if ui.button("New host").clicked() {
            actions.push(Action::NewHost(None));
        }
        if ui.button("New folder").clicked() {
            app.hosts_ui.new_folder = Some(String::new());
        }
        if ui.button("Send…").clicked() {
            actions.push(Action::Send(None));
        }
    });
    if let Some(mut name) = app.hosts_ui.new_folder.take() {
        let mut keep = true;
        ui.horizontal(|ui| {
            let r = ui.text_edit_singleline(&mut name);
            r.request_focus();
            let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (ui.button("Add").clicked() || enter) && !name.trim().is_empty() {
                app.store.folders.push(Folder { id: Uuid::new_v4(), name: name.trim().to_string() });
                keep = false;
                app.save_store();
            } else if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                keep = false;
            }
        });
        if keep {
            app.hosts_ui.new_folder = Some(name);
        }
    }
    ui.separator();

    let mut folders = app.store.folders.clone();
    folders.sort_by_key(|f| f.name.to_lowercase());
    let mut hosts = app.store.hosts.clone();
    hosts.sort_by_key(|h| h.name.to_lowercase());

    egui::ScrollArea::vertical().show(ui, |ui| {
        for f in &folders {
            let in_folder: Vec<&Host> = hosts.iter().filter(|h| h.folder_id == Some(f.id)).collect();
            if app.hosts_ui.rename.as_ref().is_some_and(|(id, _)| *id == f.id) {
                let (id, mut name) = app.hosts_ui.rename.take().expect("checked above");
                let mut keep = true;
                ui.horizontal(|ui| {
                    let r = ui.text_edit_singleline(&mut name);
                    let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if (ui.button("OK").clicked() || enter) && !name.trim().is_empty() {
                        let n = name.trim().to_string();
                        if let Some(sf) = app.store.folders.iter_mut().find(|x| x.id == id) {
                            sf.name = n;
                        }
                        keep = false;
                        app.save_store();
                    } else if ui.button("Cancel").clicked() {
                        keep = false;
                    }
                });
                if keep {
                    app.hosts_ui.rename = Some((id, name));
                }
                continue;
            }
            let header = egui::CollapsingHeader::new(format!("{} ({})", f.name, in_folder.len())).id_salt(f.id).default_open(true).show(ui, |ui| {
                for h in &in_folder {
                    host_row(ui, h, selected == Some(h.id), missing(h), actions);
                }
            });
            header.header_response.context_menu(|ui| {
                if ui.button("New host here").clicked() {
                    actions.push(Action::NewHost(Some(f.id)));
                    ui.close();
                }
                if ui.button("Send to…").clicked() {
                    actions.push(Action::Send(Some(f.id)));
                    ui.close();
                }
                if ui.button("Rename").clicked() {
                    app.hosts_ui.rename = Some((f.id, f.name.clone()));
                    ui.close();
                }
                let empty = in_folder.is_empty();
                if ui.add_enabled(empty, egui::Button::new("Delete folder")).on_disabled_hover_text("Only empty folders can be deleted").clicked() {
                    actions.push(Action::DeleteFolder(f.id));
                    ui.close();
                }
            });
        }
        let ungrouped: Vec<&Host> = hosts.iter().filter(|h| h.folder_id.is_none_or(|id| !app.store.folders.iter().any(|f| f.id == id))).collect();
        egui::CollapsingHeader::new(format!("Ungrouped ({})", ungrouped.len())).id_salt("ungrouped").default_open(true).show(ui, |ui| {
            for h in &ungrouped {
                host_row(ui, h, selected == Some(h.id), missing(h), actions);
            }
        });
    });
}

fn editor(app: &mut LzApp, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
    let folders = app.store.folders.clone();
    let secrets = app.vault.as_ref().map(|v| v.list()).unwrap_or_default();
    let Some((h, is_new)) = app.hosts_ui.draft.as_mut() else {
        ui.label("Select a host, or create one with \"New host\". Double-click a host to connect.");
        return;
    };
    ui.heading(if *is_new { "New host" } else { "Edit host" });
    ui.add_space(6.0);

    let mut ipv4 = h.ipv4.clone().unwrap_or_default();
    let mut ipv6 = h.ipv6.clone().unwrap_or_default();
    let mut kind = auth_kind(&h.auth);
    let mut secret_id = h.auth.secret_id();

    egui::Grid::new("host_form").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
        ui.label("Name");
        ui.add(egui::TextEdit::singleline(&mut h.name).desired_width(320.0));
        ui.end_row();
        ui.label("Folder");
        let cur = folders.iter().find(|f| Some(f.id) == h.folder_id).map(|f| f.name.clone()).unwrap_or_else(|| "Ungrouped".into());
        egui::ComboBox::from_id_salt("folder").selected_text(cur).show_ui(ui, |ui| {
            ui.selectable_value(&mut h.folder_id, None, "Ungrouped");
            for f in &folders {
                ui.selectable_value(&mut h.folder_id, Some(f.id), &f.name);
            }
        });
        ui.end_row();
        ui.label("IPv4 / hostname");
        ui.add(egui::TextEdit::singleline(&mut ipv4).desired_width(320.0));
        ui.end_row();
        ui.label("IPv6");
        ui.add(egui::TextEdit::singleline(&mut ipv6).desired_width(320.0));
        ui.end_row();
        ui.label("Port");
        ui.add(egui::DragValue::new(&mut h.port).range(1..=65535));
        ui.end_row();
        ui.label("Username");
        ui.add(egui::TextEdit::singleline(&mut h.username).desired_width(320.0));
        ui.end_row();
        ui.label("Authentication");
        egui::ComboBox::from_id_salt("auth").selected_text(kind.label()).show_ui(ui, |ui| {
            for k in [SecretKind::SshKey, SecretKind::FidoKey, SecretKind::Password] {
                ui.selectable_value(&mut kind, k, k.label());
            }
        });
        ui.end_row();
        ui.label("Secret");
        let matching: Vec<_> = secrets.iter().filter(|m| m.kind == kind).collect();
        let cur = matching.iter().find(|m| m.id == secret_id).map(|m| m.name.clone());
        let text = match (&cur, secret_id.is_nil()) {
            (Some(n), _) => n.clone(),
            (None, true) => "Choose…".into(),
            (None, false) => "Secret missing".into(),
        };
        egui::ComboBox::from_id_salt("secret").selected_text(text).show_ui(ui, |ui| {
            for m in &matching {
                ui.selectable_value(&mut secret_id, m.id, &m.name);
            }
            if matching.is_empty() {
                ui.label(format!("No {} in Secrets yet", kind.label()));
            }
        });
        ui.end_row();
    });

    let opt = |s: String| Some(s.trim().to_string()).filter(|s| !s.is_empty());
    h.ipv4 = opt(ipv4);
    h.ipv6 = opt(ipv6);
    if kind != auth_kind(&h.auth) && !secrets.iter().any(|m| m.id == secret_id && m.kind == kind) {
        secret_id = Uuid::nil();
    }
    h.auth = auth_with(kind, secret_id);

    let error = h.validate().err().map(|e| e.to_string()).or_else(|| secret_id.is_nil().then(|| "Choose a secret".to_string()));
    ui.add_space(8.0);
    let mut save = false;
    let mut cancel = false;
    ui.horizontal(|ui| {
        save = ui.add_enabled(error.is_none(), egui::Button::new("Save")).clicked();
        cancel = ui.button("Close").clicked();
        if !*is_new && ui.button("Connect").clicked() {
            actions.push(Action::Connect(h.id, false));
        }
    });
    if let Some(e) = error {
        ui.colored_label(ui.visuals().warn_fg_color, e);
    }
    if save {
        let host = h.clone();
        *is_new = false;
        match app.store.hosts.iter_mut().find(|x| x.id == host.id) {
            Some(x) => *x = host,
            None => app.store.hosts.push(host),
        }
        app.save_store();
        app.toast("Saved");
    }
    if cancel {
        app.hosts_ui.draft = None;
    }
}

pub fn show(app: &mut LzApp, ui: &mut egui::Ui) {
    let mut actions = Vec::new();
    egui::Panel::left("hosts_tree").resizable(true).default_size(320.0).show(ui, |ui| tree(app, ui, &mut actions));
    egui::CentralPanel::default().show(ui, |ui| {
        if let Some(id) = app.hosts_ui.confirm_delete {
            let name = app.store.hosts.iter().find(|h| h.id == id).map(|h| h.name.clone()).unwrap_or_default();
            ui.horizontal(|ui| {
                ui.label(format!("Delete host \"{name}\"?"));
                if ui.button("Delete").clicked() {
                    app.store.hosts.retain(|h| h.id != id);
                    if app.hosts_ui.draft.as_ref().is_some_and(|(h, _)| h.id == id) {
                        app.hosts_ui.draft = None;
                    }
                    app.hosts_ui.confirm_delete = None;
                    app.save_store();
                }
                if ui.button("Keep").clicked() {
                    app.hosts_ui.confirm_delete = None;
                }
            });
            ui.separator();
        }
        editor(app, ui, &mut actions);
    });

    for a in actions {
        match a {
            Action::Connect(id, v6) => connect(app, id, v6),
            Action::Edit(id) => {
                if let Some(h) = app.store.hosts.iter().find(|h| h.id == id) {
                    app.hosts_ui.draft = Some((h.clone(), false));
                }
            }
            Action::NewHost(folder) => app.hosts_ui.draft = Some((new_host(folder), true)),
            Action::DeleteHost(id) => app.hosts_ui.confirm_delete = Some(id),
            Action::DeleteFolder(id) => {
                if !app.store.hosts.iter().any(|h| h.folder_id == Some(id)) {
                    app.store.folders.retain(|f| f.id != id);
                    app.save_store();
                }
            }
            Action::Send(folder) => app.hosts_ui.send_request = Some(folder),
        }
    }
}
