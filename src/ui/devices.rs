//! Devices screen (pairing) and the "Send to device" dialog.
use super::app::LzApp;
use crate::device::{DEFAULT_SERVER, ServerConfig};
use crate::sync::mailbox::NetCmd;
use crate::sync::payload::{FolderSel, build_payload};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use uuid::Uuid;

const CODE_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Default)]
pub struct DevicesState {
    code: Option<(String, Instant)>,
    waiting_for_code: bool,
    entered: String,
    name_edit: Option<String>,
    confirm_remove: Option<String>,
    send: Option<SendDialog>,
    /// Edit buffers for the sync server; None until the section is first shown.
    server_url: Option<String>,
    server_token: String,
}

struct SendDialog {
    folders: HashSet<Option<Uuid>>,
    secrets: HashSet<Uuid>,
    target: Option<String>,
}

impl DevicesState {
    pub fn set_code(&mut self, c: String) {
        self.code = Some((c, Instant::now()));
        self.waiting_for_code = false;
    }
    pub fn clear_code(&mut self) {
        self.code = None;
        self.entered.clear();
    }
    pub fn stop_waiting(&mut self) {
        self.waiting_for_code = false;
    }
    /// Reload the server fields from device.json next frame (after a pairing code changed it).
    pub fn forget_server_edit(&mut self) {
        self.server_url = None;
        self.server_token.clear();
    }
}

fn server_section(app: &mut LzApp, ui: &mut egui::Ui) {
    ui.heading("Sync server");
    let current = app.device.as_ref().and_then(|d| d.server.clone());
    let st = &mut app.devices_ui;
    let url = st.server_url.get_or_insert_with(|| current.as_ref().map_or(DEFAULT_SERVER.to_string(), |c| c.url.clone()));
    ui.horizontal(|ui| {
        ui.label("URL:");
        ui.add(egui::TextEdit::singleline(url).desired_width(280.0));
    });
    let hint = if current.is_some() { "Leave empty to keep the saved token" } else { "Access token" };
    ui.horizontal(|ui| {
        ui.label("Token:");
        ui.add(egui::TextEdit::singleline(&mut st.server_token).password(true).hint_text(hint).desired_width(280.0));
    });
    let url_t = url.trim().trim_end_matches('/').to_string();
    let token = if st.server_token.trim().is_empty() { current.as_ref().map(|c| c.token.clone()) } else { Some(st.server_token.trim().to_string()) };
    let valid = url_t.starts_with("https://") && token.is_some();
    let changed = current.as_ref().map(|c| (&c.url, Some(&c.token))) != Some((&url_t, token.as_ref()));
    let mut save = None;
    ui.horizontal(|ui| {
        if ui.add_enabled(valid && changed, egui::Button::new("Save")).clicked() {
            save = token.clone().map(|t| ServerConfig { url: url_t.clone(), token: t });
        }
        match &current {
            Some(_) => ui.weak("Other devices get the server and token from the pairing code."),
            None => ui.weak("Needed on the first device only. Other devices get it from the pairing code."),
        };
    });
    if let Some(cfg) = save {
        if let Some(d) = app.device.as_mut() {
            d.server = Some(cfg);
        }
        app.devices_ui.forget_server_edit();
        app.save_device();
        app.restart_sync();
        app.toast("Sync server saved");
    }
}

pub fn show(app: &mut LzApp, ui: &mut egui::Ui) {
    if app.device.is_none() {
        ui.label("Sync is not available (device identity could not be loaded).");
        return;
    }
    ui.heading("This device");
    ui.horizontal(|ui| {
        ui.label("Name:");
        if let Some(n) = app.devices_ui.name_edit.as_mut() {
            ui.text_edit_singleline(n);
            if ui.button("Save").clicked() && !n.trim().is_empty() {
                let n = n.trim().to_string();
                if let Some(d) = app.device.as_mut() {
                    d.name = n;
                }
                app.devices_ui.name_edit = None;
                app.save_device();
                app.toast("Name saved. Paired devices see it after the next pairing.");
            }
        } else {
            let name = app.device.as_ref().map(|d| d.name.clone()).unwrap_or_default();
            ui.strong(&name);
            if ui.small_button("Rename").clicked() {
                app.devices_ui.name_edit = Some(name);
            }
        }
    });
    match &app.node_id {
        Some(id) => ui.weak(format!("Device ID {id}")),
        None => ui.weak("Starting sync…"),
    };
    ui.separator();

    server_section(app, ui);
    ui.separator();

    ui.heading("Paired devices");
    let paired = app.paired.read().expect("paired lock").clone();
    if paired.is_empty() {
        ui.label("None yet.");
    }
    let mut remove = None;
    for d in &paired {
        ui.horizontal(|ui| {
            ui.label(&d.name);
            ui.weak(crate::device::short_id(&d.node_id, 16));
            if app.devices_ui.confirm_remove.as_deref() == Some(d.node_id.as_str()) {
                if ui.button("Really remove").clicked() {
                    remove = Some(d.node_id.clone());
                }
                if ui.button("Keep").clicked() {
                    app.devices_ui.confirm_remove = None;
                }
            } else if ui.button("Remove").on_hover_text("This device stops accepting data from it").clicked() {
                app.devices_ui.confirm_remove = Some(d.node_id.clone());
            }
        });
    }
    if let Some(id) = remove {
        app.paired.write().expect("paired lock").retain(|d| d.node_id != id);
        app.devices_ui.confirm_remove = None;
        app.save_device();
        app.send_cmd(NetCmd::Unpair(id));
    }
    ui.separator();

    ui.heading("Pair a new device");
    ui.columns(2, |cols| {
        let ui = &mut cols[0];
        ui.strong("Show a code on this device");
        match &app.devices_ui.code {
            Some((c, at)) if at.elapsed() < CODE_TTL => {
                let left = CODE_TTL - at.elapsed();
                ui.add(egui::Label::new(egui::RichText::new(c).monospace()).wrap_mode(egui::TextWrapMode::Wrap).selectable(true));
                ui.horizontal(|ui| {
                    if ui.button("Copy code").clicked() {
                        ui.ctx().copy_text(c.clone());
                    }
                    ui.label(format!("valid for {}:{:02}", left.as_secs() / 60, left.as_secs() % 60));
                });
                ui.label("Enter it on the other device within 10 minutes. Keep lzssh open here until both show the pairing.");
                ui.ctx().request_repaint_after(Duration::from_secs(1));
            }
            _ => {
                if app.devices_ui.waiting_for_code {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Creating code…");
                    });
                } else if ui.button("Pair new device").clicked() {
                    app.devices_ui.waiting_for_code = true;
                    if let Some((tx, _)) = &app.net {
                        let _ = tx.send(NetCmd::StartPairing);
                    }
                }
            }
        }
        let ui = &mut cols[1];
        ui.strong("Enter a code from another device");
        ui.add(egui::TextEdit::multiline(&mut app.devices_ui.entered).desired_rows(3).hint_text("LZ2-…").font(egui::TextStyle::Monospace));
        if ui.add_enabled(!app.devices_ui.entered.trim().is_empty(), egui::Button::new("Pair")).clicked() {
            let c = app.devices_ui.entered.clone();
            if let Some((tx, _)) = &app.net {
                let _ = tx.send(NetCmd::EnterCode(c));
            }
            app.toast("Pairing request sent. Waiting for the other device…");
        }
    });
}

/// Opens when the Hosts screen requests it (toolbar "Send…" or folder "Send to…").
pub fn send_dialog(app: &mut LzApp, ui: &mut egui::Ui) {
    if let Some(pre) = app.hosts_ui.send_request.take() {
        let mut folders = HashSet::new();
        if let Some(f) = pre {
            folders.insert(Some(f));
        }
        let target = app.paired.read().expect("paired lock").first().map(|d| d.node_id.clone());
        app.devices_ui.send = Some(SendDialog { folders, secrets: HashSet::new(), target });
    }
    let Some(dlg) = app.devices_ui.send.as_mut() else { return };
    let paired = app.paired.read().expect("paired lock").clone();
    let secrets = app.vault.as_ref().map(|v| v.list()).unwrap_or_default();
    let mut folders = app.store.folders.clone();
    folders.sort_by_key(|f| f.name.to_lowercase());
    let mut open = true;
    let mut send = false;
    egui::Window::new("Send to device").collapsible(false).resizable(true).open(&mut open).show(ui.ctx(), |ui| {
        if paired.is_empty() {
            ui.label("No paired devices. Pair one on the Devices screen first.");
            return;
        }
        ui.columns(2, |cols| {
            cols[0].strong("Folders");
            egui::ScrollArea::vertical().id_salt("send_folders").max_height(300.0).show(&mut cols[0], |ui| {
                let mut toggle = |ui: &mut egui::Ui, key: Option<Uuid>, label: &str| {
                    let mut on = dlg.folders.contains(&key);
                    if ui.checkbox(&mut on, label).changed() {
                        if on {
                            dlg.folders.insert(key);
                        } else {
                            dlg.folders.remove(&key);
                        }
                    }
                };
                for f in &folders {
                    toggle(ui, Some(f.id), &f.name);
                }
                toggle(ui, None, "Ungrouped");
            });
            cols[1].strong("Secrets");
            egui::ScrollArea::vertical().id_salt("send_secrets").max_height(300.0).show(&mut cols[1], |ui| {
                if secrets.is_empty() {
                    ui.weak("No secrets");
                }
                for m in &secrets {
                    let mut on = dlg.secrets.contains(&m.id);
                    if ui.checkbox(&mut on, format!("{} ({})", m.name, m.kind.label())).changed() {
                        if on {
                            dlg.secrets.insert(m.id);
                        } else {
                            dlg.secrets.remove(&m.id);
                        }
                    }
                }
            });
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("To:");
            let cur = paired.iter().find(|d| Some(&d.node_id) == dlg.target.as_ref()).map(|d| d.name.clone()).unwrap_or_else(|| "Choose…".into());
            egui::ComboBox::from_id_salt("send_target").selected_text(cur).show_ui(ui, |ui| {
                for d in &paired {
                    ui.selectable_value(&mut dlg.target, Some(d.node_id.clone()), &d.name);
                }
            });
            let ready = dlg.target.is_some() && (!dlg.folders.is_empty() || !dlg.secrets.is_empty());
            send = ui.add_enabled(ready, egui::Button::new("Send")).clicked();
        });
        ui.weak("It arrives the next time the other device has lzssh unlocked.");
    });
    if send {
        let sel: Vec<FolderSel> = dlg.folders.iter().map(|f| f.map_or(FolderSel::Ungrouped, FolderSel::Folder)).collect();
        let ids: Vec<Uuid> = dlg.secrets.iter().copied().collect();
        let to = dlg.target.clone().expect("checked by ready");
        app.devices_ui.send = None;
        let Some(vault) = app.vault.as_ref() else { return };
        match build_payload(&app.store, vault, &sel, &ids) {
            Ok(p) => {
                app.send_cmd(NetCmd::Send { to, payload: p });
                app.toast("Sending…");
            }
            Err(e) => app.toast(format!("Could not prepare data: {e}")),
        }
    } else if !open {
        app.devices_ui.send = None;
    }
}
