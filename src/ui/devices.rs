//! Devices screen (pairing) and the "Send to device" dialog.
use super::app::LzApp;
use crate::sync::net::NetCmd;
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
        Some(id) => ui.weak(format!("Node ID {id}")),
        None => ui.weak("Starting network…"),
    };
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
            } else if ui.button("Remove").on_hover_text("Removes it on this device only").clicked() {
                app.devices_ui.confirm_remove = Some(d.node_id.clone());
            }
        });
    }
    if let Some(id) = remove {
        app.paired.write().expect("paired lock").retain(|d| d.node_id != id);
        app.devices_ui.confirm_remove = None;
        app.save_device();
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
                ui.label("Enter it on the other device. Keep lzssh open here.");
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
        ui.add(egui::TextEdit::multiline(&mut app.devices_ui.entered).desired_rows(3).hint_text("LZ1-…").font(egui::TextStyle::Monospace));
        if ui.add_enabled(!app.devices_ui.entered.trim().is_empty(), egui::Button::new("Pair")).clicked() {
            let c = app.devices_ui.entered.clone();
            if let Some((tx, _)) = &app.net {
                let _ = tx.send(NetCmd::EnterCode(c));
            }
            app.toast("Connecting…");
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
        ui.weak("The other device must have lzssh open and unlocked.");
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
