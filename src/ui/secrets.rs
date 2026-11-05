//! Secrets screen: list, import SSH key / FIDO handle, add password, delete.
use super::app::LzApp;
use crate::keys::{FidoKey, FidoType, create_fido_key, public_key_for};
use std::sync::mpsc::Receiver;
use crate::vault::{PlainSecret, SecretKind};
use std::path::PathBuf;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Default)]
pub struct SecretsState {
    form: Option<Form>,
    confirm_delete: Option<Uuid>,
    create: Option<CreateFido>,
}

struct CreateFido {
    name: String,
    kind: FidoType,
    error: Option<String>,
    /// Set while ssh-keygen runs (the Windows security-key dialog is open).
    pending: Option<Receiver<Result<FidoKey, String>>>,
}

struct Form {
    kind: SecretKind,
    name: String,
    file: Option<PathBuf>,
    passphrase: Zeroizing<String>,
    password: Zeroizing<String>,
    error: Option<String>,
}

impl Form {
    fn new(kind: SecretKind) -> Self {
        Form { kind, name: String::new(), file: None, passphrase: Default::default(), password: Default::default(), error: None }
    }
}

fn build(f: &Form) -> Result<PlainSecret, String> {
    let name = f.name.trim();
    if name.is_empty() {
        return Err("Enter a name".into());
    }
    let (material, public_key, passphrase) = match f.kind {
        SecretKind::Password => {
            if f.password.is_empty() {
                return Err("Enter the password".into());
            }
            (Zeroizing::new(f.password.as_bytes().to_vec()), None, None)
        }
        SecretKind::SshKey | SecretKind::FidoKey => {
            let path = f.file.as_ref().ok_or("Pick a key file")?;
            let bytes = Zeroizing::new(std::fs::read(path).map_err(|e| format!("Cannot read key file: {e}"))?);
            let pub_path = PathBuf::from(format!("{}.pub", path.display()));
            let sibling = std::fs::read_to_string(&pub_path).ok();
            let pp = Some(f.passphrase.as_str()).filter(|p| !p.is_empty());
            let pk = public_key_for(&bytes, sibling.as_deref(), pp)?;
            (bytes, Some(pk), pp.map(|p| Zeroizing::new(p.to_string())))
        }
    };
    Ok(PlainSecret { id: Uuid::new_v4(), name: name.to_string(), kind: f.kind, public_key, material, passphrase })
}

pub fn show(app: &mut LzApp, ui: &mut egui::Ui) {
    let Some(vault) = app.vault.as_mut() else { return };
    let mut toast: Option<String> = None;
    let mut changed = false;

    ui.horizontal(|ui| {
        if ui.button("Import SSH key").clicked() {
            app.secrets_ui.form = Some(Form::new(SecretKind::SshKey));
        }
        if ui.button("Create FIDO key").clicked() {
            app.secrets_ui.create = Some(CreateFido { name: "YubiKey".into(), kind: FidoType::Ed25519Sk, error: None, pending: None });
        }
        if ui.button("Import FIDO key file").clicked() {
            app.secrets_ui.form = Some(Form::new(SecretKind::FidoKey));
        }
        if ui.button("Add password").clicked() {
            app.secrets_ui.form = Some(Form::new(SecretKind::Password));
        }
    });
    ui.separator();

    if let Some(c) = app.secrets_ui.create.as_mut() {
        let mut close = false;
        if let Some(rx) = &c.pending {
            match rx.try_recv() {
                Ok(Ok(k)) => {
                    let s = PlainSecret {
                        id: Uuid::new_v4(),
                        name: c.name.trim().to_string(),
                        kind: SecretKind::FidoKey,
                        public_key: Some(k.public_key),
                        material: k.handle,
                        passphrase: None,
                    };
                    match vault.upsert(s) {
                        Ok(()) => {
                            changed = true;
                            toast = Some(format!("Created FIDO key {}", c.name.trim()));
                            close = true;
                        }
                        Err(e) => c.error = Some(e.to_string()),
                    }
                    c.pending = None;
                }
                Ok(Err(e)) => {
                    c.error = Some(e);
                    c.pending = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => ui.ctx().request_repaint_after(std::time::Duration::from_millis(200)),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    c.error = Some("Key creation failed".into());
                    c.pending = None;
                }
            }
        }
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.strong("Create FIDO key");
            ui.label("Windows will ask you to touch your security key or confirm with Windows Hello.");
            ui.add_enabled_ui(c.pending.is_none(), |ui| {
                egui::Grid::new("fido_form").num_columns(2).show(ui, |ui| {
                    ui.label("Name");
                    ui.text_edit_singleline(&mut c.name);
                    ui.end_row();
                    ui.label("Type");
                    ui.vertical(|ui| {
                        for t in [FidoType::Ed25519Sk, FidoType::EcdsaSk] {
                            ui.radio_value(&mut c.kind, t, t.label());
                        }
                    });
                    ui.end_row();
                });
            });
            if let Some(e) = &c.error {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            ui.horizontal(|ui| {
                if c.pending.is_some() {
                    ui.spinner();
                    ui.label("Waiting for the Windows security dialog…");
                } else {
                    if ui.add_enabled(!c.name.trim().is_empty(), egui::Button::new("Create")).clicked() {
                        let (tx, rx) = std::sync::mpsc::channel();
                        let (kind, dir, comment) = (c.kind, app.run_dir.clone(), format!("lzssh {}", c.name.trim()));
                        let ctx = ui.ctx().clone();
                        std::thread::spawn(move || {
                            let _ = tx.send(create_fido_key(kind, &dir, &comment));
                            ctx.request_repaint();
                        });
                        c.error = None;
                        c.pending = Some(rx);
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                }
            });
        });
        if close {
            app.secrets_ui.create = None;
        }
        ui.separator();
    }

    if let Some(f) = app.secrets_ui.form.as_mut() {
        let mut close = false;
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.strong(match f.kind {
                SecretKind::SshKey => "Import SSH private key",
                SecretKind::FidoKey => "Import FIDO key handle (e.g. id_ed25519_sk)",
                SecretKind::Password => "Add password",
            });
            egui::Grid::new("secret_form").num_columns(2).show(ui, |ui| {
                if f.kind != SecretKind::Password {
                    ui.label("File");
                    ui.horizontal(|ui| {
                        if ui.button("Choose…").clicked() {
                            let start = dirs::home_dir().map(|h| h.join(".ssh")).unwrap_or_default();
                            if let Some(p) = rfd::FileDialog::new().set_directory(start).pick_file() {
                                if f.name.is_empty() {
                                    f.name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                                }
                                f.file = Some(p);
                            }
                        }
                        ui.label(f.file.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "no file".into()));
                    });
                    ui.end_row();
                }
                ui.label("Name");
                ui.text_edit_singleline(&mut f.name);
                ui.end_row();
                match f.kind {
                    SecretKind::Password => {
                        ui.label("Password");
                        ui.add(egui::TextEdit::singleline(&mut *f.password).password(true));
                    }
                    _ => {
                        ui.label("Passphrase (if any)");
                        ui.add(egui::TextEdit::singleline(&mut *f.passphrase).password(true));
                    }
                }
                ui.end_row();
            });
            if let Some(e) = &f.error {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    match build(f) {
                        Ok(s) => {
                            let name = s.name.clone();
                            match vault.upsert(s) {
                                Ok(()) => {
                                    changed = true;
                                    toast = Some(format!("Added {name}"));
                                    close = true;
                                }
                                Err(e) => f.error = Some(e.to_string()),
                            }
                        }
                        Err(e) => f.error = Some(e),
                    }
                }
                if ui.button("Cancel").clicked() {
                    close = true;
                }
            });
        });
        if close {
            app.secrets_ui.form = None;
        }
        ui.separator();
    }

    let list = vault.list();
    if list.is_empty() {
        ui.label("No secrets yet.");
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("secrets").striped(true).num_columns(4).show(ui, |ui| {
            for m in &list {
                ui.label(&m.name);
                ui.label(m.kind.label());
                match &m.public_key {
                    Some(pk) => {
                        let short: String = if pk.chars().count() > 60 { format!("{}…", pk.chars().take(60).collect::<String>()) } else { pk.clone() };
                        ui.horizontal(|ui| {
                            ui.monospace(short);
                            if ui.small_button("Copy").clicked() {
                                ui.ctx().copy_text(pk.clone());
                            }
                        });
                    }
                    None => {
                        ui.label("");
                    }
                }
                if app.secrets_ui.confirm_delete == Some(m.id) {
                    ui.horizontal(|ui| {
                        if ui.button("Really delete").clicked() {
                            vault.remove(m.id);
                            changed = true;
                            app.secrets_ui.confirm_delete = None;
                        }
                        if ui.button("Keep").clicked() {
                            app.secrets_ui.confirm_delete = None;
                        }
                    });
                } else if ui.button("Delete").clicked() {
                    app.secrets_ui.confirm_delete = Some(m.id);
                }
                ui.end_row();
            }
        });
    });

    if changed {
        app.save_vault();
    }
    if let Some(t) = toast {
        app.toast(t);
    }
}
