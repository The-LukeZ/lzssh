//! Quick unlock setup (shown on the Settings screen) and background-job helpers shared with the PIN screen.
use super::app::LzApp;
use crate::quick_unlock::{self as qu, Owner, Secret};
use crate::vault::{UnlockKind, UnlockMethod};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;
use uuid::Uuid;

pub type Job<T> = Receiver<Result<T, String>>;

/// Runs `f` on a worker thread (Windows dialogs block) and repaints when it is done.
pub fn spawn<T: Send + 'static>(ctx: &egui::Context, f: impl FnOnce() -> anyhow::Result<T> + Send + 'static) -> Job<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        let _ = tx.send(f().map_err(|e| e.to_string()));
        ctx.request_repaint();
    });
    rx
}

/// Takes the job's result once it is there.
pub fn poll<T>(job: &mut Option<Job<T>>, ctx: &egui::Context) -> Option<Result<T, String>> {
    let r = match job.as_ref()?.try_recv() {
        Ok(r) => r,
        Err(TryRecvError::Empty) => {
            ctx.request_repaint_after(Duration::from_millis(200));
            return None;
        }
        Err(TryRecvError::Disconnected) => Err("Failed".into()),
    };
    *job = None;
    Some(r)
}

pub fn method_label(m: &UnlockMethod) -> String {
    match m.kind {
        UnlockKind::WindowsHello => "Windows Hello".into(),
        UnlockKind::SecurityKey => format!("Security key: {}", m.name),
    }
}

#[derive(Default)]
pub struct QuickUnlockState {
    /// (Windows Hello, security key) support, checked once off the UI thread.
    available: Option<(bool, bool)>,
    available_job: Option<Job<(bool, bool)>>,
    key_name: String,
    enrolling: Option<Job<(UnlockMethod, Secret)>>,
    error: Option<String>,
    confirm_remove: Option<Uuid>,
}

pub fn settings(app: &mut LzApp, ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    let st = &mut app.quick_ui;
    if st.available.is_none() && st.available_job.is_none() {
        st.available_job = Some(spawn(&ctx, || Ok((qu::hello_available(), qu::security_key_available()))));
    }
    if let Some(r) = poll(&mut st.available_job, &ctx) {
        st.available = Some(r.unwrap_or((false, false)));
    }
    let mut toast = None;
    let mut save = false;
    let Some(vault) = app.vault.as_mut() else { return };
    if let Some(r) = poll(&mut st.enrolling, &ctx) {
        match r {
            Ok((m, secret)) => {
                vault.add_unlock_method(m.clone(), &secret);
                save = true;
                toast = Some(format!("Quick unlock added: {}", method_label(&m)));
            }
            Err(e) => st.error = Some(e),
        }
    }
    let methods = vault.unlock_methods();
    egui::CollapsingHeader::new("Quick unlock").default_open(true).show(ui, |ui| {
        ui.label("Unlock lzssh with Windows Hello or a security key instead of typing the PIN. The PIN keeps working.");
        let mut remove = None;
        for m in &methods {
            ui.horizontal(|ui| {
                ui.label(method_label(m));
                if st.confirm_remove == Some(m.id) {
                    if ui.button("Really remove").clicked() {
                        remove = Some(m.id);
                    }
                    if ui.button("Keep").clicked() {
                        st.confirm_remove = None;
                    }
                } else if ui.small_button("Remove").clicked() {
                    st.confirm_remove = Some(m.id);
                }
            });
        }
        if let Some(id) = remove {
            vault.remove_unlock_method(id);
            st.confirm_remove = None;
            save = true;
        }
        let busy = st.enrolling.is_some();
        match st.available {
            None => {
                ui.spinner();
            }
            Some((hello, key)) => {
                ui.add_enabled_ui(!busy, |ui| {
                    ui.horizontal(|ui| {
                        if hello {
                            let has = methods.iter().any(|m| m.kind == UnlockKind::WindowsHello);
                            if ui.button(if has { "Set up Windows Hello again" } else { "Set up Windows Hello" }).clicked() {
                                st.error = None;
                                st.enrolling = Some(spawn(&ctx, || qu::enroll(UnlockKind::WindowsHello, "Windows Hello", Owner::current())));
                            }
                        } else {
                            ui.weak("Windows Hello is not set up on this PC.");
                        }
                    });
                    ui.horizontal(|ui| {
                        if key {
                            ui.add(egui::TextEdit::singleline(&mut st.key_name).hint_text("Key name, e.g. YubiKey").desired_width(220.0));
                            let name = st.key_name.trim().to_string();
                            if ui.add_enabled(!name.is_empty(), egui::Button::new("Add security key")).on_hover_text("You will touch the key twice").clicked() {
                                st.error = None;
                                st.key_name.clear();
                                let owner = Owner::current();
                                st.enrolling = Some(spawn(&ctx, move || qu::enroll(UnlockKind::SecurityKey, &name, owner)));
                            }
                        } else {
                            ui.weak("Security key unlock needs Windows 11.");
                        }
                    });
                });
            }
        }
        if busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Waiting for the Windows dialog…");
            });
        }
        if let Some(e) = &st.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
    });
    if save {
        app.save_vault();
    }
    if let Some(t) = toast {
        app.toast(t);
    }
}
