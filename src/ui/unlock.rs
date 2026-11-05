//! First-run "Set PIN" and "Enter PIN" screens. Fields are masked, accept paste, Enter submits.
use super::app::{LzApp, Screen};
use super::quick_unlock::{Job, method_label, poll, spawn};
use crate::quick_unlock::{self as qu, Owner, Secret};
use crate::vault::{UnlockKind, UnlockMethod, Vault, normalize_pin};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Default)]
pub struct UnlockState {
    pin: Zeroizing<String>,
    repeat: Zeroizing<String>,
    error: Option<String>,
    /// Quick-unlock methods from the vault file, read once.
    methods: Option<Vec<UnlockMethod>>,
    /// Windows Hello is started automatically once per launch.
    auto_started: bool,
    /// The running quick unlock: method ID and the authenticator job.
    quick_id: Option<Uuid>,
    quick: Option<Job<Secret>>,
}

fn start_quick(app: &mut LzApp, ctx: &egui::Context, m: UnlockMethod) {
    let owner = Owner::current();
    app.unlock.error = None;
    app.unlock.quick_id = Some(m.id);
    app.unlock.quick = Some(spawn(ctx, move || qu::authenticate(&m, owner)));
}

fn finish(app: &mut LzApp, v: Vault) {
    app.vault = Some(v);
    app.unlock = UnlockState::default();
    app.screen = Screen::Hosts;
    app.on_unlocked();
}

/// Quick-unlock buttons under the PIN field. Returns true when the vault was unlocked.
fn quick_unlock(app: &mut LzApp, ui: &mut egui::Ui) -> bool {
    let ctx = ui.ctx().clone();
    let methods = app.unlock.methods.get_or_insert_with(|| Vault::read_unlock_methods(&app.secrets_path).unwrap_or_default()).clone();
    if methods.is_empty() {
        return false;
    }
    if !app.unlock.auto_started {
        app.unlock.auto_started = true;
        if let Some(h) = methods.iter().find(|m| m.kind == UnlockKind::WindowsHello) {
            start_quick(app, &ctx, h.clone());
        }
    }
    if let (Some(r), Some(id)) = (poll(&mut app.unlock.quick, &ctx), app.unlock.quick_id) {
        match r.and_then(|s| Vault::unlock_with(&app.secrets_path, id, &s).map_err(|e| e.to_string())) {
            Ok(v) => {
                finish(app, v);
                return true;
            }
            Err(e) => app.unlock.error = Some(e),
        }
    }
    ui.add_space(8.0);
    ui.weak("or");
    let busy = app.unlock.quick.is_some();
    let mut start = None;
    for m in &methods {
        if ui.add_enabled(!busy, egui::Button::new(format!("Unlock with {}", method_label(m)))).clicked() {
            start = Some(m.clone());
        }
    }
    if busy {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Waiting for the Windows dialog…");
        });
    }
    if let Some(m) = start {
        start_quick(app, &ctx, m);
    }
    false
}

pub fn show(app: &mut LzApp, ui: &mut egui::Ui) {
    let creating = !Vault::exists(&app.secrets_path);
    let mut submit = false;
    let mut unlocked = false;
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() / 4.0);
        ui.heading(if creating { "Set a PIN (6 to 256 digits)" } else { "Enter PIN" });
        if creating {
            ui.label("The PIN encrypts your secrets. There is no recovery if you forget it.");
        }
        ui.add_space(8.0);
        let r = ui.add(egui::TextEdit::singleline(&mut *app.unlock.pin).password(true).hint_text("PIN").desired_width(160.0));
        if !r.has_focus() && app.unlock.pin.is_empty() && app.unlock.error.is_none() {
            r.request_focus();
        }
        let enter = |r: &egui::Response, ui: &egui::Ui| r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        submit |= enter(&r, ui);
        if creating {
            let r2 = ui.add(egui::TextEdit::singleline(&mut *app.unlock.repeat).password(true).hint_text("Repeat PIN").desired_width(160.0));
            submit |= enter(&r2, ui);
        }
        submit |= ui.button(if creating { "Set PIN" } else { "Unlock" }).clicked();
        if !creating && quick_unlock(app, ui) {
            unlocked = true;
            return;
        }
        if let Some(e) = &app.unlock.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
    });
    if unlocked {
        return;
    }
    if submit {
        let result = if creating {
            match (normalize_pin(&app.unlock.pin), normalize_pin(&app.unlock.repeat)) {
                (Ok(a), Ok(b)) if a != b => Err("PINs do not match".to_string()),
                (Ok(a), Ok(_)) => Vault::create(&app.secrets_path, &a).and_then(|v| v.save().map(|_| v)).map_err(|e| e.to_string()),
                (Err(e), _) | (_, Err(e)) => Err(e.to_string()),
            }
        } else {
            Vault::unlock(&app.secrets_path, &app.unlock.pin).map_err(|e| e.to_string())
        };
        match result {
            Ok(v) => finish(app, v),
            Err(e) => {
                app.unlock.error = Some(e);
                app.unlock.pin = Zeroizing::default();
                app.unlock.repeat = Zeroizing::default();
            }
        }
    }
}
