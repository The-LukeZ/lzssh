//! First-run "Set PIN" and "Enter PIN" screens. Fields are masked, accept paste, Enter submits.
use super::app::{LzApp, Screen};
use crate::vault::{Vault, normalize_pin};
use zeroize::Zeroizing;

#[derive(Default)]
pub struct UnlockState {
    pin: Zeroizing<String>,
    repeat: Zeroizing<String>,
    error: Option<String>,
}

pub fn show(app: &mut LzApp, ui: &mut egui::Ui) {
    let creating = !Vault::exists(&app.secrets_path);
    let mut submit = false;
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() / 4.0);
        ui.heading(if creating { "Set a 6-digit PIN" } else { "Enter PIN" });
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
        if let Some(e) = &app.unlock.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
    });
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
            Ok(v) => {
                app.vault = Some(v);
                app.unlock = UnlockState::default();
                app.screen = Screen::Hosts;
                app.on_unlocked();
            }
            Err(e) => {
                app.unlock.error = Some(e);
                app.unlock.pin = Zeroizing::default();
                app.unlock.repeat = Zeroizing::default();
            }
        }
    }
}
