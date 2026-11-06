//! Settings screen: password hotkey and Quick unlock.
use super::app::LzApp;
use crate::settings::Hotkey;

#[derive(Default)]
pub struct SettingsState {
    capturing: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Capture {
    Waiting,
    Cancel,
    Combo(Hotkey),
}

/// Capture mode: the first key press that makes a valid hotkey wins; Esc cancels; other keys are ignored.
fn capture(events: &[egui::Event]) -> Capture {
    for e in events {
        if let egui::Event::Key { key, pressed: true, modifiers, .. } = e {
            if *key == egui::Key::Escape {
                return Capture::Cancel;
            }
            if let Some(h) = Hotkey::from_egui(*key, *modifiers) {
                return Capture::Combo(h);
            }
        }
    }
    Capture::Waiting
}

pub fn show(app: &mut LzApp, ui: &mut egui::Ui) {
    ui.heading("Password hotkey");
    ui.label("Press the hotkey anywhere to copy a stored password to the clipboard. It is cleared after 90 s.");
    let mut h = app.settings.password_hotkey.clone();
    let mut changed = ui.checkbox(&mut h.enabled, "Enabled").changed();
    ui.horizontal(|ui| {
        if app.settings_ui.capturing {
            ui.label("Press the new combination… (Esc to cancel)");
            match capture(&ui.input(|i| i.events.clone())) {
                Capture::Combo(c) => {
                    h.combo = c;
                    changed = true;
                    app.settings_ui.capturing = false;
                }
                Capture::Cancel => app.settings_ui.capturing = false,
                Capture::Waiting => {}
            }
        } else {
            ui.label(egui::RichText::new(h.combo.to_string()).strong());
            if ui.button("Change").clicked() {
                app.settings_ui.capturing = true;
            }
            if ui.add_enabled(h.combo != Hotkey::default(), egui::Button::new("Reset to Ctrl+Alt+P")).clicked() {
                h.combo = Hotkey::default();
                changed = true;
            }
        }
    });
    if let Some(e) = &app.hotkey_error {
        ui.colored_label(ui.visuals().error_fg_color, e);
    }
    if changed {
        app.settings.password_hotkey = h.clone();
        if let Err(e) = app.settings.save(&app.settings_path) {
            app.toast(format!("Could not save settings: {e}"));
        }
        if let Some(t) = &app.hotkey {
            t.set(h.enabled.then_some(h.combo));
        }
        if !h.enabled {
            app.hotkey_error = None;
        }
    }
    ui.separator();
    ui.heading("Quick unlock");
    super::quick_unlock::settings(app, ui);
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::{Event, Key, Modifiers};

    fn key(key: Key, modifiers: Modifiers) -> Event {
        Event::Key { key, physical_key: None, pressed: true, repeat: false, modifiers }
    }

    #[test]
    fn capture_takes_first_valid_combo() {
        let ev = [key(Key::K, Modifiers::NONE), key(Key::K, Modifiers::CTRL | Modifiers::ALT)];
        assert_eq!(capture(&ev), Capture::Combo("Ctrl+Alt+K".parse().unwrap()));
    }

    #[test]
    fn capture_esc_cancels() {
        assert_eq!(capture(&[key(Key::Escape, Modifiers::NONE)]), Capture::Cancel);
    }

    #[test]
    fn capture_ignores_plain_keys_and_releases() {
        let release = Event::Key { key: Key::K, physical_key: None, pressed: false, repeat: false, modifiers: Modifiers::CTRL };
        assert_eq!(capture(&[key(Key::K, Modifiers::SHIFT), release]), Capture::Waiting);
    }
}
