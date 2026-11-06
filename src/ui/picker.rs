//! Password picker opened by the global hotkey: a small always-on-top viewport listing password
//! names (never values). Picking one copies it to the clipboard, wiped after 90 s.
use super::app::LzApp;
use crate::clipboard::{self, PendingWipe};
use crate::vault::SecretKind;
use std::ffi::c_void;
use std::time::{Duration, Instant};
use uuid::Uuid;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow;

/// Items whose name contains `query` (any case), sorted by name (any case).
pub fn filter(items: &[(Uuid, String)], query: &str) -> Vec<(Uuid, String)> {
    let q = query.to_lowercase();
    let mut out: Vec<_> = items.iter().filter(|(_, n)| n.to_lowercase().contains(&q)).cloned().collect();
    out.sort_by_key(|(_, n)| n.to_lowercase());
    out
}

#[derive(Default)]
pub struct PickerState {
    pub open: bool,
    query: String,
    selected: usize,
    /// HWND that had focus when the hotkey was pressed; focus goes back there on close.
    prev_foreground: isize,
    /// The picker had focus at least once (so losing it means the user clicked elsewhere).
    was_focused: bool,
    /// Frames since opening; focus is requested on the first ones.
    frames: u32,
    /// Hotkey pressed while open: bring the picker to the front next frame.
    refocus: bool,
    /// Passes still needed after closing so egui tears the picker window down.
    linger: u8,
    opened_at: Option<Instant>,
}

/// If the picker has not had focus this long after opening, Windows refused to activate it and
/// the user's keys go to the window behind it (maybe a `sudo` prompt): close it.
const FOCUS_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Picked,
    /// Esc or the window was closed.
    Dismissed,
    /// The user clicked elsewhere: focus stays where they clicked.
    FocusLost,
    NeverFocused,
}

impl CloseReason {
    /// Only an explicit pick or dismiss hands focus back to the window from before the hotkey.
    pub fn restores_focus(self) -> bool {
        matches!(self, CloseReason::Picked | CloseReason::Dismissed)
    }
}

impl PickerState {
    /// Opens the picker, or only brings it forward if it is already open.
    pub fn open_at(&mut self, prev_foreground: isize) {
        if self.open {
            self.refocus = true;
            return;
        }
        *self = PickerState { open: true, prev_foreground, opened_at: Some(Instant::now()), ..Default::default() };
    }

    /// Tracks the viewport's focus; returns why the picker must close, if it must.
    pub fn focus_check(&mut self, focused: Option<bool>, since_open: Duration) -> Option<CloseReason> {
        match focused {
            Some(true) => {
                self.was_focused = true;
                None
            }
            Some(false) if self.was_focused => Some(CloseReason::FocusLost),
            _ if !self.was_focused && since_open >= FOCUS_TIMEOUT => Some(CloseReason::NeverFocused),
            _ => None,
        }
    }

    /// The root viewport must run `ui` (even while minimized): the picker is open, or it just
    /// closed and its window still has to be torn down by one more pass.
    pub fn needs_paint(&self) -> bool {
        self.open || self.linger > 0
    }
}

/// Closes the picker; on pick or dismiss gives focus back to the window that had it before the hotkey.
fn close(app: &mut LzApp, reason: CloseReason) {
    let p = &mut app.picker;
    p.open = false;
    p.linger = 2;
    if reason == CloseReason::NeverFocused {
        app.toast("The password picker could not take focus. Press the hotkey again.");
        return;
    }
    if reason.restores_focus() && p.prev_foreground != 0 {
        // SAFETY: plain Win32 call; a stale HWND only makes it fail.
        let _ = unsafe { SetForegroundWindow(HWND(p.prev_foreground as *mut c_void)) };
    }
}

fn copy(app: &mut LzApp, id: Uuid, name: &str) {
    let Some(vault) = &app.vault else { return };
    let msg = match vault.get(id) {
        Ok(s) => match std::str::from_utf8(&s.material) {
            Ok(pw) => match clipboard::copy_secret(pw) {
                Ok(seq) => {
                    app.pending_wipe = Some(PendingWipe::new(seq, Instant::now()));
                    format!("Copied {name}, clipboard clears in 90 s")
                }
                Err(e) => format!("Could not copy {name}: {e}"),
            },
            Err(_) => "Password is not valid text".to_string(),
        },
        Err(e) => format!("Could not read {name}: {e}"),
    };
    app.toast(msg);
}

/// Draws the picker viewport while `app.picker.open`.
pub fn show(app: &mut LzApp, ctx: &egui::Context) {
    if !app.picker.open {
        if app.picker.linger > 0 {
            app.picker.linger -= 1;
            ctx.request_repaint();
        }
        return;
    }
    let Some(vault) = &app.vault else {
        close(app, CloseReason::Dismissed);
        return;
    };
    let items: Vec<(Uuid, String)> = vault.list().into_iter().filter(|m| m.kind == SecretKind::Password).map(|m| (m.id, m.name)).collect();
    let builder = egui::ViewportBuilder::default()
        .with_title("lzssh passwords")
        .with_inner_size([360.0, 320.0])
        .with_always_on_top()
        .with_decorations(false)
        .with_taskbar(false)
        .with_active(true);
    let p = &mut app.picker;
    let (pick, reason) = ctx.show_viewport_immediate(egui::ViewportId::from_hash_of("lzssh-picker"), builder, |ui, _| {
        let ctx = ui.ctx().clone();
        if p.frames == 1 {
            if let Some(c) = egui::ViewportCommand::center_on_screen(&ctx) {
                ctx.send_viewport_cmd(c);
            }
        }
        let first = p.frames < 3;
        if first || p.refocus {
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            p.refocus = false;
        }
        p.frames += 1;
        let since_open = p.opened_at.map(|t| t.elapsed()).unwrap_or_default();
        let mut reason = p.focus_check(ctx.input(|i| i.viewport().focused), since_open);
        if !p.was_focused && reason.is_none() {
            ctx.request_repaint_after(Duration::from_millis(100)); // so the timeout fires
        }
        if ctx.input(|i| i.viewport().close_requested()) {
            reason = Some(CloseReason::Dismissed);
        }
        let list = filter(&items, &p.query);
        let (up, down, enter, esc) = ctx.input_mut(|i| {
            (
                i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp),
                i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown),
                i.consume_key(egui::Modifiers::NONE, egui::Key::Enter),
                i.consume_key(egui::Modifiers::NONE, egui::Key::Escape),
            )
        });
        if esc {
            reason = Some(CloseReason::Dismissed);
        }
        if up {
            p.selected = p.selected.saturating_sub(1);
        }
        if down {
            p.selected += 1;
        }
        p.selected = p.selected.min(list.len().saturating_sub(1));
        let mut pick = enter.then(|| list.get(p.selected).cloned()).flatten();
        egui::CentralPanel::default().show(ui, |ui| {
            let filter_box = ui.add(egui::TextEdit::singleline(&mut p.query).hint_text("Filter passwords").desired_width(f32::INFINITY));
            if first || p.refocus || !filter_box.has_focus() {
                filter_box.request_focus();
            }
            if filter_box.changed() {
                p.selected = 0;
            }
            ui.separator();
            if items.is_empty() {
                ui.label("No passwords stored. Add one on the Secrets page.");
            } else if list.is_empty() {
                ui.label("No match");
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, (id, name)) in list.iter().enumerate() {
                    let r = ui.selectable_label(i == p.selected, name);
                    if i == p.selected && (up || down) {
                        r.scroll_to_me(None);
                    }
                    if r.clicked() {
                        pick = Some((*id, name.clone()));
                    }
                }
            });
        });
        (pick, reason)
    });
    if let Some((id, name)) = &pick {
        copy(app, *id, name);
        close(app, CloseReason::Picked);
    } else if let Some(r) = reason {
        close(app, r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items() -> Vec<(Uuid, String)> {
        ["root@web", "Backup", "db admin"].iter().map(|n| (Uuid::new_v4(), n.to_string())).collect()
    }

    #[test]
    fn filter_sorts_case_insensitive() {
        let names: Vec<_> = filter(&items(), "").into_iter().map(|(_, n)| n).collect();
        assert_eq!(names, ["Backup", "db admin", "root@web"]);
    }

    #[test]
    fn filter_matches_substring_any_case() {
        let names: Vec<_> = filter(&items(), "AD").into_iter().map(|(_, n)| n).collect();
        assert_eq!(names, ["db admin"]);
    }

    #[test]
    fn click_away_closes_without_restoring_focus() {
        let mut p = PickerState::default();
        p.open_at(1);
        assert_eq!(p.focus_check(Some(true), Duration::from_millis(50)), None);
        assert_eq!(p.focus_check(Some(false), Duration::from_millis(80)), Some(CloseReason::FocusLost));
        assert!(!CloseReason::FocusLost.restores_focus());
        assert!(CloseReason::Picked.restores_focus());
        assert!(CloseReason::Dismissed.restores_focus());
    }

    #[test]
    fn never_focused_picker_closes_after_timeout() {
        let mut p = PickerState::default();
        p.open_at(1);
        assert_eq!(p.focus_check(Some(false), Duration::from_millis(500)), None);
        assert_eq!(p.focus_check(None, Duration::from_millis(1500)), Some(CloseReason::NeverFocused));
        assert!(!CloseReason::NeverFocused.restores_focus());
    }

    #[test]
    fn press_while_open_keeps_one_picker() {
        let mut p = PickerState::default();
        p.open_at(1);
        p.query = "db".into();
        p.open_at(2);
        assert!(p.open);
        assert_eq!(p.query, "db");
        assert_eq!(p.prev_foreground, 1);
    }
}
