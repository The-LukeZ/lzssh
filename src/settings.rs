//! App settings in `%APPDATA%\lzssh\settings.json`: plain JSON, nothing secret, not synced.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::str::FromStr;

/// A global hotkey: Ctrl and/or Alt (Shift optional) plus a letter or digit.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Hotkey {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    /// `'A'..='Z'` or `'0'..='9'`.
    pub key: char,
}

impl Default for Hotkey {
    fn default() -> Self {
        Hotkey { ctrl: true, alt: true, shift: false, key: 'P' }
    }
}

impl fmt::Display for Hotkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.ctrl {
            f.write_str("Ctrl+")?;
        }
        if self.alt {
            f.write_str("Alt+")?;
        }
        if self.shift {
            f.write_str("Shift+")?;
        }
        write!(f, "{}", self.key)
    }
}

impl Hotkey {
    fn checked(ctrl: bool, alt: bool, shift: bool, key: &str) -> Option<Hotkey> {
        let mut chars = key.chars();
        let c = chars.next()?.to_ascii_uppercase();
        if chars.next().is_some() || !(c.is_ascii_uppercase() || c.is_ascii_digit()) || !(ctrl || alt) {
            return None;
        }
        Some(Hotkey { ctrl, alt, shift, key: c })
    }

    /// The combo for an egui key press, or `None` if it is not a valid hotkey.
    pub fn from_egui(key: egui::Key, mods: egui::Modifiers) -> Option<Hotkey> {
        Hotkey::checked(mods.ctrl, mods.alt, mods.shift, key.name())
    }

    /// `(MOD_* bits including MOD_NOREPEAT, virtual key code)` for `RegisterHotKey`.
    pub fn win32(&self) -> (u32, u32) {
        let mut m = 0x4000; // MOD_NOREPEAT
        if self.alt {
            m |= 0x1;
        }
        if self.ctrl {
            m |= 0x2;
        }
        if self.shift {
            m |= 0x4;
        }
        (m, self.key as u32)
    }
}

impl FromStr for Hotkey {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("Invalid hotkey \"{s}\"");
        let mut parts: Vec<&str> = s.split('+').map(str::trim).collect();
        let key = parts.pop().ok_or_else(bad)?;
        let (mut ctrl, mut alt, mut shift) = (false, false, false);
        for p in parts {
            match p.to_ascii_lowercase().as_str() {
                "ctrl" => ctrl = true,
                "alt" => alt = true,
                "shift" => shift = true,
                _ => return Err(bad()),
            }
        }
        Hotkey::checked(ctrl, alt, shift, key).ok_or_else(bad)
    }
}

impl TryFrom<String> for Hotkey {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        s.parse()
    }
}

impl From<Hotkey> for String {
    fn from(h: Hotkey) -> String {
        h.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HotkeySetting {
    pub enabled: bool,
    pub combo: Hotkey,
}

impl Default for HotkeySetting {
    fn default() -> Self {
        HotkeySetting { enabled: true, combo: Hotkey::default() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Settings {
    pub password_hotkey: HotkeySetting,
}

impl Settings {
    /// Missing or unreadable file means defaults.
    pub fn load(path: &Path) -> Settings {
        std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    /// Crash-safe: writes `<path>.tmp`, flushes it to disk, then renames it over `path`, so a crash
    /// leaves either the old or the new file, never a half-written one.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        use std::io::Write;
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
        drop(f);
        // On Windows, std::fs::rename replaces an existing target (MoveFileExW with REPLACE_EXISTING).
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_ctrl_alt_p() {
        assert_eq!(Hotkey::default().to_string(), "Ctrl+Alt+P");
    }

    #[test]
    fn parse_roundtrip() {
        for s in ["Ctrl+Alt+P", "Alt+Shift+5", "Ctrl+K"] {
            assert_eq!(s.parse::<Hotkey>().unwrap().to_string(), s);
        }
        assert_eq!("ctrl+alt+p".parse::<Hotkey>().unwrap(), Hotkey::default());
    }

    #[test]
    fn parse_rejects_bad() {
        for s in ["P", "Shift+P", "Ctrl+Alt+", "Ctrl+Alt+F5", "Ctrl+Alt+PP"] {
            assert!(s.parse::<Hotkey>().is_err(), "{s}");
        }
    }

    #[test]
    fn from_egui_requires_ctrl_or_alt() {
        use egui::{Key, Modifiers};
        assert_eq!(Hotkey::from_egui(Key::P, Modifiers::CTRL | Modifiers::ALT), Some(Hotkey::default()));
        assert_eq!(Hotkey::from_egui(Key::P, Modifiers::SHIFT), None);
        assert_eq!(Hotkey::from_egui(Key::F5, Modifiers::CTRL), None);
        assert_eq!(Hotkey::from_egui(Key::Num5, Modifiers::ALT).unwrap().to_string(), "Alt+5");
    }

    #[test]
    fn win32_codes() {
        // MOD_ALT=0x1, MOD_CONTROL=0x2, MOD_SHIFT=0x4, MOD_NOREPEAT=0x4000
        assert_eq!(Hotkey::default().win32(), (0x1 | 0x2 | 0x4000, 'P' as u32));
    }

    #[test]
    fn load_missing_file_gives_defaults() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(Settings::load(&d.path().join("settings.json")), Settings::default());
    }

    #[test]
    fn load_corrupt_file_gives_defaults() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        std::fs::write(&p, "{not json").unwrap();
        assert_eq!(Settings::load(&p), Settings::default());
    }

    #[test]
    fn save_replaces_existing_file_and_leaves_no_temp() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        std::fs::write(&p, "old").unwrap();
        Settings::default().save(&p).unwrap();
        assert_eq!(Settings::load(&p), Settings::default());
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1, "temp file left behind");
    }

    #[test]
    fn failed_save_keeps_old_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        let old = Settings { password_hotkey: HotkeySetting { enabled: false, combo: Hotkey::default() } };
        old.save(&p).unwrap();
        // A directory where the temp file goes makes the write fail before the file is touched.
        std::fs::create_dir(d.path().join("settings.json.tmp")).unwrap();
        assert!(Settings::default().save(&p).is_err());
        assert_eq!(Settings::load(&p), old);
    }

    #[test]
    fn save_load_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        let s = Settings { password_hotkey: HotkeySetting { enabled: false, combo: "Alt+Shift+K".parse().unwrap() } };
        s.save(&p).unwrap();
        assert_eq!(Settings::load(&p), s);
        assert!(std::fs::read_to_string(&p).unwrap().contains("\"Alt+Shift+K\""));
    }
}
