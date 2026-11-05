use std::path::PathBuf;

/// `%APPDATA%\lzssh\`, created if missing.
pub fn data_dir() -> PathBuf {
    let d = dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("lzssh");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// `%LOCALAPPDATA%\lzssh\run\`, created if missing. Holds decrypted key files.
pub fn run_dir() -> PathBuf {
    let d = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from(".")).join("lzssh").join("run");
    let _ = std::fs::create_dir_all(&d);
    d
}
