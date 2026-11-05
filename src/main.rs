#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(dead_code)]
mod connect;
mod dpapi;
mod keys;
mod model;
mod paths;
mod ui;
mod vault;

use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK, MessageBoxW};
use windows::core::w;

/// Returns false if another lzssh process already holds the lock.
fn single_instance() -> bool {
    // SAFETY: plain Win32 calls; the handle is intentionally leaked so the mutex lives until exit.
    unsafe {
        let h = CreateMutexW(None, true, w!("Local\\lzssh-single-instance"));
        !(h.is_err() || GetLastError() == ERROR_ALREADY_EXISTS)
    }
}

fn main() {
    if !single_instance() {
        // SAFETY: static wide strings, no owner window.
        unsafe { MessageBoxW(None, w!("lzssh is already running"), w!("lzssh"), MB_OK | MB_ICONINFORMATION) };
        return;
    }
    let run_dir = paths::run_dir();
    connect::clean_run_dir(&run_dir);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("lzssh").with_inner_size([1000.0, 650.0]).with_min_inner_size([700.0, 450.0]),
        ..Default::default()
    };
    let r = eframe::run_native("lzssh", options, Box::new(|cc| {
        cc.egui_ctx.set_zoom_factor(1.5);
        Ok(Box::new(ui::app::LzApp::new()))
    }));
    connect::clean_run_dir(&run_dir);
    if let Err(e) = r {
        let msg: Vec<u16> = format!("lzssh failed to start: {e}\0").encode_utf16().collect();
        // SAFETY: msg is NUL-terminated and outlives the call.
        unsafe { MessageBoxW(None, windows::core::PCWSTR(msg.as_ptr()), w!("lzssh"), MB_OK) };
    }
}
