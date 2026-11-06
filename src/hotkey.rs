//! Global hotkey on its own thread with a Win32 message loop, so it fires while the GUI is
//! minimized. Events go to the UI over a channel; each one wakes egui with `request_repaint`.

use crate::settings::Hotkey;
use std::sync::mpsc::{self, Receiver, Sender};
use windows::Win32::Foundation::{ERROR_HOTKEY_ALREADY_REGISTERED, LPARAM, WPARAM};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Input::KeyboardAndMouse::{HOT_KEY_MODIFIERS, RegisterHotKey, UnregisterHotKey};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetMessageW, MSG, PM_NOREMOVE, PeekMessageW, PostThreadMessageW, WM_APP, WM_HOTKEY};

const HOTKEY_ID: i32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotkeyEvent {
    /// The hotkey fired; `prev_foreground` is the HWND that had focus at that moment.
    Pressed { prev_foreground: isize },
    /// Result of a (re)registration attempt.
    Registered(Result<(), String>),
}

pub struct HotkeyThread {
    thread_id: u32,
    tx: Sender<Option<Hotkey>>,
}

impl HotkeyThread {
    /// Starts the thread and registers `initial` (`None` = no hotkey).
    pub fn spawn(ctx: egui::Context, initial: Option<Hotkey>) -> (HotkeyThread, Receiver<HotkeyEvent>) {
        let (ev_tx, ev_rx) = mpsc::channel();
        let (cmd_tx, cmd_rx) = mpsc::channel::<Option<Hotkey>>();
        let (id_tx, id_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("lzssh-hotkey".into())
            .spawn(move || run(ctx, initial, cmd_rx, ev_tx, id_tx))
            .expect("spawn hotkey thread");
        let thread_id = id_rx.recv().unwrap_or(0);
        (HotkeyThread { thread_id, tx: cmd_tx }, ev_rx)
    }

    /// Replaces the registered hotkey (`None` = unregister).
    pub fn set(&self, combo: Option<Hotkey>) {
        if self.tx.send(combo).is_ok() {
            let _ = unsafe { PostThreadMessageW(self.thread_id, WM_APP, WPARAM(0), LPARAM(0)) };
        }
    }
}

fn register(combo: Option<Hotkey>) -> Result<(), String> {
    let _ = unsafe { UnregisterHotKey(None, HOTKEY_ID) };
    let Some(h) = combo else { return Ok(()) };
    let (mods, vk) = h.win32();
    unsafe { RegisterHotKey(None, HOTKEY_ID, HOT_KEY_MODIFIERS(mods), vk) }.map_err(|e| {
        if e.code() == ERROR_HOTKEY_ALREADY_REGISTERED.to_hresult() {
            format!("Hotkey {h} is already used by another app")
        } else {
            format!("Could not register hotkey {h}: {e}")
        }
    })
}

fn run(ctx: egui::Context, initial: Option<Hotkey>, cmd_rx: Receiver<Option<Hotkey>>, ev_tx: Sender<HotkeyEvent>, id_tx: Sender<u32>) {
    let mut msg = MSG::default();
    // Create this thread's message queue before anyone posts to it.
    let _ = unsafe { PeekMessageW(&mut msg, None, 0, 0, PM_NOREMOVE) };
    let _ = id_tx.send(unsafe { GetCurrentThreadId() });
    let send = |e: HotkeyEvent| {
        let _ = ev_tx.send(e);
        ctx.request_repaint();
    };
    send(HotkeyEvent::Registered(register(initial)));
    while unsafe { GetMessageW(&mut msg, None, 0, 0) }.0 > 0 {
        match msg.message {
            WM_HOTKEY if msg.wParam.0 == HOTKEY_ID as usize => {
                let prev_foreground = unsafe { GetForegroundWindow() }.0 as isize;
                send(HotkeyEvent::Pressed { prev_foreground });
            }
            WM_APP => {
                if let Some(combo) = cmd_rx.try_iter().last() {
                    send(HotkeyEvent::Registered(register(combo)));
                }
            }
            _ => {}
        }
    }
}
