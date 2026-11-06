//! Clipboard for secrets: excluded from Clipboard History and cloud clipboard, wiped after a delay
//! only if it still holds what we put there.

use anyhow::{Context, Result};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
use windows::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard, RegisterClipboardFormatW, SetClipboardData};
use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::core::w;
use zeroize::Zeroizing;

/// How long a copied secret stays on the clipboard.
pub const WIPE_AFTER: Duration = Duration::from_secs(90);

/// A scheduled wipe of the clipboard content identified by its sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingWipe {
    pub seq: u32,
    pub due: Instant,
}

impl PendingWipe {
    pub fn new(seq: u32, now: Instant) -> Self {
        PendingWipe { seq, due: now + WIPE_AFTER }
    }

    pub fn is_due(&self, now: Instant) -> bool {
        now >= self.due
    }
}

/// Wipe only if nobody changed the clipboard since our copy.
pub fn should_wipe(pending_seq: u32, current_seq: u32) -> bool {
    pending_seq == current_seq
}

/// Opens the clipboard, retrying while another app holds it.
fn open() -> Result<()> {
    let mut last = None;
    for _ in 0..5 {
        match unsafe { OpenClipboard(None) } {
            Ok(()) => return Ok(()),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(last.expect("at least one attempt")).context("Could not open the clipboard")
}

/// Copies `bytes` into a movable global block and hands it to the clipboard (which then owns it).
unsafe fn set_bytes(format: u32, bytes: &[u8]) -> Result<()> {
    unsafe {
        let h: HGLOBAL = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1))?;
        let p = GlobalLock(h) as *mut u8;
        if p.is_null() {
            let _ = GlobalFree(Some(h));
            anyhow::bail!("GlobalLock failed");
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        let _ = GlobalUnlock(h); // returns Err when the lock count reaches 0
        if let Err(e) = SetClipboardData(format, Some(HANDLE(h.0))) {
            // Scrub our copy before freeing it. Once SetClipboardData succeeds the system owns the
            // block and only EmptyClipboard (the wipe) releases it.
            let p = GlobalLock(h) as *mut u8;
            if !p.is_null() {
                std::ptr::write_bytes(p, 0, bytes.len());
                let _ = GlobalUnlock(h);
            }
            let _ = GlobalFree(Some(h));
            return Err(e.into());
        }
        Ok(())
    }
}

/// Puts `text` on the clipboard, marked so Clipboard History and cloud clipboard skip it.
/// Returns the clipboard sequence number right after the copy. On any error the clipboard is
/// left empty, so the secret never sits there without the opt-out markers.
pub fn copy_secret(text: &str) -> Result<u32> {
    // Pre-sized so pushing never reallocates and leaves an unzeroed copy behind
    // (UTF-16 units never exceed UTF-8 bytes).
    let mut wide: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::with_capacity(text.len() + 1));
    wide.extend(text.encode_utf16());
    wide.push(0);
    let bytes = unsafe { std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2) };
    open()?;
    let r = unsafe {
        (|| -> Result<u32> {
            EmptyClipboard()?;
            // Markers first, the text last: the text is only published once the opt-outs are in place.
            let zero = 0u32.to_ne_bytes();
            for name in [w!("ExcludeClipboardContentFromMonitorProcessing"), w!("CanIncludeInClipboardHistory"), w!("CanUploadToCloudClipboard")] {
                let f = RegisterClipboardFormatW(name);
                if f == 0 {
                    anyhow::bail!("Could not register clipboard format: {}", windows::core::Error::from_thread());
                }
                set_bytes(f, &zero)?;
            }
            set_bytes(CF_UNICODETEXT.0 as u32, bytes)?;
            // Read while we still hold the clipboard, so no other app's write can slip in between.
            Ok(GetClipboardSequenceNumber())
        })()
    };
    if r.is_err() {
        let _ = unsafe { EmptyClipboard() };
    }
    let _ = unsafe { CloseClipboard() };
    r
}

/// Empties the clipboard if it still holds the copy with sequence number `seq`. Returns whether it wiped.
pub fn wipe_if_unchanged(seq: u32) -> bool {
    if !should_wipe(seq, unsafe { GetClipboardSequenceNumber() }) || open().is_err() {
        return false;
    }
    // Check again while holding the clipboard: someone may have written between the check and open().
    let ok = should_wipe(seq, unsafe { GetClipboardSequenceNumber() }) && unsafe { EmptyClipboard() }.is_ok();
    let _ = unsafe { CloseClipboard() };
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_due_after_90s() {
        let t = Instant::now();
        let w = PendingWipe::new(7, t);
        assert!(!w.is_due(t + Duration::from_secs(89)));
        assert!(w.is_due(t + Duration::from_secs(90)));
    }

    #[test]
    fn wipe_skips_when_clipboard_changed() {
        assert!(should_wipe(7, 7));
        assert!(!should_wipe(7, 8));
    }

    #[test]
    #[ignore = "touches the real clipboard"]
    fn copy_then_wipe_real_clipboard() {
        let seq = copy_secret("hunter2").unwrap();
        assert!(wipe_if_unchanged(seq));
        assert!(!wipe_if_unchanged(seq.wrapping_sub(1)));
    }
}
