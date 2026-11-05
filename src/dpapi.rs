//! Windows DPAPI (current-user scope) wrapping.
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    // SAFETY: out was filled by DPAPI with cbData bytes at pbData; copy, then free it.
    unsafe {
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out.pbData as _)));
        v
    }
}

pub fn protect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input points to valid memory for the duration of the call; out is written by the API.
    unsafe { CryptProtectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)? };
    Ok(take(out))
}

pub fn unprotect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in protect.
    unsafe { CryptUnprotectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)? };
    Ok(take(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn dpapi_roundtrip() { let c = protect(b"hi").unwrap(); assert_ne!(c, b"hi"); assert_eq!(unprotect(&c).unwrap(), b"hi"); }
}
