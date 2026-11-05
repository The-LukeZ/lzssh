//! lzssh core: model, vault, connect, sync. Used by the GUI (`lzssh`) and the console helper (`lzssh-ssh`).
#![allow(dead_code)]
pub mod askpass;
pub mod connect;
pub mod device;
pub mod dpapi;
pub mod export;
pub mod keys;
pub mod known_hosts;
pub mod model;
pub mod paths;
pub mod sync;
pub mod ui;
pub mod vault;
pub mod quick_unlock;
