use crate::connect::clean_run_dir;
use crate::model::Store;
use crate::paths;
use crate::vault::Vault;
use crate::device::{Device, PairedDevice};
use crate::sync::net::{self, NetCmd, NetEvent};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Unlock,
    Hosts,
    Secrets,
    Devices,
}

pub struct LzApp {
    pub store: Store,
    pub vault: Option<Vault>,
    pub screen: Screen,
    pub toasts: Vec<(String, Instant)>,
    pub hosts_path: PathBuf,
    pub secrets_path: PathBuf,
    pub run_dir: PathBuf,
    pub unlock: super::unlock::UnlockState,
    pub secrets_ui: super::secrets::SecretsState,
    pub hosts_ui: super::hosts::HostsState,
    pub devices_ui: super::devices::DevicesState,
    pub device_path: PathBuf,
    pub device: Option<crate::device::Device>,
    pub paired: Arc<RwLock<Vec<PairedDevice>>>,
    pub net: Option<(Sender<NetCmd>, Receiver<NetEvent>)>,
    pub node_id: Option<String>,
}

const TOAST_TTL: Duration = Duration::from_secs(5);

impl LzApp {
    pub fn new() -> Self {
        let data = paths::data_dir();
        let hosts_path = data.join("hosts.json");
        let mut toasts = Vec::new();
        let store = match Store::load(&hosts_path) {
            Ok(s) => s,
            Err(e) => {
                toasts.push((format!("Could not read hosts.json: {e}"), Instant::now()));
                Store::default()
            }
        };
        LzApp {
            store,
            vault: None,
            screen: Screen::Unlock,
            toasts,
            hosts_path,
            secrets_path: data.join("secrets.json"),
            run_dir: paths::run_dir(),
            unlock: Default::default(),
            secrets_ui: Default::default(),
            hosts_ui: Default::default(),
            devices_ui: Default::default(),
            device_path: data.join("device.json"),
            device: None,
            paired: Arc::new(RwLock::new(Vec::new())),
            net: None,
            node_id: None,
        }
    }

    pub fn toast(&mut self, msg: impl Into<String>) {
        self.toasts.push((msg.into(), Instant::now()));
    }

    pub fn save_store(&mut self) {
        if let Err(e) = self.store.save(&self.hosts_path) {
            self.toast(format!("Could not save hosts: {e}"));
        }
    }

    pub fn save_vault(&mut self) {
        if let Some(v) = &self.vault {
            if let Err(e) = v.save() {
                self.toast(format!("Could not save secrets: {e}"));
            }
        }
    }

    /// Export key to host: implemented in Task 9.
    pub fn start_export(&mut self, _host: uuid::Uuid) {
        self.toast("Export is not available yet");
    }

    /// Called once after the vault is unlocked.
    pub fn on_unlocked(&mut self) {
        match Device::load_or_create(&self.device_path) {
            Ok(d) => {
                *self.paired.write().expect("paired lock") = d.paired.clone();
                self.net = Some(net::spawn(d.secret_key, d.name.clone(), self.paired.clone()));
                self.device = Some(d);
            }
            Err(e) => self.toast(format!("Sync unavailable: could not load device.json: {e}")),
        }
    }

    /// Persist device name and the paired list (the network thread may have added peers).
    pub fn save_device(&mut self) {
        let paired = self.paired.read().expect("paired lock").clone();
        if let Some(d) = self.device.as_mut() {
            d.paired = paired;
            if let Err(e) = d.save(&self.device_path) {
                let msg = format!("Could not save device.json: {e}");
                self.toast(msg);
            }
        }
    }

    pub fn device_name(&self, node_id: &str) -> String {
        self.paired.read().expect("paired lock").iter().find(|d| d.node_id == node_id).map(|d| d.name.clone()).unwrap_or_else(|| format!("{}…", &node_id[..node_id.len().min(8)]))
    }

    pub fn send_cmd(&mut self, c: NetCmd) {
        match &self.net {
            Some((tx, _)) if tx.send(c).is_ok() => {}
            _ => self.toast("Sync is not running"),
        }
    }

    fn poll_net(&mut self) {
        let Some((_, rx)) = &self.net else { return };
        let events: Vec<NetEvent> = rx.try_iter().collect();
        for e in events {
            match e {
                NetEvent::Ready { node_id } => self.node_id = Some(node_id),
                NetEvent::PairCode(c) => self.devices_ui.set_code(c),
                NetEvent::Paired(d) => {
                    self.devices_ui.clear_code();
                    self.save_device();
                    self.toast(format!("Paired with {}", d.name));
                }
                NetEvent::Received { from, payload } => {
                    let name = self.device_name(&from);
                    let Some(vault) = self.vault.as_mut() else { continue };
                    match crate::sync::payload::apply_payload(&mut self.store, vault, payload) {
                        Ok(s) => {
                            self.save_store();
                            self.save_vault();
                            self.toast(format!("Received {} hosts, {} secrets from {name}", s.hosts, s.secrets));
                        }
                        Err(e) => self.toast(format!("Could not apply data from {name}: {e}")),
                    }
                }
                NetEvent::Sent { to } => {
                    let name = self.device_name(&to);
                    self.toast(format!("Sent to {name}"));
                }
                NetEvent::SendFailed { to, error } => {
                    let name = self.device_name(&to);
                    self.toast(format!("{name} not reachable ({error})"));
                }
                NetEvent::Error(e) => self.toast(e),
            }
        }
    }

    fn nav(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("nav").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("lzssh");
                ui.separator();
                for (s, label) in [(Screen::Hosts, "Hosts"), (Screen::Secrets, "Secrets"), (Screen::Devices, "Devices")] {
                    if ui.selectable_label(self.screen == s, label).clicked() {
                        self.screen = s;
                    }
                }
            });
        });
    }

    fn show_toasts(&mut self, ui: &mut egui::Ui) {
        self.toasts.retain(|(_, t)| t.elapsed() < TOAST_TTL);
        if self.toasts.is_empty() {
            return;
        }
        egui::Panel::bottom("toasts").show(ui, |ui| {
            for (m, _) in &self.toasts {
                ui.label(m);
            }
        });
        ui.ctx().request_repaint_after(Duration::from_millis(500));
    }
}

impl eframe::App for LzApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_net();
        if self.net.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(250));
        }
        if self.screen != Screen::Unlock {
            self.nav(ui);
        }
        super::devices::send_dialog(self, ui);
        self.show_toasts(ui);
        egui::CentralPanel::default().show(ui, |ui| match self.screen {
            Screen::Unlock => super::unlock::show(self, ui),
            Screen::Secrets => super::secrets::show(self, ui),
            Screen::Hosts => super::hosts::show(self, ui),
            Screen::Devices => super::devices::show(self, ui),
        });
    }

    fn on_exit(&mut self) {
        clean_run_dir(&self.run_dir);
    }
}
