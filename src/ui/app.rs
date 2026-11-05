use crate::connect::clean_run_dir;
use crate::model::Store;
use crate::paths;
use crate::vault::Vault;
use std::path::PathBuf;
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
    pub fn on_unlocked(&mut self) {}

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
        if self.screen != Screen::Unlock {
            self.nav(ui);
        }
        self.show_toasts(ui);
        egui::CentralPanel::default().show(ui, |ui| match self.screen {
            Screen::Unlock => super::unlock::show(self, ui),
            Screen::Secrets => super::secrets::show(self, ui),
            Screen::Hosts => super::hosts::show(self, ui),
            Screen::Devices => {
                ui.label("Coming soon");
            }
        });
    }

    fn on_exit(&mut self) {
        clean_run_dir(&self.run_dir);
    }
}
