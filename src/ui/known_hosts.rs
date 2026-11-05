//! Known hosts screen: entries of ~/.ssh/known_hosts with fingerprints; delete stale ones.
use super::app::LzApp;
use crate::known_hosts::{KnownHost, default_path, load, remove};

#[derive(Default)]
pub struct KnownHostsState {
    entries: Option<Vec<KnownHost>>,
    filter: String,
    confirm: Option<usize>,
}

pub fn show(app: &mut LzApp, ui: &mut egui::Ui) {
    let path = default_path();
    let st = &mut app.known_hosts_ui;
    let mut toast = None;
    if st.entries.is_none() {
        match load(&path) {
            Ok(e) => st.entries = Some(e),
            Err(e) => {
                st.entries = Some(vec![]);
                toast = Some(format!("Could not read {}: {e}", path.display()));
            }
        }
    }
    ui.horizontal(|ui| {
        ui.label("Filter");
        ui.add(egui::TextEdit::singleline(&mut st.filter).desired_width(240.0));
        if ui.button("Reload").clicked() {
            st.entries = None;
            st.confirm = None;
        }
        ui.weak(path.display().to_string());
    });
    ui.separator();
    let entries = st.entries.clone().unwrap_or_default();
    let f = st.filter.trim().to_lowercase();
    let shown: Vec<&KnownHost> = entries.iter().filter(|e| f.is_empty() || e.hosts.to_lowercase().contains(&f) || e.fingerprint.to_lowercase().contains(&f)).collect();
    if shown.is_empty() {
        ui.label("No entries.");
    }
    let mut delete = None;
    egui::ScrollArea::vertical().auto_shrink([false, true]).show(ui, |ui| {
        egui::Grid::new("known_hosts").striped(true).num_columns(4).spacing([16.0, 6.0]).show(ui, |ui| {
            ui.strong("Host");
            ui.strong("Key type");
            ui.strong("Fingerprint");
            ui.label("");
            ui.end_row();
            for e in shown {
                let host = if e.hashed { "(hashed host name)".to_string() } else { e.hosts.clone() };
                let host = match &e.marker {
                    Some(m) => format!("{m} {host}"),
                    None => host,
                };
                ui.label(host);
                ui.label(&e.key_type);
                ui.monospace(&e.fingerprint);
                ui.horizontal(|ui| {
                    if st.confirm == Some(e.line) {
                        if ui.button("Really delete").clicked() {
                            delete = Some(e.clone());
                        }
                        if ui.button("Keep").clicked() {
                            st.confirm = None;
                        }
                    } else if ui.button("Delete").clicked() {
                        st.confirm = Some(e.line);
                    }
                });
                ui.end_row();
            }
        });
    });
    if let Some(e) = delete {
        st.confirm = None;
        st.entries = None;
        toast = Some(match remove(&path, &e) {
            Ok(()) => format!("Removed {}", if e.hashed { "entry" } else { e.hosts.as_str() }),
            Err(err) => format!("Could not remove entry: {err}"),
        });
    }
    if let Some(t) = toast {
        app.toast(t);
    }
}
