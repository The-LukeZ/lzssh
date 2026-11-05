//! What gets pushed to another device, and how the receiver merges it (upsert by ID, never delete).
use crate::model::{Folder, Host, Store};
use crate::vault::{PlainSecret, Vault, VaultError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderSel {
    Folder(Uuid),
    /// Hosts without a folder; they stay ungrouped on the receiver.
    Ungrouped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    pub folders: Vec<Folder>,
    pub hosts: Vec<Host>,
    pub secrets: Vec<PlainSecret>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplySummary {
    pub hosts: usize,
    pub secrets: usize,
}

fn is_ungrouped(store: &Store, h: &Host) -> bool {
    h.folder_id.is_none_or(|id| !store.folders.iter().any(|f| f.id == id))
}

pub fn build_payload(store: &Store, vault: &Vault, folders: &[FolderSel], secrets: &[Uuid]) -> Result<Payload, VaultError> {
    let ungrouped = folders.contains(&FolderSel::Ungrouped);
    let folder_ids: Vec<Uuid> = folders.iter().filter_map(|s| if let FolderSel::Folder(id) = s { Some(*id) } else { None }).collect();
    let out_folders: Vec<Folder> = store.folders.iter().filter(|f| folder_ids.contains(&f.id)).cloned().collect();
    let hosts = store
        .hosts
        .iter()
        .filter(|h| if is_ungrouped(store, h) { ungrouped } else { h.folder_id.is_some_and(|id| folder_ids.contains(&id)) })
        .map(|h| {
            let mut h = h.clone();
            if is_ungrouped(store, &h) {
                h.folder_id = None;
            }
            h
        })
        .collect();
    let secrets = secrets.iter().map(|id| vault.get(*id)).collect::<Result<Vec<_>, _>>()?;
    Ok(Payload { folders: out_folders, hosts, secrets })
}

pub fn apply_payload(store: &mut Store, vault: &mut Vault, p: Payload) -> Result<ApplySummary, VaultError> {
    let summary = ApplySummary { hosts: p.hosts.len(), secrets: p.secrets.len() };
    for s in p.secrets {
        vault.upsert(s)?;
    }
    for f in p.folders {
        match store.folders.iter_mut().find(|x| x.id == f.id) {
            Some(x) => x.name = f.name,
            None => store.folders.push(f),
        }
    }
    for h in p.hosts {
        match store.hosts.iter_mut().find(|x| x.id == h.id) {
            Some(x) => *x = h,
            None => store.hosts.push(h),
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Auth, Folder, Host, Store};
    use crate::vault::{PlainSecret, SecretKind, Vault};
    use uuid::Uuid;
    use zeroize::Zeroizing;

    fn host(name: &str, folder: Option<Uuid>, secret: Uuid) -> Host {
        Host {
            id: Uuid::new_v4(),
            folder_id: folder,
            name: name.into(),
            ipv4: Some("10.0.0.1".into()),
            ipv6: None,
            port: 22,
            username: "u".into(),
            auth: Auth::Key { secret_id: secret },
        }
    }

    fn secret() -> PlainSecret {
        PlainSecret {
            id: Uuid::new_v4(),
            name: "k".into(),
            kind: SecretKind::SshKey,
            public_key: Some("ssh-ed25519 AAAA".into()),
            material: Zeroizing::new(b"PRIVATE".to_vec()),
            passphrase: Some(Zeroizing::new("pp".into())),
        }
    }

    fn vault(dir: &std::path::Path, pin: &str) -> Vault {
        Vault::create(&dir.join(format!("v{pin}.json")), pin).unwrap()
    }

    #[test]
    fn apply_upserts_and_never_deletes() {
        let d = tempfile::tempdir().unwrap();
        let f = Folder { id: Uuid::new_v4(), name: "prod".into() };
        let local = host("L", Some(f.id), Uuid::nil());
        let mut store = Store { folders: vec![f.clone()], hosts: vec![local.clone()] };
        let h = host("H", Some(f.id), Uuid::nil());
        let p = Payload { folders: vec![Folder { id: f.id, name: "production".into() }], hosts: vec![h.clone()], secrets: vec![] };
        let mut v = vault(d.path(), "111111");
        let s = apply_payload(&mut store, &mut v, p).unwrap();
        assert_eq!(s, ApplySummary { hosts: 1, secrets: 0 });
        assert_eq!(store.folders.len(), 1);
        assert_eq!(store.folders[0].name, "production");
        assert!(store.hosts.contains(&local));
        assert!(store.hosts.contains(&h));
    }

    #[test]
    fn moved_host_not_duplicated() {
        let d = tempfile::tempdir().unwrap();
        let a = Folder { id: Uuid::new_v4(), name: "A".into() };
        let b = Folder { id: Uuid::new_v4(), name: "B".into() };
        let h = host("H", Some(a.id), Uuid::nil());
        let mut store = Store { folders: vec![a.clone()], hosts: vec![h.clone()] };
        let mut moved = h.clone();
        moved.folder_id = Some(b.id);
        let p = Payload { folders: vec![b.clone()], hosts: vec![moved], secrets: vec![] };
        apply_payload(&mut store, &mut vault(d.path(), "111111"), p).unwrap();
        let hs: Vec<_> = store.hosts.iter().filter(|x| x.id == h.id).collect();
        assert_eq!(hs.len(), 1);
        assert_eq!(hs[0].folder_id, Some(b.id));
        assert_eq!(store.folders.len(), 2);
    }

    #[test]
    fn build_selects_folder_hosts_and_secrets() {
        let d = tempfile::tempdir().unwrap();
        let mut v = vault(d.path(), "111111");
        let s = secret();
        v.upsert(s.clone()).unwrap();
        let f = Folder { id: Uuid::new_v4(), name: "F".into() };
        let g = Folder { id: Uuid::new_v4(), name: "G".into() };
        let store = Store {
            folders: vec![f.clone(), g.clone()],
            hosts: vec![host("in", Some(f.id), s.id), host("out", Some(g.id), s.id), host("loose", None, s.id)],
        };
        let p = build_payload(&store, &v, &[FolderSel::Folder(f.id)], &[s.id]).unwrap();
        assert_eq!(p.folders, vec![f]);
        assert_eq!(p.hosts.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(), vec!["in"]);
        assert_eq!(p.secrets.len(), 1);
        assert_eq!(*p.secrets[0].material, b"PRIVATE".to_vec());
    }

    #[test]
    fn ungrouped_selection() {
        let d = tempfile::tempdir().unwrap();
        let v = vault(d.path(), "111111");
        let f = Folder { id: Uuid::new_v4(), name: "F".into() };
        let store = Store { folders: vec![f.clone()], hosts: vec![host("in", Some(f.id), Uuid::nil()), host("loose", None, Uuid::nil())] };
        let p = build_payload(&store, &v, &[FolderSel::Ungrouped], &[]).unwrap();
        assert!(p.folders.is_empty());
        assert_eq!(p.hosts.len(), 1);
        assert_eq!(p.hosts[0].name, "loose");
        assert_eq!(p.hosts[0].folder_id, None);
    }

    #[test]
    fn secrets_reencrypted_on_apply() {
        let d = tempfile::tempdir().unwrap();
        let mut sender = vault(d.path(), "111111");
        let s = secret();
        sender.upsert(s.clone()).unwrap();
        let p = build_payload(&Store::default(), &sender, &[], &[s.id]).unwrap();
        let json = serde_json::to_vec(&p).unwrap();
        let p: Payload = serde_json::from_slice(&json).unwrap();
        let mut receiver = vault(d.path(), "222222");
        let sum = apply_payload(&mut Store::default(), &mut receiver, p).unwrap();
        assert_eq!(sum.secrets, 1);
        let got = receiver.get(s.id).unwrap();
        assert_eq!(*got.material, *s.material);
        assert_eq!(got.passphrase.as_deref().map(|x| x.as_str()), Some("pp"));
    }
}
