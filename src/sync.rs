use super::*;
use std::collections::{HashMap, HashSet};

pub struct SyncRequest {
    pub config: SyncConfig,
    pub common_hash: Option<String>,
}

pub enum Decision {
    Local,
    Server,
    Both,
    Later,
}

pub struct Conflict {
    pub local: Option<Entry>,
    pub server: Option<Entry>,
    pub local_folder: String,
    pub server_folder: String,
    pub remaining: usize,
}

pub(super) struct PendingSync {
    request: SyncRequest,
    local_hash: String,
    remote_hash: String,
    merged: Database,
    conflicts: std::collections::VecDeque<EntryConflict>,
}

type LocatedEntry = (Entry, NodeId);

struct EntryConflict {
    local: Option<LocatedEntry>,
    server: Option<LocatedEntry>,
    local_folder: String,
    server_folder: String,
}

pub(super) enum Outcome {
    Done(String),
    Conflict(Box<Conflict>),
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn baseline_path(path: &Path) -> Result<PathBuf> {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let identity = path.to_string_lossy().to_lowercase();
    let dir = crate::storage::settings_file()?.with_file_name("sync-baselines");
    Ok(dir.join(format!("{}.kdbx", digest(identity.as_bytes()))))
}

fn remember(path: &Path, bytes: &[u8]) -> Result<String> {
    let baseline = baseline_path(path)?;
    let dir = baseline.parent().context("Папка истории недоступна")?;
    fs::create_dir_all(dir)?;
    let temp = dir.join(format!(".{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, &baseline)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.context("Не удалось сохранить зашифрованную общую версию")?;
    Ok(digest(bytes))
}

fn filename(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.chars().any(char::is_control))
        .context("Некорректное имя файла базы")
}

fn ftp_error(output: &std::process::Output) -> anyhow::Error {
    let message = String::from_utf8_lossy(&output.stderr);
    anyhow!(
        "FTPS ({}): {}",
        output.status.code().unwrap_or(-1),
        message.trim()
    )
}

fn download(path: &Path, config: &SyncConfig) -> Result<Option<Vec<u8>>> {
    let name = filename(path)?;
    let result = ftp_request(config, Some(name), "")?;
    if result.status.success() {
        return Ok(Some(result.stdout));
    }
    // FTP 550 may also mean permission denied. Verify absence in the directory.
    if matches!(result.status.code(), Some(19 | 78)) {
        let listing = ftp_request(config, None, "list-only\n")?;
        if !listing.status.success() {
            return Err(ftp_error(&listing));
        }
        let names = std::str::from_utf8(&listing.stdout)
            .context("Список файлов на сервере имеет неизвестную кодировку")?;
        if !names.lines().any(|line| {
            line.trim_end_matches('\r')
                .rsplit('/')
                .next()
                .is_some_and(|file| file.eq_ignore_ascii_case(name))
        }) {
            return Ok(None);
        }
    }
    Err(ftp_error(&result))
}

fn upload(path: &Path, config: &SyncConfig, bytes: &[u8]) -> Result<Outcome> {
    let name = filename(path)?;
    let staged = format!("peplos-{}.tmp", Uuid::new_v4());
    let parent = path.parent().context("Папка базы недоступна")?;
    let source = parent.join(format!(".{staged}"));
    let transfer = (|| -> Result<()> {
        // Upload exactly the bytes that were checked, even if another program touches the local file.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&source)?;
        file.write_all(bytes)?;
        drop(file);
        let source = curl_quote(&source.to_string_lossy())?;
        let rename_from = curl_quote(&format!("-RNFR {staged}"))?;
        let rename_to = curl_quote(&format!("-RNTO {name}"))?;
        let options =
            format!("upload-file = {source}\nquote = {rename_from}\nquote = {rename_to}\n");
        let output = ftp_request(config, Some(&staged), &options)?;
        if !output.status.success() {
            let remove = curl_quote(&format!("+DELE {staged}"))?;
            let _ = ftp_request(config, None, &format!("quote = {remove}\nlist-only\n"));
            return Err(ftp_error(&output));
        }
        Ok(())
    })();
    let _ = fs::remove_file(&source);
    transfer?;
    let confirmed = download(path, config)?.context("Отправленный файл отсутствует на сервере")?;
    if confirmed != bytes {
        return Err(anyhow!(
            "Сервер вернул содержимое, отличающееся от отправленной базы"
        ));
    }
    Ok(Outcome::Done(remember(path, bytes)?))
}

pub(super) fn check(vault: &mut Vault, request: SyncRequest, publish: bool) -> Result<Outcome> {
    vault.pending_sync = None;
    let path = vault.path.clone().context("База не открыта")?;
    let local = fs::read(&path)?;
    let local_hash = digest(&local);
    let Some(remote) = download(&path, &request.config)? else {
        anyhow::ensure!(publish, "Серверной копии пока нет. Нажмите «Сохранить», чтобы отправить базу.");
        check_local_bytes(vault, &local)?;
        return upload(&path, &request.config, &local);
    };
    let remote_hash = digest(&remote);
    if local_hash == remote_hash {
        return Ok(Outcome::Done(remember(&path, &local)?));
    }
    if request.common_hash.as_ref() == Some(&remote_hash) {
        anyhow::ensure!(publish, "Локальная версия ждёт отправки. Нажмите «Сохранить».");
        check_local_bytes(vault, &local)?;
        return upload(&path, &request.config, &local);
    }
    let key = vault.key.as_ref().context("База закрыта")?;
    let mut server = open_database(remote.as_slice(), key).map_err(|_| {
        anyhow!("Серверная база не открывается текущим мастер-ключом. Обе копии сохранены.")
    })?;
    let local_db = open_database(local.as_slice(), key)?;
    if server.root_group_id != local_db.root_group_id {
        return Err(anyhow!(
            "На сервере находится другая база. Проверьте папку и имя файла."
        ));
    }
    if request.common_hash.as_ref() == Some(&local_hash) {
        install_database(&path, &remote, key, &server)?;
        server.data_modified = false;
        vault.db = Some(server);
        return Ok(Outcome::Done(remember(&path, &remote)?));
    }
    anyhow::ensure!(publish, "Локальная и серверная версии различаются. Нажмите «Сохранить», чтобы начать сравнение.");

    // Older versions stored the hash but did not keep the corresponding file.
    // Without that file, show all differing entries for review.
    let baseline = request.common_hash.as_ref().and_then(|hash| {
        let bytes = fs::read(baseline_path(&path).ok()?).ok()?;
        if digest(&bytes) == *hash {
            open_database(bytes.as_slice(), key).ok()
        } else {
            None
        }
    });
    let (merged, conflicts) = merge(local_db, &server, baseline.as_ref())?;
    continue_sync(
        vault,
        PendingSync {
            request,
            local_hash,
            remote_hash,
            merged,
            conflicts,
        },
    )
}

fn check_local_bytes(vault: &mut Vault, bytes: &[u8]) -> Result<()> {
    let key = vault.key.as_ref().context("База закрыта")?;
    let mut db =
        open_database(bytes, key).context("Локальный файл не прошёл проверку перед отправкой")?;
    db.data_modified = false;
    vault.db = Some(db);
    Ok(())
}

pub(super) fn resolve(vault: &mut Vault, decision: Decision) -> Result<Outcome> {
    let mut pending = vault.pending_sync.take().context("Сравнение устарело")?;
    if matches!(decision, Decision::Later) {
        return Err(anyhow!(
            "Разрешение конфликтов отложено. Обе копии сохранены."
        ));
    }
    let conflict = pending
        .conflicts
        .pop_front()
        .context("Нет записи для сравнения")?;
    let merged = &mut pending.merged;
    match decision {
        Decision::Local => insert(merged, conflict.local)?,
        Decision::Server => insert(merged, conflict.server)?,
        Decision::Both => {
            if let (Some(local), Some((mut server, parent))) = (conflict.local, conflict.server) {
                server.id = NodeId::new_uuid();
                server.title.push_str(" (копия с сервера)");
                for previous in &mut server.history {
                    previous.id = server.id;
                }
                insert(merged, Some(local))?;
                insert(merged, Some((server, parent)))?;
            } else {
                return Err(anyhow!("Дублировать можно только две существующие записи"));
            }
        }
        Decision::Later => unreachable!(),
    }
    continue_sync(vault, pending)
}

fn continue_sync(vault: &mut Vault, mut pending: PendingSync) -> Result<Outcome> {
    if let Some(item) = pending.conflicts.front() {
        let conflict = Conflict {
            local: item.local.as_ref().map(|(entry, _)| entry.clone()),
            server: item.server.as_ref().map(|(entry, _)| entry.clone()),
            local_folder: item.local_folder.clone(),
            server_folder: item.server_folder.clone(),
            remaining: pending.conflicts.len(),
        };
        vault.pending_sync = Some(pending);
        return Ok(Outcome::Conflict(Box::new(conflict)));
    }

    let path = vault.path.clone().context("База не открыта")?;
    if digest(&fs::read(&path)?) != pending.local_hash {
        return Err(anyhow!(
            "Локальный файл изменился. Повторите синхронизацию."
        ));
    }
    // Recheck before committing a merge that may have waited for the user.
    let remote = download(&path, &pending.request.config)?
        .context("Файл на сервере исчез. Повторите синхронизацию.")?;
    if digest(&remote) != pending.remote_hash {
        return Err(anyhow!(
            "Файл на сервере изменился. Повторите синхронизацию."
        ));
    }
    let key = vault.key.as_ref().context("База закрыта")?;
    let mut bytes = Vec::new();
    save_database(&mut bytes, &pending.merged, key)?;
    install_database(&path, &bytes, key, &pending.merged)?;
    pending.merged.data_modified = false;
    vault.db = Some(pending.merged);
    // The merged local copy now includes the server version or explicit choices
    // about it. A failed upload can retry against that version without reasking.
    vault.retry_base_sha256 = Some(remember(&path, &remote)?);
    upload(&path, &pending.request.config, &bytes)
}

fn insert(db: &mut Database, located: Option<LocatedEntry>) -> Result<()> {
    if let Some((entry, parent)) = located {
        let id = entry.id;
        if !db.add_entry(entry, &parent) {
            return Err(anyhow!(
                "Папка записи изменилась. Слияние остановлено, обе копии сохранены."
            ));
        }
        db.deleted_objects.retain(|deleted| *deleted != id);
    }
    Ok(())
}

fn entry_map(db: &Database) -> HashMap<NodeId, (&Entry, NodeId)> {
    db.groups
        .iter()
        .flat_map(|(parent, group)| {
            group
                .child_entry_ids
                .iter()
                .filter_map(move |id| db.entries.get(id).map(|entry| (*id, (entry, *parent))))
        })
        .collect()
}

fn entry_equal(a: Option<(&Entry, NodeId)>, b: Option<(&Entry, NodeId)>) -> Result<bool> {
    match (a, b) {
        (None, None) => Ok(true),
        (Some((a, pa)), Some((b, pb))) if pa == pb => {
            Ok(Zeroizing::new(serde_json::to_vec(a)?) == Zeroizing::new(serde_json::to_vec(b)?))
        }
        _ => Ok(false),
    }
}

fn own_entry(item: Option<(&Entry, NodeId)>) -> Option<LocatedEntry> {
    item.map(|(entry, parent)| (entry.clone(), parent))
}

fn folder(db: &Database, item: Option<(&Entry, NodeId)>) -> String {
    item.and_then(|(_, parent)| db.groups.get(&parent))
        .map(|group| group.title.clone())
        .unwrap_or_default()
}

fn merge(
    mut local: Database,
    server: &Database,
    baseline: Option<&Database>,
) -> Result<(Database, std::collections::VecDeque<EntryConflict>)> {
    let local_entries = entry_map(&local);
    let remote_entries = entry_map(server);
    let base_entries = baseline.map(entry_map).unwrap_or_default();
    let mut ids: Vec<_> = local_entries
        .keys()
        .chain(remote_entries.keys())
        .copied()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    ids.sort_by_key(|id| node_id_string(*id));
    let mut conflicts = std::collections::VecDeque::new();
    let mut entries = Vec::new();
    for id in ids {
        let a = local_entries.get(&id).copied();
        let b = remote_entries.get(&id).copied();
        let base = base_entries.get(&id).copied();
        let different_passwords = matches!((a, b), (Some((left, _)), Some((right, _)))
            if left.password.as_str() != right.password.as_str());
        if entry_equal(a, b)?
            || (!different_passwords && baseline.is_some() && entry_equal(b, base)?)
        {
            entries.push(own_entry(a));
        } else if !different_passwords && baseline.is_some() && entry_equal(a, base)? {
            entries.push(own_entry(b));
        } else {
            conflicts.push_back(EntryConflict {
                local: own_entry(a),
                server: own_entry(b),
                local_folder: folder(&local, a),
                server_folder: folder(server, b),
            });
        }
    }
    merge_groups(&mut local, server, baseline)?;
    for (id, icon) in &server.custom_icons {
        if local.custom_icons.get(id).is_some_and(|old| old != icon) {
            return Err(anyhow!(
                "Различаются пользовательские значки базы. Обе копии сохранены."
            ));
        }
        local
            .custom_icons
            .entry(*id)
            .or_insert_with(|| icon.clone());
    }
    local.entries.clear();
    for group in local.groups.values_mut() {
        group.child_entry_ids.clear();
    }
    local
        .deleted_objects
        .extend(server.deleted_objects.iter().copied());
    let mut seen = HashSet::new();
    local
        .deleted_objects
        .retain(|id| seen.insert(*id) && !local.groups.contains_key(id));
    for entry in entries {
        insert(&mut local, entry)?;
    }
    Ok((local, conflicts))
}

fn group_map(db: &Database) -> HashMap<NodeId, (Group, Option<NodeId>)> {
    let parents: HashMap<_, _> = db
        .groups
        .iter()
        .flat_map(|(parent, group)| {
            group
                .child_group_ids
                .iter()
                .map(move |child| (*child, *parent))
        })
        .collect();
    db.groups
        .iter()
        .map(|(id, group)| {
            let mut group = group.clone();
            group.child_group_ids.clear();
            group.child_entry_ids.clear();
            (*id, (group, parents.get(id).copied()))
        })
        .collect()
}

fn merge_groups(
    local: &mut Database,
    server: &Database,
    baseline: Option<&Database>,
) -> Result<()> {
    macro_rules! merge_property {
        ($field:ident) => {
            if local.$field != server.$field {
                match baseline {
                    Some(base) if base.$field == local.$field => local.$field = server.$field.clone(),
                    Some(base) if base.$field == server.$field => {}
                    _ => return Err(anyhow!("Настройки базы различаются. Обе копии сохранены.")),
                }
            }
        };
    }
    merge_property!(name);
    merge_property!(description);
    merge_property!(default_username);
    merge_property!(recycle_bin_uuid);
    merge_property!(entry_templates_uuid);

    let a = group_map(local);
    let b = group_map(server);
    let base = baseline.map(group_map).unwrap_or_default();
    let ids = a.keys().chain(b.keys()).copied().collect::<HashSet<_>>();
    let mut groups = HashMap::new();
    let mut parents = HashMap::new();
    for id in ids {
        let left = a.get(&id);
        let right = b.get(&id);
        let left_value = serde_json::to_vec(&left)?;
        let right_value = serde_json::to_vec(&right)?;
        let base_value = serde_json::to_vec(&base.get(&id))?;
        let chosen =
            if left_value == right_value || (baseline.is_some() && right_value == base_value) {
                left
            } else if (baseline.is_some() && left_value == base_value)
                || (baseline.is_none() && left.is_none())
            {
                right
            } else if baseline.is_none() && right.is_none() {
                left
            } else {
                return Err(anyhow!("Обнаружен конфликт папок. Обе копии сохранены."));
            };
        if let Some((group, parent)) = chosen {
            groups.insert(id, group.clone());
            parents.insert(id, *parent);
        }
    }
    for (&id, &parent) in &parents {
        if let Some(parent) = parent {
            groups
                .get_mut(&parent)
                .context("Родительская папка отсутствует")?
                .add_child_group(id);
        }
        let mut current = id;
        let mut visited = HashSet::new();
        while Some(current) != local.root_group_id {
            if !visited.insert(current) {
                return Err(anyhow!("Получилась циклическая структура папок"));
            }
            current = parents
                .get(&current)
                .copied()
                .flatten()
                .context("Папка находится вне базы")?;
        }
    }
    local.groups = groups;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Database, NodeId, NodeId, NodeId) {
        let mut db = Database::default();
        let root = NodeId::new_uuid();
        let first = NodeId::new_uuid();
        let second = NodeId::new_uuid();
        db.root_group_id = Some(root);
        db.groups.insert(root, Group::new(root));
        db.add_entry(Entry::new(first), &root);
        db.add_entry(Entry::new(second), &root);
        (db, root, first, second)
    }

    fn copy(db: &Database) -> Database {
        let mut other = Database::new(db.version);
        other.root_group_id = db.root_group_id;
        other.groups = db.groups.clone();
        other.entries = db.entries.clone();
        other
    }

    #[test]
    fn independent_changes_preserve_new_record_and_server_edit() {
        let (base, root, first, _) = fixture();
        let mut local = copy(&base);
        let mut server = copy(&base);
        let added = NodeId::new_uuid();
        local.add_entry(Entry::new(added), &root);
        server.entries.get_mut(&first).unwrap().title = "Обновлено на сервере".into();
        let (merged, conflicts) = merge(local, &server, Some(&base)).unwrap();
        assert!(conflicts.is_empty());
        assert!(merged.entries.contains_key(&added));
        assert_eq!(merged.entries[&first].title, "Обновлено на сервере");
    }

    #[test]
    fn differing_passwords_need_a_decision_even_with_a_common_version() {
        let (base, _, first, second) = fixture();
        let mut local = copy(&base);
        let mut server = copy(&base);
        local.entries.get_mut(&second).unwrap().title = "Локальная правка".into();
        server.entries.get_mut(&first).unwrap().password = ProtectedString::new_protected("server");
        let (merged, conflicts) = merge(local, &server, Some(&base)).unwrap();
        assert_eq!(merged.entries[&second].title, "Локальная правка");
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].local.as_ref().unwrap().0.id, first);
        assert_eq!(
            conflicts[0].server.as_ref().unwrap().0.password.as_str(),
            "server"
        );
    }

    #[test]
    fn removed_records_are_not_restored_from_an_unchanged_copy() {
        let (base, _, first, _) = fixture();
        let mut server = copy(&base);
        server.remove_entry(&first, false).unwrap();
        let (merged, conflicts) = merge(copy(&base), &server, Some(&base)).unwrap();
        assert!(!merged.entries.contains_key(&first));
        assert!(merged.deleted_objects.contains(&first));
        assert!(conflicts.is_empty());
    }
}
