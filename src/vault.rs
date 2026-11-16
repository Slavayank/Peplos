use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    thread,
    time::Instant,
};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use crossbeam_channel::{unbounded, Receiver, Sender};
use keepass_rs::{
    open_database, save_database, CompositeKey, Database, DatabaseVersion, Entry, Group, IconImage, IconImageCustom,
    IconImageStandard, NodeId, ProtectedString,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::storage::SyncConfig;

#[path = "sync.rs"]
mod sync;
pub use sync::{Conflict, Decision, SyncRequest};

#[derive(Clone, Debug)]
pub struct GroupInfo {
    pub id: String,
    pub parent_id: Option<String>,
    pub title: String,
    pub child_groups: Vec<String>,
    pub entry_count: usize,
    pub icon_id: u32,
    pub icon_png: Option<Vec<u8>>,
    pub is_recycle_bin: bool,
}

#[derive(Clone, Debug)]
pub struct EntryInfo {
    pub id: String,
    pub group_id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub creation_time: Option<i64>,
    pub last_modification_time: Option<i64>,
    pub usage_count: i64,
    pub icon_id: u32,
    pub icon_png: Option<Vec<u8>>,
    pub has_custom_icon: bool,
}

#[derive(Clone, Debug)]
pub struct VaultSnapshot {
    pub root_id: String,
    pub groups: Vec<GroupInfo>,
    pub entries: Vec<EntryInfo>,
    pub modified: bool,
}

pub enum Command {
    Create { path: PathBuf, password: Zeroizing<String> },
    Unlock {
        path: PathBuf,
        password: Zeroizing<String>,
        key_file: Option<PathBuf>,
        sync: Option<SyncRequest>,
    },
    RenameGroup {
        id: String,
        title: String,
    },
    MoveGroupToRecycleBin {
        id: String,
    },
    DeleteRecycledGroup {
        id: String,
    },
    MoveEntryToRecycleBin {
        id: String,
    },
    DeleteRecycledEntry {
        id: String,
    },
    ConsolidateRecycleBin {
        destination: String,
    },
    SetGroupIcon {
        id: String,
        icon_id: u32,
        png: Option<Vec<u8>>,
    },
    CreateGroup {
        parent_id: String,
        title: String,
        icon_id: u32,
        png: Option<Vec<u8>>,
    },
    CreateEntry {
        group_id: String,
        title: String,
        username: String,
        password: Zeroizing<String>,
        url: String,
        notes: String,
        tags: Vec<String>,
        png: Option<Vec<u8>>,
    },
    SaveAs {
        path: PathBuf,
        sync: Option<SyncRequest>,
    },
    ChangeMasterPassword {
        password: Zeroizing<String>,
    },
    EditEntry {
        id: String,
        title: String,
        username: String,
        password: Option<Zeroizing<String>>,
        clear_password: bool,
        url: String,
        notes: String,
        tags: Vec<String>,
    },
    SetEntryIcon {
        id: String,
        png: Option<Vec<u8>>,
    },
    CopyPassword {
        id: String,
    },
    GetEntryPassword {
        id: String,
    },
    Save {
        sync: Option<SyncRequest>,
    },
    ResolveSync(Decision),
    TestFtps {
        config: SyncConfig,
    },
}

pub enum Event {
    Progress(String),
    Opened {
        path: PathBuf,
        snapshot: VaultSnapshot,
    },
    Changed(VaultSnapshot),
    SyncConflict(Box<Conflict>),
    Password(Zeroizing<String>),
    EntryPassword {
        id: String,
        password: Zeroizing<String>,
    },
    Saved {
        elapsed_ms: u128,
        sync_result: Option<std::result::Result<(), String>>,
        uploaded_sha256: Option<String>,
        retry_base_sha256: Option<String>,
        path: Option<PathBuf>,
    },
    MasterPasswordChanged,
    FtpsTest(std::result::Result<(), String>),
    Error(String),
}

struct Vault {
    db: Option<Database>,
    key: Option<CompositeKey>,
    path: Option<PathBuf>,
    pending_sync: Option<sync::PendingSync>,
    retry_base_sha256: Option<String>,
}

pub fn spawn_worker(ctx: eframe::egui::Context) -> (Sender<Command>, Receiver<Event>) {
    let (command_tx, command_rx) = unbounded::<Command>();
    let (event_tx, event_rx) = unbounded::<Event>();
    thread::Builder::new()
        .name("peplos-vault".into())
        .spawn(move || worker_loop(command_rx, event_tx, ctx))
        .expect("could not start the Peplos database worker");
    (command_tx, event_rx)
}

fn worker_loop(rx: Receiver<Command>, tx: Sender<Event>, ctx: eframe::egui::Context) {
    let mut vault = Vault {
        db: None,
        key: None,
        path: None,
        pending_sync: None,
        retry_base_sha256: None,
    };
    while let Ok(command) = rx.recv() {
        let result = match command {
            Command::Create { path, password } => {
                send(&tx, &ctx, Event::Progress("Создаю зашифрованную базу…".into()));
                match create_database(&path, password) {
                    Ok((db, key)) => {
                        let snap = snapshot(&db);
                        vault.db = Some(db); vault.key = Some(key); vault.path = Some(path.clone());
                        vault.pending_sync = None; vault.retry_base_sha256 = None;
                        Event::Opened { path, snapshot: snap }
                    }
                    Err(error) => Event::Error(error.to_string()),
                }
            }
            Command::Unlock {
                path,
                password,
                key_file,
                sync,
            } => {
                send(
                    &tx,
                    &ctx,
                    Event::Progress("Проверяю и расшифровываю базу…".into()),
                );
                let opened = open(&path, password, key_file);
                match opened {
                    Ok((db, key)) => {
                        vault.db = Some(db);
                        vault.key = Some(key);
                        vault.path = Some(path.clone());
                        vault.pending_sync = None;
                        if let Some(request) = sync {
                            send(&tx, &ctx, Event::Progress("Проверяю версию базы на сервере…".into()));
                            finish_sync(&mut vault, Instant::now(), Some(path), &tx, &ctx, |vault| {
                                sync::check(vault, request, false)
                            })
                        } else {
                            Event::Opened { path, snapshot: snapshot(vault.db.as_ref().unwrap()) }
                        }
                    }
                    Err(error) => Event::Error(error.to_string()),
                }
            }
            Command::RenameGroup { id, title } => mutate(&mut vault, |db| {
                let id = parse_node_id(&id)?;
                let group = db
                    .groups
                    .get_mut(&id)
                    .ok_or_else(|| anyhow!("Папка не найдена"))?;
                group.title = title;
                group.last_modification_time = keepass_rs::DateInstant::now();
                db.mark_modified();
                Ok(())
            }),
            Command::MoveGroupToRecycleBin { id } => mutate(&mut vault, |db| {
                let id = parse_node_id(&id)?;
                if !db.groups.contains_key(&id) {
                    return Err(anyhow!("Папка не найдена"));
                }
                let existing = find_recycle_bin(db)?;
                if db.root_group_id == Some(id) || existing == Some(id) {
                    return Err(anyhow!("Эту системную папку нельзя переместить в корзину"));
                }
                if existing.is_some_and(|bin| group_contains(db, id, bin)) {
                    return Err(anyhow!("Эта папка содержит корзину и не может быть перемещена в неё"));
                }
                if existing.is_some_and(|bin| group_contains(db, bin, id)) {
                    return Err(anyhow!("Папка уже находится в корзине"));
                }
                ensure_recycle_bin(db, existing)?;
                db.remove_group(&id, true)
                    .ok_or_else(|| anyhow!("Не удалось переместить папку в корзину"))?;
                Ok(())
            }),
            Command::MoveEntryToRecycleBin { id } => mutate(&mut vault, |db| {
                recycle_entry(db, parse_node_id(&id)?)
            }),
            Command::DeleteRecycledGroup { id } => mutate(&mut vault, |db| {
                delete_recycled_group(db, parse_node_id(&id)?)
            }),
            Command::DeleteRecycledEntry { id } => mutate(&mut vault, |db| {
                delete_recycled_entry(db, parse_node_id(&id)?)
            }),
            Command::ConsolidateRecycleBin { destination } => mutate(&mut vault, |db| {
                consolidate_recycle_bin(db, parse_node_id(&destination)?)
            }),
            Command::SetGroupIcon { id, icon_id, png } => mutate(&mut vault, |db| {
                set_group_icon(db, &id, icon_id, png)?;
                Ok(())
            }),
            Command::CreateGroup {
                parent_id,
                title,
                icon_id,
                png,
            } => mutate(&mut vault, |db| {
                let parent_id = parse_node_id(&parent_id)?;
                if !db.groups.contains_key(&parent_id) {
                    return Err(anyhow!("Папка не найдена"));
                }
                let id = NodeId::new_uuid();
                let mut group = Group::new(id);
                group.title = title;
                group.icon = IconImage::Standard(IconImageStandard::new(icon_id));
                db.groups.insert(id, group);
                db.groups.get_mut(&parent_id).unwrap().add_child_group(id);
                if png.is_some() {
                    set_group_icon(db, &node_id_string(id), icon_id, png)?;
                }
                db.mark_modified();
                Ok(())
            }),
            Command::CreateEntry {
                group_id,
                title,
                username,
                password,
                url,
                notes,
                tags,
                png,
            } => mutate(&mut vault, |db| {
                let group_id = parse_node_id(&group_id)?;
                if !db.groups.contains_key(&group_id) {
                    return Err(anyhow!("Папка не найдена"));
                }
                let id = NodeId::new_uuid();
                let mut entry = Entry::new(id);
                entry.title = title;
                entry.username = ProtectedString::new_plain(&username);
                entry.password = ProtectedString::new_protected(password.as_str());
                entry.url = url;
                entry.notes = ProtectedString::new_plain(&notes);
                entry.tags = tags;
                entry.last_modification_time = keepass_rs::DateInstant::now();
                db.add_entry(entry, &group_id);
                if png.is_some() {
                    set_entry_icon(db, &node_id_string(id), png)?;
                }
                Ok(())
            }),
            Command::EditEntry {
                id,
                title,
                username,
                password,
                clear_password,
                url,
                notes,
                tags,
            } => mutate(&mut vault, |db| {
                let id = parse_node_id(&id)?;
                let entry = db
                    .entries
                    .get_mut(&id)
                    .ok_or_else(|| anyhow!("Запись не найдена"))?;
                entry.title = title;
                entry.username = ProtectedString::new_plain(&username);
                if clear_password {
                    entry.password = ProtectedString::new_protected("");
                } else if let Some(password) = password {
                    entry.password = ProtectedString::new_protected(password.as_str());
                }
                entry.url = url;
                entry.notes = ProtectedString::new_plain(&notes);
                entry.tags = tags;
                entry.last_modification_time = keepass_rs::DateInstant::now();
                db.mark_modified();
                Ok(())
            }),
            Command::SetEntryIcon { id, png } => mutate(&mut vault, |db| {
                set_entry_icon(db, &id, png)?;
                Ok(())
            }),
            Command::CopyPassword { id } => match get_password(&vault, &id) {
                Ok(secret) => Event::Password(Zeroizing::new(secret)),
                Err(error) => Event::Error(error.to_string()),
            },
            Command::GetEntryPassword { id } => match get_password(&vault, &id) {
                Ok(secret) => Event::EntryPassword {
                    id,
                    password: Zeroizing::new(secret),
                },
                Err(error) => Event::Error(error.to_string()),
            },
            Command::Save { sync } => {
                send(
                    &tx,
                    &ctx,
                    Event::Progress("Сохраняю зашифрованный файл…".into()),
                );
                let start = Instant::now();
                let needs_save = vault.db.as_ref().is_some_and(|db| db.data_modified);
                let saved = if needs_save { save(&mut vault) } else { Ok(()) };
                match saved {
                    Ok(()) => return_sync(&mut vault, sync, start, None, &tx, &ctx),
                    Err(error) => Event::Error(error.to_string()),
                }
            }
            Command::SaveAs { path, sync } => {
                send(&tx, &ctx, Event::Progress("Сохраняю копию базы…".into()));
                let start = Instant::now();
                match save_to(&mut vault, &path) {
                    Ok(()) => {
                        vault.path = Some(path.clone());
                        return_sync(&mut vault, sync, start, Some(path), &tx, &ctx)
                    }
                    Err(error) => Event::Error(error.to_string()),
                }
            }
            Command::ChangeMasterPassword { mut password } => {
                send(
                    &tx,
                    &ctx,
                    Event::Progress("Меняю мастер-пароль базы…".into()),
                );
                if password.is_empty() {
                    Event::Error("Новый мастер-пароль не может быть пустым".into())
                } else if let (Some(old_key), Some(db)) = (vault.key.as_ref(), vault.db.as_mut()) {
                    let mut new_key = CompositeKey::new().with_password(password.as_bytes());
                    password.zeroize();
                    new_key.key_file_data = old_key.key_file_data.clone();
                    new_key.hardware_key = old_key.hardware_key.clone();
                    vault.key = Some(new_key);
                    db.mark_modified();
                    Event::MasterPasswordChanged
                } else {
                    password.zeroize();
                    Event::Error("База не открыта".into())
                }
            }
            Command::ResolveSync(decision) => {
                send(&tx, &ctx, Event::Progress("Выполняется синхронизация…".into()));
                finish_sync(&mut vault, Instant::now(), None, &tx, &ctx, |vault| sync::resolve(vault, decision))
            }
            Command::TestFtps { config } => match test_ftps(&config) {
                Ok(()) => Event::FtpsTest(Ok(())),
                Err(error) => Event::FtpsTest(Err(error.to_string())),
            },
        };
        send(&tx, &ctx, result);
    }
}

fn send(tx: &Sender<Event>, ctx: &eframe::egui::Context, event: Event) {
    let _ = tx.send(event);
    ctx.request_repaint();
}

fn return_sync(
    vault: &mut Vault,
    sync: Option<SyncRequest>,
    start: Instant,
    path: Option<PathBuf>,
    tx: &Sender<Event>,
    ctx: &eframe::egui::Context,
) -> Event {
    if let Some(request) = sync {
        send(tx, ctx, Event::Progress("Выполняется синхронизация…".into()));
        return finish_sync(vault, start, path, tx, ctx, |vault| sync::check(vault, request, true));
    }
    Event::Saved {
        elapsed_ms: start.elapsed().as_millis(),
        sync_result: None,
        uploaded_sha256: None,
        retry_base_sha256: None,
        path,
    }
}

fn finish_sync(
    vault: &mut Vault,
    start: Instant,
    path: Option<PathBuf>,
    tx: &Sender<Event>,
    ctx: &eframe::egui::Context,
    operation: impl FnOnce(&mut Vault) -> Result<sync::Outcome>,
) -> Event {
    vault.retry_base_sha256 = None;
    let (sync_result, uploaded_sha256) = match operation(vault) {
        Ok(sync::Outcome::Done(hash)) => (Ok(()), Some(hash)),
        Ok(sync::Outcome::Conflict(conflict)) => {
            if let Some(path) = path {
                send(tx, ctx, Event::Opened { path, snapshot: snapshot(vault.db.as_ref().unwrap()) });
            }
            return Event::SyncConflict(conflict);
        }
        Err(error) => (Err(format!("{error:#}")), None),
    };
    if let Some(db) = &vault.db {
        let snapshot = snapshot(db);
        if let Some(path) = path.as_ref() {
            send(tx, ctx, Event::Opened { path: path.clone(), snapshot });
        } else {
            send(tx, ctx, Event::Changed(snapshot));
        }
    }
    Event::Saved {
        elapsed_ms: start.elapsed().as_millis(),
        sync_result: Some(sync_result),
        uploaded_sha256,
        retry_base_sha256: vault.retry_base_sha256.take(),
        path,
    }
}

fn mutate(vault: &mut Vault, action: impl FnOnce(&mut Database) -> Result<()>) -> Event {
    let Some(db) = vault.db.as_mut() else {
        return Event::Error("Сначала откройте базу".into());
    };
    match action(db) {
        Ok(()) => Event::Changed(snapshot(db)),
        Err(error) => Event::Error(error.to_string()),
    }
}

fn create_database(path: &Path, mut password: Zeroizing<String>) -> Result<(Database, CompositeKey)> {
    anyhow::ensure!(!password.is_empty(), "Мастер-пароль не может быть пустым");
    let key = CompositeKey::new().with_password(password.as_bytes());
    password.zeroize();
    let mut db = Database::new(DatabaseVersion::KDBX4);
    let mut root = Group::new(NodeId::new_uuid());
    root.title = "Peplos".into();
    db.root_group_id = Some(root.id);
    db.groups.insert(root.id, root);
    let mut bytes = Vec::new();
    save_database(&mut bytes, &db, &key).context("Не удалось зашифровать новую базу")?;
    let check = open_database(bytes.as_slice(), &key).context("Проверка новой базы не прошла")?;
    anyhow::ensure!(check.root_group_id == db.root_group_id, "Проверка новой базы не прошла");
    let parent = path.parent().context("Некорректный путь к базе")?;
    let temp = parent.join(format!(".peplos-{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut out = OpenOptions::new().write(true).create_new(true).open(&temp)?;
        out.write_all(&bytes)?; out.sync_all()?; drop(out);
        fs::hard_link(&temp, path).context("Не удалось создать базу: файл уже существует или папка не поддерживает создание файла")?;
        Ok(())
    })();
    let _ = fs::remove_file(temp);
    result?;
    db.data_modified = false;
    Ok((db, key))
}

fn open(
    path: &Path,
    mut password: Zeroizing<String>,
    key_file: Option<PathBuf>,
) -> Result<(Database, CompositeKey)> {
    let mut key = CompositeKey::new();
    if !password.is_empty() {
        key = key.with_password(password.as_bytes());
    }
    password.zeroize();
    let mut key_file_material = match key_file {
        Some(path) => Some(
            read_key_file(&path)
                .with_context(|| format!("Файл ключа {} не удалось прочитать", path.display()))?,
        ),
        None => None,
    };
    if let Some(ref material) = key_file_material {
        key = key.with_key_file(material.as_slice());
    }
    if let Some(ref mut material) = key_file_material {
        material.zeroize();
    }
    let file = File::open(path)
        .with_context(|| format!("Файл базы не удалось открыть: {}", path.display()))?;
    let db = open_database(file, &key)
        .map_err(|error| anyhow!("Ошибка чтения базы KeePass: {error}"))?;
    Ok((db, key))
}

fn read_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(fs::read(path)?);
    if bytes.len() == 32 {
        return Ok(bytes);
    }
    if bytes.len() == 64 && bytes.iter().all(u8::is_ascii_hexdigit) {
        let text = std::str::from_utf8(&bytes)?;
        return Ok(Zeroizing::new(hex_decode(text)?));
    }
    if bytes.is_empty() {
        return Err(anyhow!("Файл-ключ пустой"));
    }
    if let Ok(text) = std::str::from_utf8(&bytes) {
        let candidate = text.trim_start_matches('\u{feff}').trim_start();
        if !candidate.starts_with('<') {
            return Ok(bytes);
        }
        let mut reader = quick_xml::Reader::from_str(candidate);
        reader.config_mut().trim_text(true);
        let mut version = None;
        let mut encoded_data: Option<Zeroizing<String>> = None;
        let mut declared_hash = None;
        loop {
            match reader.read_event() {
                Ok(quick_xml::events::Event::Start(tag)) if tag.name().as_ref() == b"Version" => {
                    version = Some(reader.read_text(tag.name())?.trim().to_owned());
                }
                Ok(quick_xml::events::Event::Start(tag)) if tag.name().as_ref() == b"Data" => {
                    for attribute in tag.attributes() {
                        let attribute = attribute?;
                        if attribute.key.as_ref() == b"Hash" {
                            declared_hash = Some(
                                attribute
                                    .decode_and_unescape_value(reader.decoder())?
                                    .into_owned(),
                            );
                        }
                    }
                    let data = reader
                        .read_text(tag.name())?
                        .chars()
                        .filter(|ch| !ch.is_whitespace())
                        .collect::<String>();
                    encoded_data = Some(Zeroizing::new(data));
                }
                Ok(quick_xml::events::Event::Eof) => break,
                Err(error) => return Err(error.into()),
                _ => {}
            }
        }
        let data =
            encoded_data.ok_or_else(|| anyhow!("В XML-файле ключа отсутствует поле Data"))?;
        let version =
            version.ok_or_else(|| anyhow!("В XML-файле ключа отсутствует версия формата"))?;
        let key = match version.as_str() {
            v if v.starts_with("1.0") => Zeroizing::new(
                STANDARD
                    .decode(data.as_bytes())
                    .context("Некорректные данные XML-файла ключа версии 1.0")?,
            ),
            "2.0" => {
                let key = Zeroizing::new(
                    hex_decode(data.as_str())
                        .context("Некорректные шестнадцатеричные данные XML-файла ключа")?,
                );
                let hash_text = declared_hash.ok_or_else(|| {
                    anyhow!("В XML-файле ключа версии 2.0 отсутствует контрольная сумма")
                })?;
                let hash = hex_decode(&hash_text)
                    .context("Некорректная контрольная сумма XML-файла ключа")?;
                let expected = Sha256::digest(key.as_slice());
                if hash.as_slice() != &expected[..4] {
                    return Err(anyhow!("Контрольная сумма XML-файла ключа не совпадает"));
                }
                key
            }
            other => return Err(anyhow!("Неподдерживаемая версия XML-файла ключа: {other}")),
        };
        let mut normalized = Zeroizing::new(vec![0u8; 32]);
        let length = key.len().min(32);
        normalized[..length].copy_from_slice(&key[..length]);
        return Ok(normalized);
    }
    Ok(bytes)
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(anyhow!("Некорректная шестнадцатеричная длина ключа"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

fn parse_node_id(value: &str) -> Result<NodeId> {
    if let Some(raw) = value.strip_prefix("int:") {
        return Ok(NodeId::from_int(raw.parse()?));
    }
    Ok(NodeId::from_uuid(Uuid::parse_str(value)?))
}

pub fn node_id_string(id: NodeId) -> String {
    match id {
        NodeId::Uuid(uuid) => uuid.hyphenated().to_string(),
        NodeId::Int(number) => format!("int:{number}"),
    }
}

fn set_group_icon(db: &mut Database, id: &str, icon_id: u32, png: Option<Vec<u8>>) -> Result<()> {
    let id = parse_node_id(id)?;
    if !db.groups.contains_key(&id) {
        return Err(anyhow!("Папка не найдена"));
    }
    if let Some(png) = png {
        let uuid = Uuid::new_v4();
        db.custom_icons.insert(
            uuid,
            IconImageCustom {
                uuid,
                data: png,
                name: String::new(),
                last_modification_time: 0,
            },
        );
        let group = db.groups.get_mut(&id).unwrap();
        group.custom_icon_uuid = Some(uuid);
        group.icon = IconImage::Standard(IconImageStandard::new(icon_id));
    } else {
        let group = db.groups.get_mut(&id).unwrap();
        group.custom_icon_uuid = None;
        group.icon = IconImage::Standard(IconImageStandard::new(icon_id));
    }
    db.groups.get_mut(&id).unwrap().last_modification_time = keepass_rs::DateInstant::now();
    db.mark_modified();
    Ok(())
}

fn set_entry_icon(db: &mut Database, id: &str, png: Option<Vec<u8>>) -> Result<()> {
    let id = parse_node_id(id)?;
    if let Some(png) = png {
        let uuid = Uuid::new_v4();
        db.custom_icons.insert(
            uuid,
            IconImageCustom {
                uuid,
                data: png,
                name: String::new(),
                last_modification_time: 0,
            },
        );
        let entry = db
            .entries
            .get_mut(&id)
            .ok_or_else(|| anyhow!("Запись не найдена"))?;
        entry.custom_icon_uuid = Some(uuid);
        entry.last_modification_time = keepass_rs::DateInstant::now();
    } else {
        let entry = db
            .entries
            .get_mut(&id)
            .ok_or_else(|| anyhow!("Запись не найдена"))?;
        entry.custom_icon_uuid = None;
        entry.last_modification_time = keepass_rs::DateInstant::now();
    }
    db.mark_modified();
    Ok(())
}

fn get_password(vault: &Vault, id: &str) -> Result<String> {
    let db = vault
        .db
        .as_ref()
        .ok_or_else(|| anyhow!("Сначала откройте базу"))?;
    let id = parse_node_id(id)?;
    let entry = db
        .entries
        .get(&id)
        .ok_or_else(|| anyhow!("Запись не найдена"))?;
    Ok(entry.password.as_str().to_owned())
}

fn save(vault: &mut Vault) -> Result<()> {
    let path = vault
        .path
        .clone()
        .ok_or_else(|| anyhow!("Путь к базе отсутствует"))?;
    save_to(vault, &path)
}

fn save_to(vault: &mut Vault, path: &Path) -> Result<()> {
    let db = vault
        .db
        .as_ref()
        .ok_or_else(|| anyhow!("Сначала откройте базу"))?;
    let key = vault
        .key
        .as_ref()
        .ok_or_else(|| anyhow!("Ключ базы отсутствует"))?;
    let mut bytes = Vec::new();
    save_database(&mut bytes, db, key).context("Не удалось зашифровать базу")?;
    install_database(path, &bytes, key, db)?;
    if let Some(db) = vault.db.as_mut() {
        db.data_modified = false;
    }
    Ok(())
}

fn install_database(path: &Path, bytes: &[u8], key: &CompositeKey, db: &Database) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Некорректный путь к базе"))?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("database.kdbx");
    let temp = parent.join(format!(".{file_name}.peplos-{}.tmp", Uuid::new_v4()));
    let write_result = (|| -> Result<()> {
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        out.write_all(bytes)?;
        out.sync_all()?;
        drop(out);
        let check = open_database(File::open(&temp)?, key).map_err(|_| {
            anyhow!("Проверка временного KDBX-файла не прошла; исходная база не изменена")
        })?;
        if check.entry_count() != db.entry_count() || check.group_count() != db.group_count() {
            return Err(anyhow!(
                "Проверка сохранённого файла не совпала; исходная база не изменена"
            ));
        }
        let permissions = fs::metadata(path)
            .ok()
            .map(|metadata| metadata.permissions());
        if let Some(permissions) = permissions {
            fs::set_permissions(&temp, permissions)?;
        }
        fs::rename(&temp, path)
            .with_context(|| format!("Не удалось заменить базу {}", path.display()))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write_result
}

pub fn is_recycle_bin_name(name: &str) -> bool {
    let name = name.trim();
    name.eq_ignore_ascii_case("Recycle Bin") || name.to_lowercase() == "корзина"
}

fn find_recycle_bin(db: &Database) -> Result<Option<NodeId>> {
    if let Some(id) = db.recycle_bin_uuid.map(NodeId::from_uuid) {
        if Some(id) != db.root_group_id && db.groups.contains_key(&id) {
            return Ok(Some(id));
        }
    }
    let root = db.root_group().context("Корневая папка базы отсутствует")?;
    let mut candidates = root.child_group_ids.iter().filter_map(|id| {
        let group = db.groups.get(id)?;
        (is_recycle_bin_name(&group.title)
            && matches!(id, NodeId::Uuid(uuid) if Some(*uuid) != db.entry_templates_uuid))
            .then_some(*id)
    });
    let first = candidates.next();
    if candidates.next().is_some() {
        return Err(anyhow!("Найдено несколько папок корзины. Запись или папка осталась на месте."));
    }
    Ok(first)
}

fn ensure_recycle_bin(db: &mut Database, existing: Option<NodeId>) -> Result<NodeId> {
    if let Some(NodeId::Uuid(uuid)) = existing {
        if db.recycle_bin_uuid != Some(uuid) {
            db.recycle_bin_uuid = Some(uuid);
            db.mark_modified();
        }
        return Ok(NodeId::Uuid(uuid));
    }
    db.root_group().context("Корневая папка базы отсутствует")?;
    db.recycle_bin_uuid = None;
    Ok(db.create_recycle_bin())
}

fn recycle_entry(db: &mut Database, id: NodeId) -> Result<()> {
    if !db.entries.contains_key(&id) {
        return Err(anyhow!("Запись не найдена"));
    }
    let parent = db.find_parent_group_of_entry(&id).context("Папка записи не найдена")?;
    let existing = find_recycle_bin(db)?;
    if existing.is_some_and(|bin| group_contains(db, bin, parent)) {
        return Err(anyhow!("Запись уже находится в корзине"));
    }
    ensure_recycle_bin(db, existing)?;
    db.remove_entry(&id, true).context("Не удалось переместить запись в корзину")?;
    Ok(())
}

fn delete_recycled_entry(db: &mut Database, id: NodeId) -> Result<()> {
    let bin = find_recycle_bin(db)?.context("Корзина не найдена")?;
    let parent = db.find_parent_group_of_entry(&id).context("Запись не найдена")?;
    if !group_contains(db, bin, parent) {
        return Err(anyhow!("Окончательно удалить можно только запись из корзины"));
    }
    db.remove_entry(&id, false).context("Не удалось удалить запись из корзины")?;
    Ok(())
}

fn delete_recycled_group(db: &mut Database, id: NodeId) -> Result<()> {
    let bin = find_recycle_bin(db)?.context("Корзина не найдена")?;
    if id == bin || Some(id) == db.root_group_id || !group_contains(db, bin, id) {
        return Err(anyhow!("Окончательно удалить можно только папку внутри корзины"));
    }
    db.remove_group(&id, false).context("Не удалось удалить папку из корзины")?;
    db.deleted_objects.push(id);
    Ok(())
}

fn group_contains(db: &Database, parent: NodeId, child: NodeId) -> bool {
    let mut pending = vec![parent];
    let mut visited = std::collections::HashSet::new();
    while let Some(id) = pending.pop() {
        if id == child {
            return true;
        }
        if visited.insert(id) {
            if let Some(group) = db.groups.get(&id) {
                pending.extend(group.child_group_ids.iter().copied());
            }
        }
    }
    false
}

fn consolidate_recycle_bin(db: &mut Database, destination: NodeId) -> Result<()> {
    let source = db.recycle_bin_uuid.map(NodeId::from_uuid).context("Активная корзина не найдена")?;
    let root = db.root_group().context("Корневая папка базы отсутствует")?;
    let root_id = root.id;
    if source == destination
        || !root.child_group_ids.contains(&source)
        || !root.child_group_ids.contains(&destination)
    {
        return Err(anyhow!("Объединить можно только две разные корзины в корне базы"));
    }
    let NodeId::Uuid(uuid) = destination else {
        return Err(anyhow!("Папка не поддерживает назначение корзиной"));
    };
    let target = db.groups.get(&destination).context("Папка назначения не найдена")?;
    let active = db.groups.get(&source).context("Активная корзина не найдена")?;
    if !is_recycle_bin_name(&target.title) || !is_recycle_bin_name(&active.title)
        || db.entry_templates_uuid == Some(uuid)
        || db.entry_templates_uuid == db.recycle_bin_uuid
        || group_contains(db, source, destination)
        || group_contains(db, destination, source)
    {
        return Err(anyhow!("Подходящая папка корзины не найдена"));
    }
    let active = db.groups.remove(&source).expect("active group was validated");
    let target = db.groups.get_mut(&destination).expect("destination was validated");
    if !active.notes.is_empty() && active.notes != target.notes {
        if !target.notes.is_empty() {
            target.notes.push_str("\n\n");
        }
        target.notes.push_str(&active.notes);
    }
    for id in active.child_entry_ids {
        target.add_child_entry(id);
    }
    for id in active.child_group_ids {
        target.add_child_group(id);
    }
    db.groups.get_mut(&root_id).expect("root was validated")
        .child_group_ids.retain(|id| *id != source);
    db.recycle_bin_uuid = Some(uuid);
    db.deleted_objects.push(source);
    db.mark_modified();
    Ok(())
}

fn snapshot(db: &Database) -> VaultSnapshot {
    let root_id = db.root_group_id.map(node_id_string).unwrap_or_default();
    let mut groups = Vec::with_capacity(db.groups.len());
    let mut entries = Vec::with_capacity(db.entries.len());
    if let Some(root) = db.root_group() {
        let recycle_bin = find_recycle_bin(db).ok().flatten();
        walk_group(db, root.id, None, &mut groups, &mut entries, recycle_bin, 0);
    }
    VaultSnapshot {
        root_id,
        groups,
        entries,
        modified: db.data_modified,
    }
}

fn walk_group(
    db: &Database,
    id: NodeId,
    parent: Option<String>,
    groups: &mut Vec<GroupInfo>,
    entries: &mut Vec<EntryInfo>,
    recycle_bin: Option<NodeId>,
    depth: usize,
) {
    if depth > 128 {
        return;
    }
    let Some(group) = db.groups.get(&id) else {
        return;
    };
    let id_string = node_id_string(id);
    let icon_png = group
        .custom_icon_uuid
        .and_then(|uuid| db.custom_icons.get(&uuid).map(|icon| icon.data.clone()));
    groups.push(GroupInfo {
        id: id_string.clone(),
        parent_id: parent,
        title: group.title.clone(),
        child_groups: group
            .child_group_ids
            .iter()
            .map(|id| node_id_string(*id))
            .collect(),
        entry_count: group.child_entry_ids.len(),
        icon_id: match &group.icon {
            IconImage::Standard(i) => i.icon_id,
            IconImage::Custom(i) => i.uuid.as_bytes()[0] as u32,
        },
        icon_png: icon_png.clone(),
        is_recycle_bin: recycle_bin == Some(id),
    });
    for entry_id in &group.child_entry_ids {
        if let Some(entry) = db.entries.get(entry_id) {
            let own_icon = entry
                .custom_icon_uuid
                .and_then(|uuid| db.custom_icons.get(&uuid).map(|icon| icon.data.clone()));
            entries.push(EntryInfo {
                id: node_id_string(entry.id),
                group_id: id_string.clone(),
                title: entry.title.clone(),
                username: entry.username.as_str().to_string(),
                url: entry.url.clone(),
                notes: entry.notes.as_str().to_string(),
                tags: entry.tags.clone(),
                creation_time: entry.creation_time.as_millis(),
                last_modification_time: entry.last_modification_time.as_millis(),
                usage_count: entry.usage_count,
                icon_id: if own_icon.is_none() {
                    match &group.icon {
                        IconImage::Standard(i) => i.icon_id,
                        IconImage::Custom(i) => i.uuid.as_bytes()[0] as u32,
                    }
                } else {
                    match &entry.icon {
                        IconImage::Standard(i) => i.icon_id,
                        IconImage::Custom(i) => i.uuid.as_bytes()[0] as u32,
                    }
                },
                icon_png: own_icon.or_else(|| icon_png.clone()),
                has_custom_icon: entry.custom_icon_uuid.is_some(),
            });
        }
    }
    for child in &group.child_group_ids {
        walk_group(
            db,
            *child,
            Some(id_string.clone()),
            groups,
            entries,
            recycle_bin,
            depth + 1,
        );
    }
}

pub fn encode_icon_png(bytes: &[u8]) -> Result<Vec<u8>> {
    let image = image::load_from_memory(bytes).context("Формат изображения не поддерживается")?;
    let image = image
        .resize(256, 256, image::imageops::FilterType::Lanczos3)
        .to_rgba8();
    let mut output = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image).write_to(&mut output, image::ImageFormat::Png)?;
    Ok(output.into_inner())
}

#[cfg(test)]
mod time_roundtrip_tests {
    use keepass_rs::{
        DatabaseVersion, DateInstant, KdbxXmlReader, KdbxXmlWriter, Salsa20InnerStream,
    };

    use super::*;

    fn recycle_fixture() -> (Database, NodeId, NodeId) {
        let mut db = Database::default();
        let root = NodeId::new_uuid();
        db.groups.insert(root, Group::new(root));
        db.root_group_id = Some(root);
        let bin = NodeId::new_uuid();
        let mut group = Group::new(bin);
        group.title = "Recycle Bin".into();
        assert!(db.add_group(group, &root));
        (db, root, bin)
    }

    #[test]
    fn new_database_roundtrip_and_no_overwrite() {
        let dir = std::env::temp_dir().join(format!("peplos-create-test-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("new.kdbx");
        let (db, _) = create_database(&path, Zeroizing::new("test master password".into())).unwrap();
        assert_eq!(db.group_count(), 1);
        let original = std::fs::read(&path).unwrap();
        let (reopened, _) = open(&path, Zeroizing::new("test master password".into()), None).unwrap();
        assert_eq!(reopened.root_group_id, db.root_group_id);
        assert!(open(&path, Zeroizing::new("incorrect".into()), None).is_err());
        assert!(create_database(&path, Zeroizing::new("other".into())).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn existing_recycle_bin_without_metadata_is_reused() {
        let (mut db, root, bin) = recycle_fixture();
        let entry = NodeId::new_uuid();
        assert!(db.add_entry(Entry::new(entry), &root));
        let key = b"recycle-bin-test";
        let xml = KdbxXmlWriter::write(&db, &mut Salsa20InnerStream::new(key)).unwrap();
        let mut db = KdbxXmlReader::read(&xml, &mut Salsa20InnerStream::new(key)).unwrap();
        assert!(db.recycle_bin_uuid.is_none());
        recycle_entry(&mut db, entry).unwrap();
        assert_eq!(db.find_parent_group_of_entry(&entry), Some(bin));
        assert!(db.is_recycle_bin(&bin));
        assert_eq!(db.groups.len(), 2);
        assert!(db.deleted_objects.is_empty());
        let xml = KdbxXmlWriter::write(&db, &mut Salsa20InnerStream::new(key)).unwrap();
        let reopened = KdbxXmlReader::read(&xml, &mut Salsa20InnerStream::new(key)).unwrap();
        assert!(reopened.is_recycle_bin(&bin));
        assert_eq!(reopened.find_parent_group_of_entry(&entry), Some(bin));
    }

    #[test]
    fn consolidation_keeps_entries_and_subfolders_in_the_chosen_bin() {
        let (mut db, root, original) = recycle_fixture();
        let active = db.create_recycle_bin();
        let entry = NodeId::new_uuid();
        assert!(db.add_entry(Entry::new(entry), &active));
        let subfolder = NodeId::new_uuid();
        assert!(db.add_group(Group::new(subfolder), &active));
        let nested = NodeId::new_uuid();
        assert!(db.add_entry(Entry::new(nested), &subfolder));
        assert_eq!(find_recycle_bin(&db).unwrap(), Some(active));
        consolidate_recycle_bin(&mut db, original).unwrap();
        assert_eq!(find_recycle_bin(&db).unwrap(), Some(original));
        assert_eq!(db.groups[&root].child_group_ids, vec![original]);
        assert_eq!(db.groups[&original].child_group_ids, vec![subfolder]);
        assert_eq!(db.find_parent_group_of_entry(&entry), Some(original));
        assert_eq!(db.find_parent_group_of_entry(&nested), Some(subfolder));
        assert_eq!(db.deleted_objects, vec![active]);
    }

    #[test]
    fn ambiguous_unregistered_bins_leave_entry_in_place() {
        let (mut db, root, _) = recycle_fixture();
        db.create_recycle_bin();
        db.recycle_bin_uuid = None;
        let entry = NodeId::new_uuid();
        assert!(db.add_entry(Entry::new(entry), &root));
        assert!(recycle_entry(&mut db, entry).is_err());
        assert_eq!(db.find_parent_group_of_entry(&entry), Some(root));
        assert_eq!(db.groups.len(), 3);
        assert!(db.deleted_objects.is_empty());
    }

    #[test]
    fn permanent_deletion_is_limited_to_the_recycle_bin_and_survives_reopen() {
        let (mut db, root, bin) = recycle_fixture();
        let subfolder = NodeId::new_uuid();
        assert!(db.add_group(Group::new(subfolder), &bin));
        let kept = NodeId::new_uuid();
        let removed = NodeId::new_uuid();
        assert!(db.add_entry(Entry::new(kept), &root));
        assert!(db.add_entry(Entry::new(removed), &subfolder));

        assert!(delete_recycled_entry(&mut db, kept).is_err());
        delete_recycled_entry(&mut db, removed).unwrap();

        let key = b"delete-recycled-entry-test";
        let xml = KdbxXmlWriter::write(&db, &mut Salsa20InnerStream::new(key)).unwrap();
        let reopened = KdbxXmlReader::read(&xml, &mut Salsa20InnerStream::new(key)).unwrap();
        assert!(reopened.entries.contains_key(&kept));
        assert!(!reopened.entries.contains_key(&removed));
        assert!(reopened.groups[&subfolder].child_entry_ids.is_empty());
        assert_eq!(reopened.deleted_objects, vec![removed]);
    }

    #[test]
    fn deleting_a_recycled_folder_removes_only_its_subtree() {
        let (mut db, root, bin) = recycle_fixture();
        let folder = NodeId::new_uuid();
        let nested = NodeId::new_uuid();
        let sibling = NodeId::new_uuid();
        let entry = NodeId::new_uuid();
        assert!(db.add_group(Group::new(folder), &bin));
        assert!(db.add_group(Group::new(nested), &folder));
        assert!(db.add_group(Group::new(sibling), &root));
        assert!(db.add_entry(Entry::new(entry), &nested));
        assert!(delete_recycled_group(&mut db, sibling).is_err());
        assert!(delete_recycled_group(&mut db, bin).is_err());
        delete_recycled_group(&mut db, folder).unwrap();
        assert!(db.groups[&bin].child_group_ids.is_empty());
        assert!(db.groups.contains_key(&sibling));
        for id in [folder, nested, entry] {
            assert!(!db.groups.contains_key(&id));
            assert!(!db.entries.contains_key(&id));
            assert!(db.deleted_objects.contains(&id));
        }
    }

    #[test]
    fn entry_and_group_access_times_survive_save() {
        let mut db = Database::default();
        let root_id = NodeId::new_uuid();
        let entry_id = NodeId::new_uuid();
        let mut group = Group::new(root_id);
        group.title = "Root".into();
        group.last_access_time = DateInstant::EpochMillis(1_600_000_000_000);
        group.add_child_entry(entry_id);
        let mut entry = Entry::new(entry_id);
        entry.title = "Example".into();
        entry.creation_time = DateInstant::EpochMillis(1_500_000_000_000);
        entry.last_modification_time = DateInstant::EpochMillis(1_600_000_000_000);
        entry.last_access_time = DateInstant::EpochMillis(1_700_000_000_000);
        entry.usage_count = 7;
        entry.tags = vec!["Work".into(), "Shared".into()];
        db.groups.insert(root_id, group);
        db.entries.insert(entry_id, entry);
        db.root_group_id = Some(root_id);

        for version in [DatabaseVersion::KDBX31, DatabaseVersion::KDBX4] {
            db.version = version;
            let key = b"peplos-roundtrip-check";
            let xml = KdbxXmlWriter::write(&db, &mut Salsa20InnerStream::new(key)).unwrap();
            let reopened = KdbxXmlReader::read(&xml, &mut Salsa20InnerStream::new(key)).unwrap();
            let entry = reopened.entries.get(&entry_id).unwrap();
            assert_eq!(
                entry.creation_time,
                DateInstant::EpochMillis(1_500_000_000_000)
            );
            assert_eq!(
                entry.last_modification_time,
                DateInstant::EpochMillis(1_600_000_000_000)
            );
            assert_eq!(
                entry.last_access_time,
                DateInstant::EpochMillis(1_700_000_000_000)
            );
            assert_eq!(entry.usage_count, 7);
            assert_eq!(entry.tags, ["Work", "Shared"]);
            assert_eq!(
                reopened.groups.get(&root_id).unwrap().last_access_time,
                DateInstant::EpochMillis(1_600_000_000_000)
            );
        }

        let key = CompositeKey::new().with_password(b"synthetic-test-password");
        let mut encrypted_file = Vec::new();
        save_database(&mut encrypted_file, &db, &key).unwrap();
        let reopened = open_database(encrypted_file.as_slice(), &key).unwrap();
        let entry = reopened.entries.get(&entry_id).unwrap();
        assert_eq!(
            entry.last_access_time,
            DateInstant::EpochMillis(1_700_000_000_000)
        );
        assert_eq!(entry.tags, ["Work", "Shared"]);
    }
}

fn ftp_request(config: &SyncConfig, filename: Option<&str>, options: &str) -> Result<std::process::Output> {
    let encrypted = STANDARD
        .decode(&config.password_dpapi)
        .context("Сохранённый пароль FTPS повреждён")?;
    let password = crate::storage::unprotect_secret(&encrypted)?;
    let mut remote = url::Url::parse(&format!("ftp://{}:{}/", config.host, config.port))?;
    {
        let mut segments = remote
            .path_segments_mut()
            .map_err(|_| anyhow!("Некорректный FTPS-путь"))?;
        for part in config
            .remote_directory
            .trim_matches('/')
            .split('/')
            .filter(|part| !part.is_empty())
        {
            segments.push(part);
        }
        segments.push(filename.unwrap_or(""));
    }
    let remote_url = remote.to_string();
    let credentials = Zeroizing::new(format!("{}:{}", config.username, password.as_str()));
    let user = Zeroizing::new(curl_quote(&credentials)?);
    let url_line = curl_quote(&remote_url)?;
    let input = Zeroizing::new(format!("silent\nshow-error\nssl-reqd\nftp-pasv\ngloboff\nconnect-timeout = 8\nmax-time = 90\nuser = {}\nurl = {url_line}\n{options}", user.as_str()));
    let mut child = curl_command()
        .args(["--disable", "--config", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("В Windows не найден curl.exe")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("Не удалось подготовить FTPS-передачу"))?
        .write_all(input.as_bytes())?;
    Ok(child.wait_with_output()?)
}

fn curl_command() -> ProcessCommand {
    let mut command = ProcessCommand::new("curl.exe");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

fn test_ftps(config: &SyncConfig) -> Result<()> {
    let encrypted = STANDARD
        .decode(&config.password_dpapi)
        .context("Сохранённый пароль FTPS повреждён")?;
    let password = crate::storage::unprotect_secret(&encrypted)?;
    let mut remote = url::Url::parse(&format!("ftp://{}:{}/", config.host, config.port))?;
    {
        let mut segments = remote
            .path_segments_mut()
            .map_err(|_| anyhow!("Некорректный FTPS-путь"))?;
        for part in config
            .remote_directory
            .trim_matches('/')
            .split('/')
            .filter(|part| !part.is_empty())
        {
            segments.push(part);
        }
    }
    let credentials = Zeroizing::new(format!("{}:{}", config.username, password.as_str()));
    let user = Zeroizing::new(curl_quote(&credentials)?);
    let url_line = curl_quote(remote.as_str())?;
    let input = Zeroizing::new(format!(
        "silent\nshow-error\nfail\nssl-reqd\nftp-pasv\nlist-only\nuser = {}\nurl = {url_line}\n",
        user.as_str()
    ));
    let mut child = curl_command()
        .args(["--config", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("В Windows не найден curl.exe")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("Не удалось проверить FTPS-соединение"))?
        .write_all(input.as_bytes())?;
    let result = child.wait_with_output()?;
    if !result.status.success() {
        let message = String::from_utf8_lossy(&result.stderr).trim().to_string();
        return Err(anyhow!(if message.is_empty() {
            "Не удалось подключиться к FTPS-серверу".to_string()
        } else {
            message
        }));
    }
    Ok(())
}

fn curl_quote(value: &str) -> Result<String> {
    if value.chars().any(|c| c.is_control()) {
        return Err(anyhow!(
            "Значение FTPS-настройки содержит недопустимые управляющие символы"
        ));
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

#[allow(dead_code)]
fn icon_fingerprint(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
