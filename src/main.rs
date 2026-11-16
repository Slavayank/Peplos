#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
mod autotype;
mod storage;
mod vault;

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, FontFamily, FontId, Frame, Layout, Margin,
    RichText, Stroke, TextEdit, TextureHandle, TextureOptions, Vec2,
};
use sha2::{Digest, Sha256};
#[cfg(windows)]
use winit::platform::windows::WindowExtWindows;
#[cfg(windows)]
use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
use zeroize::{Zeroize, Zeroizing};

use storage::{AppSettings, SyncConfig, SyncState};
use vault::{Command, Conflict, Decision, EntryInfo, Event, GroupInfo, SyncRequest, VaultSnapshot};

const BG: Color32 = Color32::from_rgb(0, 0, 0);
const SURFACE: Color32 = Color32::from_rgb(28, 29, 35);
const SURFACE_RAISED: Color32 = Color32::from_rgb(37, 39, 47);
const ACCENT: Color32 = Color32::from_rgb(135, 100, 70); // #876446
const SECONDARY: Color32 = Color32::from_rgb(184, 181, 173);
const GOLD: Color32 = Color32::from_rgb(176, 134, 96); // #B08660
const WHITE: Color32 = Color32::from_rgb(242, 238, 231);
const MUTED: Color32 = Color32::from_rgb(151, 150, 146);
const BORDER: Color32 = Color32::from_rgba_unmultiplied_const(220, 210, 195, 24);
// Match the default rounded corner drawn by Windows 11.
const WINDOW_RADIUS: u8 = 8;

fn main() -> eframe::Result<()> {
    let icon = application_icon();
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1120.0, 730.0])
        .with_min_inner_size([760.0, 500.0])
        .with_title("Peplos")
        .with_resizable(true)
        .with_decorations(false)
        .with_transparent(true)
        .with_visible(false);
    if let Some(icon) = icon {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }
    let options = eframe::NativeOptions {
        viewport,
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "Peplos",
        options,
        Box::new(|cc| Ok(Box::new(PeplosApp::new(cc)))),
    )
}

fn application_icon() -> Option<egui::IconData> {
    let decoded = image::load_from_memory(include_bytes!("../assets/peplos-icon.png")).ok()?;
    let pixels = decoded
        .resize(256, 256, image::imageops::FilterType::Lanczos3)
        .to_rgba8();
    Some(egui::IconData {
        rgba: pixels.into_raw(),
        width: 256,
        height: 256,
    })
}

struct UnlockDraft {
    path: PathBuf,
    password: String,
    key_file: Option<PathBuf>,
    working: bool,
    focus_requested: bool,
    creating: bool,
    confirmation: String,
}

impl Drop for UnlockDraft {
    fn drop(&mut self) { self.password.zeroize(); self.confirmation.zeroize(); }
}

#[cfg(windows)]
struct AutoTypeRequest {
    id: String,
    username: String,
    own_window: isize,
    target_window: isize,
}

struct GroupDraft {
    id: Option<String>,
    parent_id: String,
    title: String,
    original_title: String,
    icon_id: u32,
    icon_id_changed: bool,
    icon_png: Option<Vec<u8>>,
    icon_changed: bool,
}

struct EntryDraft {
    id: Option<String>,
    group_id: String,
    title: String,
    username: String,
    password: String,
    show_password: bool,
    password_loading: bool,
    url: String,
    notes: String,
    tags_input: String,
    creation_time: Option<i64>,
    last_modification_time: Option<i64>,
    usage_count: i64,
    clear_password: bool,
    icon_png: Option<Vec<u8>>,
    icon_changed: bool,
}

impl Drop for EntryDraft {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

struct SyncDraft {
    enabled: bool,
    host: String,
    port: String,
    username: String,
    remote_directory: String,
    password: String,
    already_has_password: bool,
    master_password: String,
    master_password_confirm: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsTab { Overview, Connection, Security }

struct BreadcrumbSegment {
    title: String,
    glyph: u32,
    icon_png: Option<Vec<u8>>,
    group_id: Option<String>,
}

impl Drop for SyncDraft {
    fn drop(&mut self) {
        self.password.zeroize();
        self.master_password.zeroize();
        self.master_password_confirm.zeroize();
    }
}

struct PeplosApp {
    command_tx: crossbeam_channel::Sender<Command>,
    event_rx: crossbeam_channel::Receiver<Event>,
    settings: AppSettings,
    snapshot: Option<VaultSnapshot>,
    database_path: Option<PathBuf>,
    selected_group: Option<String>,
    selected_entry: Option<String>,
    #[cfg(windows)]
    pending_auto_type: Option<AutoTypeRequest>,
    #[cfg(windows)]
    auto_type_hotkey: bool,
    #[cfg(windows)]
    auto_type_running: bool,
    #[cfg(windows)]
    auto_type_result_tx: crossbeam_channel::Sender<Result<(), String>>,
    #[cfg(windows)]
    auto_type_result_rx: crossbeam_channel::Receiver<Result<(), String>>,
    expanded: HashSet<String>,
    search: String,
    search_focus_requested: bool,
    unlock: Option<UnlockDraft>,
    clipboard_password: Option<([u8; 32], Instant)>,
    group_editor: Option<GroupDraft>,
    entry_editor: Option<EntryDraft>,
    sync_editor: Option<SyncDraft>,
    sync_conflict: Option<Box<Conflict>>,
    show_conflict_secrets: bool,
    save_as_sync: Option<(PathBuf, SyncConfig)>,
    sync_in_flight: bool,
    settings_tab: SettingsTab,
    ftps_test_result: Option<std::result::Result<(), String>>,
    textures: HashMap<String, TextureHandle>,
    logo: TextureHandle,
    grain: TextureHandle,
    busy: bool,
    status: String,
    error: Option<String>,
    open_started: Instant,
    resize_hit_test_installed: bool,
    backdrop_checked: bool,
    backdrop_available: bool,
}

impl Drop for PeplosApp {
    fn drop(&mut self) { self.clear_expired_clipboard(true); }
}

impl PeplosApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        #[cfg(windows)]
        let (auto_type_result_tx, auto_type_result_rx) = crossbeam_channel::unbounded();
        apply_theme(&cc.egui_ctx);
        let logo_image = image::load_from_memory(include_bytes!("../assets/peplos-wordmark.png"))
            .expect("embedded Peplos wordmark is a valid PNG")
            .to_rgba8();
        let logo = cc.egui_ctx.load_texture(
            "peplos-logo",
            egui::ColorImage::from_rgba_unmultiplied(
                [logo_image.width() as usize, logo_image.height() as usize],
                logo_image.as_raw(),
            ),
            // The wordmark is displayed much smaller than its source PNG.
            // Trilinear minification prevents jagged shield edges at UI sizes.
            TextureOptions::LINEAR.with_mipmap_mode(Some(egui::TextureFilter::Linear)),
        );
        let grain = cc.egui_ctx.load_texture(
            "subtle-grain",
            grain_image(),
            TextureOptions::NEAREST_REPEAT,
        );
        let settings = AppSettings::load();
        let unlock = settings.recent_databases.first().map(|recent| UnlockDraft {
            path: PathBuf::from(&recent.path),
            password: String::new(),
            key_file: None,
            working: false,
            focus_requested: false,
            creating: false,
            confirmation: String::new(),
        });
        let has_recent_database = unlock.is_some();
        let (command_tx, event_rx) = vault::spawn_worker(cc.egui_ctx.clone());
        #[cfg(windows)]
        let (backdrop_checked, backdrop_available, resize_hit_test_installed) =
            if let Some(window) = cc.winit_window() {
                // egui-winit enables a shadow for undecorated windows. In winit
                // that shadow reserves a visible 1 px non-client strip on top.
                window.set_undecorated_shadow(false);
                let backdrop = configure_window_backdrop(window);
                let resize = install_window_resize_hit_test(window);
                // Configure DWM before the first visible frame: otherwise the
                // undecorated window briefly appears rectangular on startup.
                window.set_visible(true);
                suppress_window_border(window);
                (true, backdrop, resize)
            } else {
                (false, false, false)
            };
        #[cfg(not(windows))]
        let (backdrop_checked, backdrop_available, resize_hit_test_installed) =
            (false, false, false);
        Self {
            command_tx,
            event_rx,
            settings,
            snapshot: None,
            database_path: None,
            selected_group: None,
            selected_entry: None,
            #[cfg(windows)]
            pending_auto_type: None,
            #[cfg(windows)]
            auto_type_hotkey: false,
            #[cfg(windows)]
            auto_type_running: false,
            #[cfg(windows)]
            auto_type_result_tx,
            #[cfg(windows)]
            auto_type_result_rx,
            expanded: HashSet::new(),
            search: String::new(),
            search_focus_requested: false,
            unlock,
            clipboard_password: None,
            group_editor: None,
            entry_editor: None,
            sync_editor: None,
            sync_conflict: None,
            show_conflict_secrets: false,
            save_as_sync: None,
            sync_in_flight: false,
            settings_tab: SettingsTab::Overview,
            ftps_test_result: None,
            textures: HashMap::new(),
            logo,
            grain,
            busy: false,
            status: if has_recent_database {
                "Введите пароль последней базы"
            } else {
                "База не открыта"
            }
            .into(),
            error: None,
            open_started: Instant::now(),
            resize_hit_test_installed,
            backdrop_checked,
            backdrop_available,
        }
    }

    fn poll_events(&mut self, ctx: &egui::Context) {
        #[cfg(windows)]
        while let Ok(result) = self.auto_type_result_rx.try_recv() {
            self.auto_type_running = false;
            match result {
                Ok(()) => self.status = "Быстрый ввод выполнен".into(),
                Err(message) => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    self.error = Some(format!("Быстрый ввод: {message}"));
                }
            }
        }
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                Event::Progress(message) => {
                    if matches!(message.as_str(), "Выполняется синхронизация…" | "Проверяю версию базы на сервере…") {
                        self.sync_in_flight = true;
                    }
                    self.status = message;
                    self.busy = true;
                }
                Event::Opened { path, snapshot } => {
                    #[cfg(windows)]
                    {
                        self.pending_auto_type = None;
                    }
                    self.busy = false;
                    self.apply_save_as_sync(&path);
                    self.database_path = Some(path.clone());
                    self.settings.remember_database(&path);
                    let _ = self.settings.save();
                    self.selected_group = Some(snapshot.root_id.clone());
                    self.selected_entry = None;
                    self.expanded.clear();
                    self.expanded.insert(snapshot.root_id.clone());
                    self.expanded.extend(
                        snapshot
                            .groups
                            .iter()
                            .filter(|group| {
                                group.parent_id.as_deref() == Some(snapshot.root_id.as_str())
                                    && !group.is_recycle_bin
                            })
                            .map(|group| group.id.clone()),
                    );
                    self.snapshot = Some(snapshot);
                    self.unlock = None;
                    self.search.clear();
                    self.status.clear();
                    self.error = None;
                }
                Event::Changed(snapshot) => {
                    if self
                        .selected_group
                        .as_ref()
                        .is_some_and(|id| !snapshot.groups.iter().any(|group| &group.id == id))
                    {
                        self.selected_group = snapshot
                            .groups
                            .iter()
                            .find(|group| group.is_recycle_bin)
                            .map(|group| group.id.clone())
                            .or_else(|| Some(snapshot.root_id.clone()));
                    }
                    self.snapshot = Some(snapshot);
                    self.busy = false;
                    if self.snapshot.as_ref().is_some_and(|snapshot| snapshot.modified) {
                        self.status.clear();
                    }
                }
                Event::Password(mut password) => {
                    if password.is_empty() {
                        self.status = "Пароль в записи пустой".into();
                    } else {
                        let mut text = password.to_string();
                        match arboard::Clipboard::new()
                            .and_then(|mut clipboard| clipboard.set_text(text.clone()))
                        {
                            Ok(()) => {
                                self.clipboard_password = Some((Sha256::digest(text.as_bytes()).into(), Instant::now() + Duration::from_secs(60)));
                                ctx.request_repaint_after(Duration::from_secs(60));
                                self.status = "Пароль скопирован на 1 минуту".into();
                            },
                            Err(error) => {
                                self.status =
                                    format!("Не удалось записать пароль в буфер: {error}");
                            }
                        }
                        text.zeroize();
                        password.zeroize();
                    }
                    self.busy = false;
                }
                Event::EntryPassword { id, password } => {
                    if let Some(draft) = self.entry_editor.as_mut() {
                        if draft.id.as_deref() == Some(id.as_str()) {
                            draft.password = password.to_string();
                            draft.password_loading = false;
                        }
                    }
                    #[cfg(windows)]
                    if self
                        .pending_auto_type
                        .as_ref()
                        .is_some_and(|request| request.id == id)
                    {
                        let request = self.pending_auto_type.take().expect("request exists");
                        if password.is_empty() {
                            self.status = "Пароль в записи пустой".into();
                        } else {
                            self.auto_type_running = true;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                            let result_tx = self.auto_type_result_tx.clone();
                            let repaint = ctx.clone();
                            std::thread::spawn(move || {
                                let result = autotype::run(
                                    request.own_window,
                                    request.target_window,
                                    Zeroizing::new(request.username),
                                    password,
                                );
                                if result.is_err() {
                                    repaint
                                        .send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                                }
                                let _ = result_tx.send(result);
                                repaint.request_repaint();
                            });
                        }
                    }
                }
                Event::Saved {
                    elapsed_ms,
                    sync_result,
                    uploaded_sha256,
                    retry_base_sha256,
                    path,
                } => {
                    self.busy = false;
                    self.sync_in_flight = false;
                    if let Some(path) = path {
                        self.apply_save_as_sync(&path);
                        self.database_path = Some(path.clone());
                        self.settings.remember_database(&path);
                        if let Err(error) = self.settings.save() {
                            self.error = Some(format!(
                                "База сохранена; не удалось обновить список недавних баз: {error}"
                            ));
                        }
                    }
                    let current_path = self.database_path.as_deref();
                    if let (Some(result), Some(current_path)) = (sync_result, current_path) {
                        let mut state = self.settings.sync_state_for(current_path).cloned().unwrap_or_default();
                        match result {
                            Ok(()) => {
                                state.last_success = Some(std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs());
                                state.last_uploaded_sha256 = uploaded_sha256;
                                state.last_error = None;
                                self.status = "БД синхронизирована".into();
                            }
                            Err(message) => {
                                if let Some(hash) = retry_base_sha256 {
                                    state.last_uploaded_sha256 = Some(hash);
                                }
                                state.last_error = Some(message.clone());
                                if sync_transfer_retryable(&message) {
                                    self.status = "Работа офлайн · нажмите «Сохранить» для отправки".into();
                                } else if message.contains("Нажмите «Сохранить»") {
                                    self.status = message.clone();
                                } else {
                                    self.status = "База сохранена локально · синхронизация не завершена".into();
                                    if message.starts_with("Разрешение конфликтов отложено.") {
                                        self.status = "Конфликт отложен · обе копии сохранены".into();
                                    } else {
                                        self.error = Some(format!("Синхронизация: {message}"));
                                    }
                                }
                            }
                        }
                        self.settings.set_sync_state_for(current_path, state);
                        let _ = self.settings.save();
                    } else {
                        self.status = format!("Сохранено локально за {:.2} с", elapsed_ms as f64 / 1000.0);
                    }
                    if let Some(snapshot) = self.snapshot.as_mut() {
                        snapshot.modified = false;
                    }
                }
                Event::SyncConflict(conflict) => {
                    self.sync_in_flight = false;
                    self.busy = false;
                    self.status = "Требуется решение по конфликту синхронизации".into();
                    self.show_conflict_secrets = false;
                    self.sync_conflict = Some(conflict);
                    self.sync_editor = None;
                    if let Some(snapshot) = self.snapshot.as_mut() {
                        snapshot.modified = false;
                    }
                }
                Event::MasterPasswordChanged => {
                    self.busy = false;
                    if let Some(draft) = self.sync_editor.as_mut() {
                        draft.master_password.zeroize();
                        draft.master_password_confirm.zeroize();
                    }
                    self.status = "Новый мастер-пароль будет применён при сохранении базы".into();
                    self.error = None;
                    if let Some(snapshot) = self.snapshot.as_mut() {
                        snapshot.modified = true;
                    }
                }
                Event::FtpsTest(result) => {
                    self.busy = false;
                    self.ftps_test_result = Some(result.clone());
                    match result {
                        Ok(()) => self.status = "Подключение FTPS работает".into(),
                        Err(message) => {
                            self.status = "Проверка FTPS не пройдена".into();
                            self.error = Some(format!("Проверка FTPS: {message}"));
                        }
                    }
                }
                Event::Error(message) => {
                    self.save_as_sync = None;
                    #[cfg(windows)]
                    {
                        self.pending_auto_type = None;
                    }
                    self.busy = false;
                    if let Some(dialog) = self.unlock.as_mut() {
                        dialog.working = false;
                    }
                    self.error = Some(message.clone());
                    self.status = "Операция не выполнена".into();
                }
            }
        }
    }

    fn handle_hotkeys(&mut self, ctx: &egui::Context, frame: &eframe::Frame) {
        if self.sync_conflict.is_some() || self.sync_in_flight {
            return;
        }
        #[cfg(not(windows))]
        let _ = frame;
        #[cfg(windows)]
        if std::mem::take(&mut self.auto_type_hotkey) {
            let selected = self.selected_entry.as_ref().and_then(|id| {
                self.snapshot
                    .as_ref()?
                    .entries
                    .iter()
                    .find(|entry| &entry.id == id)
            });
            let own = frame
                .winit_window()
                .and_then(|window| autotype::window_handle(window));
            match (selected, own) {
                (Some(entry), Some(own_window)) => {
                    if let Some(target_window) = autotype::target_window(own_window) {
                        let request = AutoTypeRequest {
                            id: entry.id.clone(),
                            username: entry.username.clone(),
                            own_window,
                            target_window,
                        };
                        if self
                            .command_tx
                            .send(Command::GetEntryPassword {
                                id: request.id.clone(),
                            })
                            .is_ok()
                        {
                            self.pending_auto_type = Some(request);
                            self.status = "Подготавливаю быстрый ввод…".into();
                        } else {
                            self.error = Some("Не удалось получить пароль записи".into());
                        }
                    } else {
                        self.status = "Не найдено другое окно для быстрого ввода".into();
                    }
                }
                _ => self.status = "Выберите запись для быстрого ввода".into(),
            }
        }
        let editing_dialog_open = self.unlock.is_some()
            || self.entry_editor.is_some()
            || self.group_editor.is_some()
            || self.sync_editor.is_some();
        let can_copy_password = self.selected_entry.is_some() && !editing_dialog_open;
        let rename_group = !editing_dialog_open
            && !ctx.egui_wants_keyboard_input()
            && self.selected_group.is_some()
            && ctx.input(|input| input.key_pressed(egui::Key::F2));
        let delete_group = !editing_dialog_open
            && !ctx.egui_wants_keyboard_input()
            && self.selected_group.as_ref().is_some_and(|id| {
                self.snapshot.as_ref().is_some_and(|snapshot| {
                    snapshot.groups.iter().any(|group| {
                        &group.id == id && group.parent_id.is_some() && !group.is_recycle_bin
                    })
                })
            })
            && ctx.input(|input| input.key_pressed(egui::Key::Delete));
        let (copy_password, copy_login, save, focus_search) = ctx.input_mut(|input| {
            let copy_event = input
                .events
                .iter()
                .any(|event| matches!(event, egui::Event::Copy));
            let copy_key = input.key_pressed(egui::Key::C) && input.modifiers.ctrl;
            let copy_password = can_copy_password && (copy_event || copy_key);
            let focus_search = input.key_pressed(egui::Key::K) && input.modifiers.ctrl;
            if focus_search {
                input.consume_key(egui::Modifiers::CTRL, egui::Key::K);
            }
            if copy_password {
                // egui-winit maps Windows Ctrl+C to Event::Copy (not Key::C).
                // Remove that event so TextEdit can't consume it as a text copy.
                input
                    .events
                    .retain(|event| !matches!(event, egui::Event::Copy));
                input.consume_key(egui::Modifiers::CTRL, egui::Key::C);
            }
            (
                copy_password,
                input.key_pressed(egui::Key::B) && input.modifiers.ctrl,
                input.key_pressed(egui::Key::S) && input.modifiers.ctrl,
                focus_search,
            )
        });
        self.search_focus_requested |= focus_search;
        if copy_password && !editing_dialog_open {
            if let Some(id) = self.selected_entry.clone() {
                self.copy_entry_password(id);
            }
        }
        if rename_group {
            if let Some(id) = self.selected_group.clone() {
                self.open_group_editor(Some(id), None);
            }
        }
        if delete_group {
            if let Some(id) = self.selected_group.clone() {
                self.delete_folder(id);
            }
        }
        if !ctx.egui_wants_keyboard_input() {
            if let Some(id) = self.selected_entry.clone() {
                if copy_login {
                    if let Some(entry) = self
                        .snapshot
                        .as_ref()
                        .and_then(|s| s.entries.iter().find(|entry| entry.id == id))
                    {
                        ctx.copy_text(entry.username.clone());
                        self.status = "Логин скопирован".into();
                    }
                }
            }
            if save && self.snapshot.is_some() && !self.busy {
                self.save_database();
            }
        }
    }

    fn folder_in_recycle_bin(&self, id: &str) -> bool {
        let Some(snapshot) = &self.snapshot else { return false };
        let mut current = Some(id);
        for _ in &snapshot.groups {
            let Some(group) = current.and_then(|id| snapshot.groups.iter().find(|group| group.id == id)) else {
                break;
            };
            if group.is_recycle_bin {
                return true;
            }
            current = group.parent_id.as_deref();
        }
        false
    }

    fn delete_folder(&mut self, id: String) {
        if self.busy {
            return;
        }
        let permanent = self.folder_in_recycle_bin(&id);
        if permanent && rfd::MessageDialog::new()
            .set_title("Удалить папку навсегда")
            .set_description("Папка, её подпапки и все записи внутри будут удалены из базы. Восстановить их из корзины будет невозможно.")
            .set_buttons(rfd::MessageButtons::YesNo)
            .set_level(rfd::MessageLevel::Warning)
            .show() != rfd::MessageDialogResult::Yes
        {
            return;
        }
        let (command, status) = if permanent {
            (Command::DeleteRecycledGroup { id }, "Удаляю папку из корзины…")
        } else {
            (Command::MoveGroupToRecycleBin { id }, "Перемещаю папку в корзину…")
        };
        if self.command_tx.send(command).is_ok() {
            self.busy = true;
            self.status = status.into();
        } else {
            self.error = Some("Не удалось запустить удаление папки".into());
        }
    }

    fn sync_request(&self, path: &std::path::Path) -> Option<SyncRequest> {
        let config = self.settings.sync_for(path).filter(|config| config.enabled)?.clone();
        let common_hash = self.settings.sync_state_for(path)
            .and_then(|state| state.last_uploaded_sha256.clone());
        Some(SyncRequest { config, common_hash })
    }

    fn has_unsaved_changes(&self) -> bool {
        self.snapshot.as_ref().is_some_and(|snapshot| snapshot.modified)
    }

    fn apply_save_as_sync(&mut self, path: &std::path::Path) {
        if self.save_as_sync.as_ref().is_some_and(|(target, _)| target == path) {
            if let Some((_, config)) = self.save_as_sync.take() {
                self.settings.set_sync_for(path, config);
            }
        }
    }

    fn save_database(&mut self) {
        if self.busy || self.sync_conflict.is_some() {
            return;
        }
        let sync = self.database_path.as_deref().and_then(|path| self.sync_request(path));
        let _ = self.command_tx.send(Command::Save { sync });
        self.busy = true;
        self.status = "Подготавливаю сохранение…".into();
    }

    fn save_database_as(&mut self) {
        if self.busy || self.snapshot.is_none() {
            return;
        }
        let file_name = self
            .database_path
            .as_ref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .unwrap_or("database.kdbx");
        let Some(mut path) = rfd::FileDialog::new()
            .set_title("Сохранить базу как")
            .add_filter("Базы KeePass", &["kdbx"])
            .set_file_name(file_name)
            .save_file()
        else {
            return;
        };
        if path.extension().is_none() {
            path.set_extension("kdbx");
        }
        let inherited = if self.settings.sync_for(&path).is_none() {
            self.database_path.as_deref().and_then(|source| self.sync_request(source))
        } else {
            None
        };
        let sync = self.sync_request(&path).or_else(|| inherited.as_ref().map(|source| {
            let same_filename = self.database_path.as_ref().is_some_and(|original| original.file_name() == path.file_name());
            SyncRequest {
                config: source.config.clone(),
                common_hash: if same_filename { source.common_hash.clone() } else { None },
            }
        }));
        let inherited_config = inherited.map(|request| (path.clone(), request.config));
        match self.command_tx.send(Command::SaveAs { path, sync }) {
            Ok(()) => {
                self.save_as_sync = inherited_config;
                self.busy = true;
                self.status = "Подготавливаю копию базы…".into();
            }
            Err(_) => self.error = Some("Не удалось запустить сохранение копии базы".into()),
        }
    }

    fn copy_entry_password(&mut self, id: String) {
        match self.command_tx.send(Command::CopyPassword { id }) {
            Ok(()) => {
                self.busy = true;
                self.status = "Копирую пароль…".into();
            }
            Err(_) => {
                self.status = "Не удалось запустить копирование пароля".into();
            }
        }
    }

    fn choose_database(&mut self, path: Option<PathBuf>) {
        let path = path.or_else(|| {
            rfd::FileDialog::new()
                .set_title("Открыть базу KeePass")
                .add_filter("Базы KeePass", &["kdbx", "kdb"])
                .pick_file()
        });
        if let Some(path) = path {
            if self.has_unsaved_changes() && !confirm_discard_changes() {
                return;
            }
            self.error = None;
            self.unlock = Some(UnlockDraft {
                path,
                password: String::new(),
                key_file: None,
                working: false,
                focus_requested: false,
                creating: false,
                confirmation: String::new(),
            });
        }
    }

    fn choose_new_database(&mut self) {
        let Some(path) = rfd::FileDialog::new().set_title("Создать базу KeePass")
            .add_filter("Базы KeePass", &["kdbx"]).set_file_name("Peplos.kdbx").save_file() else { return; };
        if path.exists() {
            self.error = Some("Файл уже существует. Выберите другое имя.".into());
            return;
        }
        self.error = None;
        self.unlock = Some(UnlockDraft { path, password: String::new(), key_file: None,
            working: false, focus_requested: false, creating: true, confirmation: String::new() });
    }

    fn clear_expired_clipboard(&mut self, force: bool) {
        let Some((hash, deadline)) = self.clipboard_password else { return };
        if !force && Instant::now() < deadline { return; }
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            match clipboard.get_text() {
                Ok(value) => {
                    let value = Zeroizing::new(value);
                    if <[u8; 32]>::from(Sha256::digest(value.as_bytes())) == hash
                        && clipboard.clear().is_err() && !force { return; }
                    self.clipboard_password = None;
                }
                Err(_) if force => self.clipboard_password = None,
                Err(_) => {},
            }
        }
    }

    fn submit_unlock(&mut self) {
        let Some(draft) = self.unlock.as_mut() else {
            return;
        };
        if draft.working || (draft.password.is_empty() && (draft.creating || draft.key_file.is_none())) {
            return;
        }
        if draft.creating && draft.password != draft.confirmation {
            self.error = Some("Пароли не совпадают".into());
            return;
        }
        draft.confirmation.zeroize();
        let creating = draft.creating;
        let password = Zeroizing::new(std::mem::take(&mut draft.password));
        let path = draft.path.clone();
        let key_file = draft.key_file.clone();
        draft.working = true;
        let command = if creating { Command::Create { path, password } } else {
            let sync = self.sync_request(&path);
            Command::Unlock { path, password, key_file, sync }
        };
        let _ = self.command_tx.send(command);
        self.busy = true;
        self.open_started = Instant::now();
        self.status = "Подключаюсь к базе…".into();
    }

    fn open_group_editor(&mut self, id: Option<String>, parent_id: Option<String>) {
        let group = id.as_ref().and_then(|id| {
            self.snapshot
                .as_ref()?
                .groups
                .iter()
                .find(|group| &group.id == id)
        });
        self.group_editor = Some(GroupDraft {
            id,
            parent_id: parent_id
                .or_else(|| self.selected_group.clone())
                .unwrap_or_default(),
            title: group.map(|group| group.title.clone()).unwrap_or_default(),
            original_title: group.map(|group| group.title.clone()).unwrap_or_default(),
            icon_id: group.map(|group| group.icon_id).unwrap_or(4),
            icon_id_changed: false,
            icon_png: group.and_then(|group| group.icon_png.clone()),
            icon_changed: false,
        });
    }

    fn open_entry_editor(&mut self, id: Option<String>) {
        let entry = id.as_ref().and_then(|id| {
            self.snapshot
                .as_ref()?
                .entries
                .iter()
                .find(|entry| &entry.id == id)
        });
        let group_id = entry
            .map(|entry| entry.group_id.clone())
            .or_else(|| self.selected_group.clone())
            .unwrap_or_default();
        let password_id = id.clone();
        self.entry_editor = Some(EntryDraft {
            id,
            group_id,
            title: entry.map(|entry| entry.title.clone()).unwrap_or_default(),
            username: entry
                .map(|entry| entry.username.clone())
                .unwrap_or_default(),
            password: String::new(),
            show_password: false,
            password_loading: password_id.is_some(),
            url: entry.map(|entry| entry.url.clone()).unwrap_or_default(),
            notes: entry.map(|entry| entry.notes.clone()).unwrap_or_default(),
            tags_input: entry.map(|entry| entry.tags.join(", ")).unwrap_or_default(),
            creation_time: entry.and_then(|entry| entry.creation_time),
            last_modification_time: entry.and_then(|entry| entry.last_modification_time),
            usage_count: entry.map(|entry| entry.usage_count).unwrap_or(0),
            clear_password: false,
            icon_png: entry
                .filter(|entry| entry.has_custom_icon)
                .and_then(|entry| entry.icon_png.clone()),
            icon_changed: false,
        });
        if let Some(id) = password_id {
            let _ = self.command_tx.send(Command::GetEntryPassword { id });
        }
    }

    fn open_sync_editor(&mut self) {
        let Some(path) = self.database_path.as_deref() else {
            self.error = Some("Сначала откройте базу данных".into());
            return;
        };
        let saved = self.settings.sync_for(path);
        self.settings_tab = SettingsTab::Overview;
        self.ftps_test_result = None;
        self.sync_editor = Some(SyncDraft {
            enabled: saved.map(|sync| sync.enabled).unwrap_or(true),
            host: saved.map(|sync| sync.host.clone()).unwrap_or_default(),
            port: saved
                .map(|sync| sync.port.to_string())
                .unwrap_or_else(|| "21".into()),
            username: saved.map(|sync| sync.username.clone()).unwrap_or_default(),
            remote_directory: saved
                .map(|sync| sync.remote_directory.clone())
                .unwrap_or_default(),
            password: String::new(),
            already_has_password: saved.is_some_and(|sync| !sync.password_dpapi.is_empty()),
            master_password: String::new(),
            master_password_confirm: String::new(),
        });
    }

    fn show_header(&mut self, parent: &mut egui::Ui) {
        let ctx = parent.ctx().clone();
        let database_filename = self
            .database_path
            .as_ref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .map(str::to_owned);
        parent.add_space(5.0);
        parent.horizontal(|ui| {
            ui.add_space(12.0);
            ui.image((self.logo.id(), Vec2::new(112.0, 29.0)));
            if let Some(filename) = database_filename.as_deref() {
                ui.add(
                    egui::Label::new(RichText::new(filename).size(12.0).color(MUTED)).truncate(),
                )
                .on_hover_text(filename);
            }
            let drag_rect = ui.available_rect_before_wrap();
            let drag = ui.interact(
                drag_rect,
                egui::Id::unique(egui::IdSalt::new("window-drag")),
                egui::Sense::click_and_drag(),
            );
            if drag.drag_started() {
                ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                window_controls(ui);
            });
        });
        parent.add_space(5.0);
    }

    fn show_welcome(&mut self, ui: &mut egui::Ui) {
        let recents = self.settings.recent_databases.clone();
        let mut open_path = None;
        let mut create = false;
        let rect = ui.max_rect();
        ui.allocate_ui_with_layout(rect.size(), Layout::top_down(Align::Min), |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.image((self.logo.id(), Vec2::new(185.0, 48.0)));
                ui.add_space(9.0);
                ui.label(
                    RichText::new("Ваша база — в одном быстром месте")
                        .size(23.0)
                        .strong()
                        .color(WHITE),
                );
                ui.add_space(5.0);
                ui.label(
                    RichText::new("Откройте базу KeePass или продолжите с недавней")
                        .size(13.0)
                        .color(MUTED),
                );
                ui.add_space(16.0);
                if filled_button(ui, "Открыть базу KeePass", [172.0, 34.0], ACCENT, WHITE).clicked()
                {
                    open_path = Some(None);
                }
                ui.add_space(8.0);
                if filled_button(ui, "Создать новую базу", [172.0, 34.0], SURFACE_RAISED, WHITE).clicked() { create = true; }
            });
            if !recents.is_empty() {
                ui.add_space(18.0);
                let available_width = ui.available_width();
                let content_width = (available_width - 48.0).min(1040.0).max(0.0);
                let side_padding = ((available_width - content_width) * 0.5).max(24.0);
                let content_height = ui.available_height();
                ui.horizontal(|ui| {
                    ui.add_space(side_padding);
                    ui.allocate_ui_with_layout(
                        Vec2::new(content_width, content_height),
                        Layout::top_down(Align::Min),
                        |ui| {
                            ui.label(
                                RichText::new("НЕДАВНИЕ БАЗЫ")
                                    .size(10.0)
                                    .strong()
                                    .color(SECONDARY),
                            );
                            ui.add_space(5.0);
                            egui::ScrollArea::vertical()
                                .id_salt("recent-databases-list")
                                .auto_shrink([false, false])
                                .max_height(ui.available_height())
                                .show(ui, |ui| {
                                    for recent in recents.iter().take(8) {
                                        let mut clicked = false;
                                        Frame::new()
                                            .fill(SURFACE_RAISED)
                                            .corner_radius(CornerRadius::same(8))
                                            .stroke(Stroke::new(1.0, BORDER))
                                            .inner_margin(Margin::symmetric(12, 8))
                                            .show(ui, |ui| {
                                                ui.set_width(ui.available_width());
                                                ui.horizontal(|ui| {
                                                    ui.label(icon_text(0xf1c0, 19.0, GOLD));
                                                    ui.vertical(|ui| {
                                                        ui.set_max_width(
                                                            (ui.available_width() - 8.0).max(80.0),
                                                        );
                                                        ui.label(
                                                            RichText::new(&recent.name)
                                                                .size(12.5)
                                                                .strong()
                                                                .color(WHITE),
                                                        );
                                                        ui.add(
                                                            egui::Label::new(
                                                                RichText::new(&recent.path)
                                                                    .size(10.0)
                                                                    .color(MUTED),
                                                            )
                                                            .truncate(),
                                                        );
                                                    });
                                                    ui.with_layout(
                                                        Layout::right_to_left(Align::Center),
                                                        |ui| {
                                                            if filled_button(
                                                                ui,
                                                                "Открыть",
                                                                [92.0, 31.0],
                                                                ACCENT,
                                                                WHITE,
                                                            )
                                                            .clicked()
                                                            {
                                                                clicked = true;
                                                            }
                                                        },
                                                    );
                                                });
                                            });
                                        if clicked {
                                            open_path = Some(Some(PathBuf::from(&recent.path)));
                                        }
                                        ui.add_space(5.0);
                                    }
                                });
                        },
                    );
                });
            }
        });
        if let Some(path) = open_path {
            self.choose_database(path);
        }
        if create { self.choose_new_database(); }
    }

    fn show_database(&mut self, parent: &mut egui::Ui) {
        let Some(snapshot) = self.snapshot.as_ref() else {
            return;
        };
        let root = snapshot.root_id.clone();
        let groups: HashMap<String, GroupInfo> = snapshot
            .groups
            .iter()
            .cloned()
            .map(|group| (group.id.clone(), group))
            .collect();
        let available = parent.available_size_before_wrap();
        let panel_height = available.y.max(120.0);
        let footer_y = parent.available_rect_before_wrap().top() + panel_height - 24.0;
        let sidebar_width = (available.x * 0.235).clamp(230.0, 330.0);
        parent.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.allocate_ui_with_layout(
                Vec2::new(sidebar_width, panel_height),
                Layout::top_down(Align::Min),
                |ui| {
                    let panel_rect = ui.max_rect();
                    let corner = if ui.ctx().input(|input| input.viewport().maximized.unwrap_or(false)) {
                        0
                    } else {
                        WINDOW_RADIUS
                    };
                    ui.painter().rect_filled(
                        panel_rect,
                        CornerRadius { nw: corner, ne: 0, sw: corner, se: 0 },
                        Color32::from_rgba_unmultiplied(0, 0, 0, 61),
                    );
                    paint_panel_grain(ui.painter(), &self.grain, panel_rect, true, corner);
                    let inner_rect = panel_rect.shrink2(Vec2::new(15.0, 17.0));
                    ui.scope_builder(
                        egui::UiBuilder::new()
                            .id_salt("folder-panel-content")
                            .max_rect(inner_rect)
                            .layout(Layout::top_down(Align::Min)),
                        |ui| {
                            ui.horizontal(|ui| {
                                ui.image((self.logo.id(), Vec2::new(131.0, 34.0)));
                            });
                            ui.add_space(8.0);
                            egui::ScrollArea::vertical()
                                .id_salt("folder-tree")
                                .auto_shrink([false, false])
                                // Reserve room for both action rows and the footer so the
                                // folder tree scrolls inside the panel instead of pushing
                                // those controls past its bottom edge.
                                .max_height((ui.available_height() - 150.0).max(72.0))
                                .show(ui, |ui| {
                                    ui.spacing_mut().item_spacing.y = 3.0;
                                    self.group_branch(ui, &root, &groups)
                                });
                            ui.add_space(5.0);
                            let create_width = ((ui.available_width() - 6.0) / 2.0).max(60.0);
                            egui::Grid::new("sidebar-create-actions")
                                .num_columns(2)
                                .spacing(Vec2::new(6.0, 4.0))
                                .show(ui, |ui| {
                                    if sidebar_create_action(ui, create_width, "Папка", false)
                                        .clicked()
                                    {
                                        let parent = self
                                            .selected_group
                                            .clone()
                                            .unwrap_or_else(|| root.clone());
                                        self.open_group_editor(None, Some(parent));
                                    }
                                    if sidebar_create_action(ui, create_width, "Ключ", true)
                                        .clicked()
                                    {
                                        if self.selected_group.is_none() {
                                            self.selected_group = Some(root.clone());
                                        }
                                        self.open_entry_editor(None);
                                    }
                                    ui.end_row();
                                });
                            ui.add_space(3.0);
                            ui.separator();
                            let action_width = ((ui.available_width() - 12.0) / 4.0).max(32.0);
                            egui::Grid::new("sidebar-actions")
                                .num_columns(4)
                                .spacing(Vec2::new(4.0, 2.0))
                                .show(ui, |ui| {
                                    if sidebar_icon_action(ui, action_width, 0xf07c, false).on_hover_text("Открыть базу").clicked() { self.choose_database(None); }
                                    if sidebar_icon_action(ui, action_width, 0xf0c7, self.snapshot.as_ref().is_some_and(|s| s.modified)).on_hover_text("Сохранить").clicked() { self.save_database(); }
                                    if sidebar_icon_action(ui, action_width, 0xf0c5, false).on_hover_text("Сохранить как").clicked() { self.save_database_as(); }
                                    if sidebar_icon_action(ui, action_width, 0xf013, false).on_hover_text("Настройки базы").clicked() { self.open_sync_editor(); }
                                    ui.end_row();
                                });
                            ui.painter().text(
                                egui::pos2(inner_rect.left(), footer_y),
                                Align2::LEFT_CENTER,
                                format!("{} папок · {} записей", groups.len(),
                                    self.snapshot.as_ref().map(|s| s.entries.len()).unwrap_or(0)),
                                FontId::proportional(12.0),
                                MUTED,
                            );
                        },
                    );
                },
            );
            let main_width = ui.available_width().max(120.0);
            ui.allocate_ui_with_layout(
                Vec2::new(main_width, panel_height),
                Layout::top_down(Align::Min),
                |ui| {
                    let panel_rect = ui.max_rect();
                    let corner = if ui.ctx().input(|input| input.viewport().maximized.unwrap_or(false)) {
                        0
                    } else {
                        WINDOW_RADIUS
                    };
                    paint_panel_grain(ui.painter(), &self.grain, panel_rect, false, corner);
                    let drag_rect = egui::Rect::from_min_size(
                        panel_rect.left_top(),
                        Vec2::new(panel_rect.width(), 14.0),
                    );
                    let drag = ui.interact(
                        drag_rect,
                        egui::Id::unique("database-window-drag"),
                        egui::Sense::click_and_drag(),
                    );
                    if drag.drag_started() {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
                    }
                    Frame::new()
                        .fill(Color32::TRANSPARENT)
                        .corner_radius(CornerRadius::same(16))
                        .inner_margin(Margin::symmetric(24, 16))
                        .show(ui, |ui| {
                            let mut entries: Vec<EntryInfo> = self
                                .snapshot
                                .as_ref()
                                .map(|snapshot| {
                                    snapshot
                                        .entries
                                        .iter()
                                        .filter(|entry| {
                                            if self.search.trim().is_empty() {
                                                Some(entry.group_id.as_str())
                                                    == self.selected_group.as_deref()
                                            } else {
                                                let query = self.search.trim().to_lowercase();
                                                if let Some(tag) = query.strip_prefix('#') {
                                                    entry.tags.iter().any(|value| value.to_lowercase().contains(tag))
                                                } else {
                                                entry.title.to_lowercase().contains(&query)
                                                    || entry
                                                        .username
                                                        .to_lowercase()
                                                        .contains(&query)
                                                    || entry.url.to_lowercase().contains(&query)
                                                    || entry.notes.to_lowercase().contains(&query)
                                                    || entry.tags.iter().any(|value| value.to_lowercase().contains(&query))
                                                }
                                            }
                                        })
                                        .cloned()
                                        .collect()
                                })
                                .unwrap_or_default();
                            entries.sort_by(|a, b| {
                                a.title
                                    .to_lowercase()
                                    .cmp(&b.title.to_lowercase())
                                    .then_with(|| {
                                        a.username
                                            .to_lowercase()
                                            .cmp(&b.username.to_lowercase())
                                    })
                            });
                            ui.horizontal(|ui| {
                                let header_width = ui.available_width();
                                let breadcrumb_width = (header_width * 0.46)
                                    .min((header_width - 310.0).max(100.0));
                                self.show_breadcrumbs(ui, &groups, breadcrumb_width);
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    window_controls(ui);
                                    let width = (ui.available_width() - 12.0).max(120.0);
                                    Frame::new()
                                        .fill(Color32::from_rgba_unmultiplied(13, 14, 19, 115))
                                        .corner_radius(CornerRadius::same(22))
                                        .inner_margin(Margin::symmetric(12, 0))
                                        .show(ui, |ui| {
                                            let search = ui.add_sized(
                                                [(width - 24.0).max(96.0), 44.0],
                                                TextEdit::singleline(&mut self.search)
                                                    .id_salt("vault-search")
                                                    .frame(Frame::NONE)
                                                    .hint_text("Поиск по названию, логину, адресу или #тегу")
                                                    .align(Align2::LEFT_CENTER)
                                                    .margin(Margin::ZERO),
                                            );
                                            if self.search_focus_requested {
                                                search.request_focus();
                                                self.search_focus_requested = false;
                                            }
                                        });
                                    if !self.search.is_empty()
                                        && filled_icon_button(
                                            ui,
                                            0xf00d,
                                            [34.0, 36.0],
                                            SURFACE_RAISED,
                                            WHITE,
                                        )
                                        .clicked()
                                    {
                                        self.search.clear();
                                    }
                                });
                            });
                            ui.add_space(6.0);
                            if entries.is_empty() {
                                            ui.add_space(24.0);
                                ui.vertical_centered(|ui| {
                                    ui.label(
                                        RichText::new(if self.search.is_empty() {
                                            "Здесь пока нет записей"
                                        } else {
                                            "Ничего не найдено"
                                        })
                                        .size(18.0)
                                        .strong()
                                        .color(WHITE),
                                    );
                                    ui.add_space(5.0);
                                    ui.label(
                                        RichText::new(if self.search.is_empty() {
                                            "Создайте первую запись или выберите другую папку"
                                        } else {
                                            "Попробуйте изменить запрос или очистите его кнопкой справа"
                                        })
                                        .size(13.0)
                                        .color(MUTED),
                                    );
                                    ui.add_space(16.0);
                                    if action_button(ui, "Новая запись", true).clicked()
                                    {
                                        self.open_entry_editor(None);
                                    }
                                });
                            } else {
                                egui::ScrollArea::vertical()
                                    .id_salt("entry-list")
                                    .auto_shrink([false, false])
                                    .max_height((ui.available_height() - 34.0).max(0.0))
                                    .show(ui, |ui| {
                                        ui.spacing_mut().item_spacing.y = 2.0;
                                        for entry in entries {
                                            self.entry_card(ui, &entry);
                                        }
                                    });
                            }
                        let footer = egui::Rect::from_min_max(
                            egui::pos2(ui.max_rect().left(), footer_y - 12.0),
                            egui::pos2(ui.max_rect().right(), footer_y + 12.0),
                        );
                        ui.scope_builder(egui::UiBuilder::new()
                            .id_salt("database-footer")
                            .max_rect(footer)
                            .layout(Layout::left_to_right(Align::Center)), |ui| {
                            ui.set_min_height(24.0);
                            if self.busy {
                                ui.spinner();
                            }
                            if !self.status.is_empty() {
                                ui.add(egui::Label::new(RichText::new(&self.status).size(12.0).color(if self.busy {
                                    SECONDARY
                                } else {
                                    MUTED
                                })).truncate()).on_hover_text(&self.status);
                            }
                            if self.snapshot.as_ref().is_some_and(|s| s.modified) {
                                ui.label(RichText::new("Несохранённые изменения").size(12.0).color(GOLD));
                            }
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(
                                    RichText::new("Ctrl+V ввод   ·   Ctrl+C пароль   ·   Ctrl+B логин")
                                        .size(12.0)
                                        .color(MUTED),
                                );
                            });
                        });
                        });
                },
            );
        });
    }

    fn breadcrumb_segments(&self, groups: &HashMap<String, GroupInfo>) -> Vec<BreadcrumbSegment> {
        let database_title = self
            .database_path
            .as_ref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .unwrap_or("База данных")
            .to_owned();
        let root_id = self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.root_id.clone());
        let mut segments = vec![BreadcrumbSegment {
            title: database_title,
            glyph: 0xf1c0,
            icon_png: None,
            group_id: root_id.clone(),
        }];

        let selected_entry = self.snapshot.as_ref().and_then(|snapshot| {
            self.selected_entry
                .as_ref()
                .and_then(|id| snapshot.entries.iter().find(|entry| &entry.id == id))
        });
        let mut current_group = selected_entry
            .map(|entry| entry.group_id.clone())
            .or_else(|| self.selected_group.clone());
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        while let Some(id) = current_group {
            if root_id.as_deref() == Some(id.as_str()) || !seen.insert(id.clone()) {
                break;
            }
            let Some(group) = groups.get(&id) else {
                break;
            };
            chain.push(BreadcrumbSegment {
                title: group.title.clone(),
                glyph: if group.is_recycle_bin {
                    0xf1f8
                } else {
                    standard_icon_glyph(group.icon_id)
                },
                icon_png: group.icon_png.clone(),
                group_id: Some(group.id.clone()),
            });
            current_group = group.parent_id.clone();
        }
        segments.extend(chain.into_iter().rev());

        if let Some(entry) = selected_entry {
            segments.push(BreadcrumbSegment {
                title: entry.title.clone(),
                glyph: standard_icon_glyph(entry.icon_id),
                icon_png: entry.icon_png.clone(),
                group_id: None,
            });
        }
        segments
    }

    fn show_breadcrumbs(
        &mut self,
        ui: &mut egui::Ui,
        groups: &HashMap<String, GroupInfo>,
        width: f32,
    ) {
        let segments = self.breadcrumb_segments(groups);
        let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 44.0), egui::Sense::hover());
        let painter = ui.painter().with_clip_rect(rect);
        let font = FontId::new(13.0, FontFamily::Proportional);
        let icon_width = 22.0;
        let separator_width = 15.0;
        let text_gap = 5.0;
        let fixed_width = segments.len() as f32 * icon_width
            + segments.len().saturating_sub(1) as f32 * separator_width;
        let mut titles: Vec<String> = segments
            .iter()
            .map(|segment| segment.title.clone())
            .collect();
        let mut title_widths: Vec<f32> = titles
            .iter()
            .map(|title| {
                painter
                    .layout_no_wrap(title.clone(), font.clone(), WHITE)
                    .size()
                    .x
            })
            .collect();
        let mut total_width = fixed_width
            + title_widths
                .iter()
                .map(|width| text_gap + width)
                .sum::<f32>();

        // Keep every icon and collapse labels from the database towards the key.
        for index in 0..segments.len().saturating_sub(1) {
            if total_width <= rect.width() {
                break;
            }
            total_width -= text_gap + title_widths[index];
            title_widths[index] = 0.0;
            titles[index].clear();
        }
        if total_width > rect.width() {
            let last = segments.len() - 1;
            let available = (rect.width() - (total_width - title_widths[last])).max(0.0);
            if available < 10.0 {
                total_width -= text_gap + title_widths[last];
                titles[last].clear();
                title_widths[last] = 0.0;
            } else {
                titles[last] = ellipsize_text(&painter, &titles[last], &font, WHITE, available);
                let shortened_width = painter
                    .layout_no_wrap(titles[last].clone(), font.clone(), WHITE)
                    .size()
                    .x;
                total_width -= title_widths[last] - shortened_width;
                title_widths[last] = shortened_width;
            }
        }

        let mut x = if total_width > rect.width() {
            rect.right() - total_width
        } else {
            rect.left()
        };
        let mut clicked_group = None;
        for (index, segment) in segments.iter().enumerate() {
            if index > 0 {
                painter.text(
                    egui::pos2(x + separator_width * 0.5, rect.center().y),
                    Align2::CENTER_CENTER,
                    "/",
                    FontId::new(14.0, FontFamily::Proportional),
                    MUTED,
                );
                x += separator_width;
            }
            let segment_start = x;
            let center = egui::pos2(x + icon_width * 0.5, rect.center().y);
            painter.circle_filled(
                center,
                10.0,
                if index + 1 == segments.len() {
                    ACCENT
                } else {
                    Color32::from_rgba_unmultiplied(255, 255, 255, 20)
                },
            );
            if let Some(texture) = segment
                .icon_png
                .as_deref()
                .and_then(|bytes| custom_icon_texture(ui, &mut self.textures, bytes))
            {
                painter.image(
                    texture,
                    egui::Rect::from_center_size(center, Vec2::splat(13.0)),
                    egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
                    WHITE,
                );
            } else if segment.glyph == 0xf1c0 {
                paint_database_symbol(&painter, center, 14.0, WHITE);
            } else if segment.glyph == 0xf084 {
                paint_key_symbol(&painter, center, 18.0, WHITE);
            } else {
                painter.text(
                    center,
                    Align2::CENTER_CENTER,
                    char::from_u32(segment.glyph).unwrap_or('\u{f07b}'),
                    FontId::new(11.0, FontFamily::Name("Medeo Icons".into())),
                    WHITE,
                );
            }
            x += icon_width;
            if !titles[index].is_empty() {
                x += text_gap;
                painter.text(
                    egui::pos2(x, rect.center().y),
                    Align2::LEFT_CENTER,
                    &titles[index],
                    font.clone(),
                    if index + 1 == segments.len() {
                        WHITE
                    } else {
                        SECONDARY
                    },
                );
                x += title_widths[index];
            }
            let hit_rect = egui::Rect::from_min_max(
                egui::pos2(segment_start, rect.top()),
                egui::pos2(x, rect.bottom()),
            );
            let response = ui.interact(
                hit_rect,
                ui.scope_id().with(("breadcrumb", index)),
                egui::Sense::click(),
            );
            if response.clicked() {
                clicked_group = segment.group_id.clone();
            }
            response.on_hover_text(&segment.title);
        }
        if let Some(group_id) = clicked_group {
            self.selected_group = Some(group_id);
            self.selected_entry = None;
            self.search.clear();
        }
    }

    fn group_branch(&mut self, ui: &mut egui::Ui, id: &str, groups: &HashMap<String, GroupInfo>) {
        let Some(group) = groups.get(id).cloned() else {
            return;
        };
        let is_root = group.parent_id.is_none();
        let is_expanded = is_root || self.expanded.contains(id);
        let is_selected = self.selected_group.as_deref() == Some(id);
        let has_children = !group.child_groups.is_empty();
        let show_arrow = has_children && !is_root;
        let row_width = ui.available_width();
        let (rect, response) =
            ui.allocate_exact_size(Vec2::new(row_width, 42.0), egui::Sense::click());
        let hovered = response.hovered();
        let center = egui::pos2(rect.left() + 20.0, rect.center().y);
        paint_icon_badge(
            ui,
            egui::Rect::from_center_size(center, Vec2::splat(32.0)),
            group.icon_png.as_deref(),
            if group.is_recycle_bin {
                0xf1f8
            } else if is_root {
                0xf1c0
            } else {
                standard_icon_glyph(group.icon_id)
            },
            &mut self.textures,
            is_selected || hovered,
        );

        let arrow_width = if show_arrow { 28.0 } else { 8.0 };
        let count_text = if group.entry_count > 0 {
            group.entry_count.to_string()
        } else {
            String::new()
        };
        let count_right = rect.right() - arrow_width - 4.0;
        let count_left = count_right - 36.0;
        let title_right = if count_text.is_empty() {
            count_right
        } else {
            count_left
        };
        let title_clip = egui::Rect::from_min_max(
            egui::pos2(rect.left() + 46.0, rect.top()),
            egui::pos2(title_right - 5.0, rect.bottom()),
        );
        let highlighted = is_selected || hovered;
        let text_color = if highlighted { WHITE } else { SECONDARY };
        let painter = ui.painter().with_clip_rect(title_clip);
        let title_pos = egui::pos2(rect.left() + 46.0, rect.center().y);
        let title_font = FontId::new(13.0, FontFamily::Proportional);
        let title = ellipsize_text(
            &painter,
            &group.title,
            &title_font,
            text_color,
            title_clip.width(),
        );
        painter.text(
            title_pos,
            Align2::LEFT_CENTER,
            &title,
            title_font.clone(),
            text_color,
        );
        if highlighted {
            painter.text(
                title_pos + Vec2::new(0.55, 0.0),
                Align2::LEFT_CENTER,
                &title,
                title_font,
                text_color,
            );
        }
        if !count_text.is_empty() {
            ui.painter().text(
                egui::pos2(count_right, rect.center().y),
                Align2::RIGHT_CENTER,
                count_text,
                FontId::new(12.0, FontFamily::Proportional),
                if highlighted {
                    Color32::from_rgb(224, 213, 195)
                } else {
                    MUTED
                },
            );
        }
        if show_arrow {
            let arrow_center = egui::pos2(rect.right() - 12.0, rect.center().y);
            let points = if is_expanded {
                [
                    arrow_center + Vec2::new(-4.0, -2.0),
                    arrow_center + Vec2::new(0.0, 2.0),
                    arrow_center + Vec2::new(4.0, -2.0),
                ]
            } else {
                [
                    arrow_center + Vec2::new(-2.0, -4.0),
                    arrow_center + Vec2::new(2.0, 0.0),
                    arrow_center + Vec2::new(-2.0, 4.0),
                ]
            };
            let stroke = Stroke::new(1.6, if highlighted { WHITE } else { SECONDARY });
            ui.painter().line_segment([points[0], points[1]], stroke);
            ui.painter().line_segment([points[1], points[2]], stroke);
        }
        if response.clicked() {
            let clicked_on_arrow = show_arrow
                && ui.ctx().input(|input| {
                    input
                        .pointer
                        .interact_pos()
                        .is_some_and(|position| position.x >= rect.right() - arrow_width)
                });
            if clicked_on_arrow {
                if is_expanded {
                    self.expanded.remove(id);
                } else {
                    self.expanded.insert(id.to_owned());
                }
            } else {
                self.selected_group = Some(group.id.clone());
                self.selected_entry = None;
                self.search.clear();
            }
        }
        response.context_menu(|ui| {
            ui.spacing_mut().button_padding = Vec2::new(14.0, 7.0);
            let visuals = &mut ui.style_mut().visuals;
            visuals.widgets.inactive.corner_radius = CornerRadius::same(5);
            visuals.widgets.hovered.corner_radius = CornerRadius::same(5);
            visuals.widgets.active.corner_radius = CornerRadius::same(5);
            visuals.widgets.open.corner_radius = CornerRadius::same(5);
            if ui.button("Редактировать папку  ·  F2").clicked() {
                self.open_group_editor(Some(group.id.clone()), None);
                ui.close();
            }
            if ui.button("Новая подпапка").clicked() {
                self.open_group_editor(None, Some(group.id.clone()));
                ui.close();
            }
            if ui.button("Новая запись здесь").clicked() {
                self.selected_group = Some(group.id.clone());
                self.open_entry_editor(None);
                ui.close();
            }
            let duplicate_bin = !group.is_recycle_bin
                && group.parent_id.as_deref() == self.snapshot.as_ref().map(|db| db.root_id.as_str())
                && !is_root
                && vault::is_recycle_bin_name(&group.title)
                && groups.values().any(|other| {
                    other.is_recycle_bin && other.parent_id == group.parent_id
                        && vault::is_recycle_bin_name(&other.title)
                });
            if duplicate_bin && ui.add_enabled(!self.busy, egui::Button::new("Объединить корзины здесь")).clicked() {
                ui.close();
                let confirmed = rfd::MessageDialog::new()
                    .set_title("Объединить корзины")
                    .set_description("Перенести записи и подпапки из активной корзины в выбранную папку? Выбранная папка станет корзиной, а опустевшая папка будет убрана.")
                    .set_buttons(rfd::MessageButtons::YesNo)
                    .show() == rfd::MessageDialogResult::Yes;
                if confirmed {
                    if self.command_tx.send(Command::ConsolidateRecycleBin {
                        destination: group.id.clone(),
                    }).is_ok() {
                        self.selected_group = Some(group.id.clone());
                        self.selected_entry = None;
                        self.busy = true;
                        self.status = "Объединяю корзины…".into();
                    } else {
                        self.error = Some("Не удалось запустить объединение корзин".into());
                    }
                }
            }
            if !is_root && !group.is_recycle_bin {
                ui.separator();
                let label = if self.folder_in_recycle_bin(&group.id) {
                    "Удалить навсегда  ·  Del"
                } else {
                    "В корзину  ·  Del"
                };
                if ui.add_enabled(!self.busy, egui::Button::new(label)).clicked() {
                    self.delete_folder(group.id.clone());
                    ui.close();
                }
            }
        });
        if is_expanded {
            for child in group.child_groups {
                self.group_branch(ui, &child, groups);
            }
            if !is_root && has_children {
                let (separator, _) = ui.allocate_exact_size(
                    Vec2::new(ui.available_width(), 18.0),
                    egui::Sense::hover(),
                );
                let pixels_per_point = ui.ctx().pixels_per_point();
                let top = (separator.center().y * pixels_per_point).floor() / pixels_per_point;
                let bottom = top + 1.0 / pixels_per_point;
                let left = separator.left() + 8.0;
                let middle = separator.center().x;
                let right = separator.right() - 8.0;
                let mut mesh = egui::Mesh::default();
                for (x, color) in [
                    (left, Color32::TRANSPARENT),
                    (middle, ACCENT),
                    (right, Color32::TRANSPARENT),
                ] {
                    mesh.colored_vertex(egui::pos2(x, top), color);
                    mesh.colored_vertex(egui::pos2(x, bottom), color);
                }
                mesh.add_triangle(0, 1, 2);
                mesh.add_triangle(1, 3, 2);
                mesh.add_triangle(2, 3, 4);
                mesh.add_triangle(3, 5, 4);
                ui.painter().add(mesh);
            }
        }
    }

    fn entry_card(&mut self, ui: &mut egui::Ui, entry: &EntryInfo) {
        let selected = self.selected_entry.as_deref() == Some(entry.id.as_str());
        let dialog_open = self.unlock.is_some()
            || self.group_editor.is_some()
            || self.entry_editor.is_some()
            || self.sync_editor.is_some();
        // Keep the edit action clear of the overlay scrollbar on the right.
        let row_width = (ui.available_width() - 4.0).max(120.0);
        let action_width = 3.0 * 24.0 + 2.0 * ui.spacing().item_spacing.x + 12.0;
        let text_width = (row_width - 42.0 - action_width - 8.0).max(120.0);
        let (column_widths, column_gap) = entry_column_widths(text_width);
        let row_height = 38.0;
        let (row_rect, row_response) =
            ui.allocate_exact_size(Vec2::new(row_width, row_height), egui::Sense::click());
        let hovered = !dialog_open
            && ui.ctx().input(|input| {
                input
                    .pointer
                    .hover_pos()
                    .is_some_and(|pos| row_rect.contains(pos) && ui.clip_rect().contains(pos))
            });
        if selected || hovered {
            ui.painter().rect_filled(
                row_rect.shrink2(Vec2::new(0.0, 1.0)),
                CornerRadius::same(18),
                if selected {
                    Color32::from_rgba_unmultiplied(135, 100, 70, 55)
                } else {
                    Color32::from_rgba_unmultiplied(235, 225, 210, 22)
                },
            );
        }
        ui.scope_builder(
            egui::UiBuilder::new()
                .id_salt(("entry-row", &entry.id))
                .max_rect(row_rect)
                .layout(Layout::left_to_right(Align::Center)),
            |ui| {
                ui.add_space(4.0);
                let badge_rect = ui
                    .allocate_exact_size(Vec2::splat(26.0), egui::Sense::hover())
                    .0;
                paint_icon_badge(
                    ui,
                    badge_rect,
                    entry.icon_png.as_deref(),
                    standard_icon_glyph(entry.icon_id),
                    &mut self.textures,
                    selected || hovered,
                );
                ui.add_space(8.0);
                let (text_rect, _) =
                    ui.allocate_exact_size(Vec2::new(text_width, row_height), egui::Sense::click());
                let values = [
                    if entry.title.is_empty() {
                        "Без названия"
                    } else {
                        entry.title.as_str()
                    },
                    entry.username.as_str(),
                    entry.url.as_str(),
                    entry.notes.as_str(),
                ];
                let colors = [WHITE, SECONDARY, GOLD, MUTED];
                let mut x = text_rect.left();
                for ((value, width), color) in values.iter().zip(column_widths).zip(colors) {
                    let value = single_line(value);
                    if !value.is_empty() {
                        ui.painter()
                            .with_clip_rect(egui::Rect::from_min_size(
                                egui::pos2(x, text_rect.top()),
                                Vec2::new(width, text_rect.height()),
                            ))
                            .text(
                                egui::pos2(x, text_rect.center().y),
                                Align2::LEFT_CENTER,
                                value,
                                FontId::new(11.5, FontFamily::Proportional),
                                color,
                            );
                    }
                    x += width + column_gap;
                }
                let text_click = ui.interact(
                    text_rect,
                    ui.scope_id().with(("entry-row-text", &entry.id)),
                    egui::Sense::click(),
                );
                if !dialog_open && text_click.double_clicked() {
                    self.selected_entry = Some(entry.id.clone());
                    self.open_entry_editor(Some(entry.id.clone()));
                } else if !dialog_open && (text_click.clicked() || row_response.clicked()) {
                    self.selected_entry = Some(entry.id.clone());
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.add_space(12.0);
                    let edit =
                        icon_action_with_enabled(ui, 0xf044, 16.0, 26.0, SECONDARY, !dialog_open);
                    if !dialog_open
                        && edit
                            .on_hover_text("Редактировать запись и значок")
                            .clicked()
                    {
                        self.selected_entry = Some(entry.id.clone());
                        self.open_entry_editor(Some(entry.id.clone()));
                    }
                    let copy_password =
                        icon_action_with_enabled(ui, 0xf0c5, 16.0, 26.0, SECONDARY, !dialog_open);
                    if !dialog_open
                        && copy_password
                            .on_hover_text("Скопировать пароль · Ctrl+C")
                            .clicked()
                    {
                        self.selected_entry = Some(entry.id.clone());
                        self.copy_entry_password(entry.id.clone());
                    }
                    let copy_login =
                        icon_action_with_enabled(ui, 0xf007, 16.0, 26.0, SECONDARY, !dialog_open);
                    if !dialog_open
                        && copy_login
                            .on_hover_text("Скопировать логин · Ctrl+B")
                            .clicked()
                    {
                        self.selected_entry = Some(entry.id.clone());
                        ui.ctx().copy_text(entry.username.clone());
                        self.status = "Логин скопирован".into();
                    }
                });
            },
        );
        ui.painter().hline(
            row_rect.x_range(),
            row_rect.bottom() + 1.0,
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(210, 202, 188, 24)),
        );
        if !dialog_open && row_response.double_clicked() {
            self.selected_entry = Some(entry.id.clone());
            self.open_entry_editor(Some(entry.id.clone()));
        } else if !dialog_open && row_response.clicked() {
            self.selected_entry = Some(entry.id.clone());
        }
        if hovered && self.entry_editor.is_none() {
            egui::Tooltip::always_open(ui.ctx().clone(), ui.layer_id(), row_response.id, row_rect)
                .at_pointer()
                .width(300.0)
                .show(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.label(
                        RichText::new(if entry.title.is_empty() {
                            "Без названия"
                        } else {
                            &entry.title
                        })
                        .strong()
                        .size(12.0)
                        .color(WHITE),
                    );
                    entry_tooltip_field(ui, 0xf007, &entry.username);
                    entry_tooltip_field(ui, 0xf0ac, &url_domain(&entry.url));
                    entry_tooltip_field(ui, 0xf017, &format_entry_time(entry.creation_time));
                    entry_tooltip_field(
                        ui,
                        0xf044,
                        &format_entry_time(entry.last_modification_time),
                    );
                });
        }
    }

    fn show_unlock_dialog(&mut self, ctx: &egui::Context) {
        let mut submit = false;
        let mut cancel = false;
        egui::Window::new("ОТКРЫТЬ БАЗУ")
            .id(egui::Id::unique("unlock_database"))
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .title_bar(false)
            .fixed_size([520.0, 380.0])
            .frame(
                Frame::new()
                    .fill(SURFACE_RAISED)
                    .corner_radius(CornerRadius::same(20))
                    .shadow(popup_shadow())
                    .inner_margin(Margin::ZERO),
            )
            .show(ctx, |ui| {
                modal_header(ui, if self.unlock.as_ref().is_some_and(|d| d.creating) { "СОЗДАТЬ БАЗУ" } else { "ОТКРЫТЬ БАЗУ" });
                Frame::new()
                    .fill(Color32::TRANSPARENT)
                    .inner_margin(Margin::symmetric(22, 14))
                    .show(ui, |ui| {
                        let Some(draft) = self.unlock.as_mut() else {
                            return;
                        };
                        Frame::new()
                            .fill(SURFACE)
                            .corner_radius(CornerRadius::same(10))
                            .inner_margin(Margin::symmetric(12, 9))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(draft.path.to_string_lossy())
                                            .size(11.0)
                                            .color(MUTED),
                                    )
                                    .truncate(),
                                );
                            });
                        ui.add_space(18.0);
                        ui.label(RichText::new("Пароль").size(12.0).color(SECONDARY));
                        let available = ui.available_width();
                        let password_response = ui.add_sized(
                            [available, 42.0],
                            TextEdit::singleline(&mut draft.password)
                                .password(true)
                                .hint_text("Введите мастер-пароль")
                                .margin(Margin::symmetric(13, 10)),
                        );
                        if !draft.focus_requested {
                            password_response.request_focus();
                            draft.focus_requested = true;
                        }
                        if (password_response.has_focus() || password_response.lost_focus())
                            && ui.input(|input| input.key_pressed(egui::Key::Enter))
                        {
                            submit = true;
                        }
                        ui.add_space(8.0);
                        if draft.creating {
                            ui.label(RichText::new("Повторите мастер-пароль").size(12.0).color(SECONDARY));
                            ui.add_sized([available, 42.0], TextEdit::singleline(&mut draft.confirmation).password(true).hint_text("Повторите пароль"));
                        }
                        if !draft.creating { ui.horizontal(|ui| {
                            if ui
                                .button(if draft.key_file.is_some() {
                                    "Заменить файл-ключ"
                                } else {
                                    "Добавить файл-ключ"
                                })
                                .clicked()
                            {
                                if let Some(path) = rfd::FileDialog::new()
                                    .set_title("Выбрать файл-ключ")
                                    .pick_file()
                                {
                                    draft.key_file = Some(path);
                                }
                            }
                            if let Some(path) = &draft.key_file {
                                ui.label(
                                    RichText::new(
                                        path.file_name()
                                            .and_then(|n| n.to_str())
                                            .unwrap_or("Файл выбран"),
                                    )
                                    .size(11.0)
                                    .color(MUTED),
                                );
                            }
                        }); }
                        ui.add_space(15.0);
                        if draft.working {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(RichText::new("Проверяю мастер-ключ…").color(SECONDARY));
                            });
                        } else {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if filled_button(ui, if draft.creating { "Создать" } else { "Открыть" }, [115.0, 38.0], ACCENT, WHITE)
                                    .clicked()
                                {
                                    submit = true;
                                }
                                if filled_button(ui, "Отмена", [100.0, 38.0], SURFACE, WHITE)
                                    .clicked()
                                {
                                    cancel = true;
                                }
                            });
                        }
                    });
            });
        if cancel {
            self.unlock = None;
            self.error = None;
            self.busy = false;
        }
        if submit {
            self.submit_unlock();
        }
    }

    fn show_group_dialog(&mut self, ctx: &egui::Context) {
        let mut save = false;
        let mut cancel = false;
        let dialog_title = if self.group_editor.as_ref().is_some_and(|d| d.id.is_some()) {
            "ПАПКА"
        } else {
            "НОВАЯ ПАПКА"
        };
        let dialog_height = (ctx.content_rect().height() - 88.0).clamp(420.0, 560.0);
        let icon_list_height = (dialog_height - 350.0).max(72.0);
        egui::Window::new(dialog_title)
            .id(egui::Id::unique("edit_group"))
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .title_bar(false)
            .fixed_size([520.0, dialog_height])
            .frame(
                Frame::new()
                    .fill(SURFACE_RAISED)
                    .corner_radius(CornerRadius::same(20))
                    .shadow(popup_shadow())
                    .inner_margin(Margin::ZERO),
            )
            .show(ctx, |ui| {
                modal_header(ui, dialog_title);
                Frame::new()
                    .fill(Color32::TRANSPARENT)
                    .inner_margin(Margin::symmetric(22, 12))
                    .show(ui, |ui| {
                        let Some(draft) = self.group_editor.as_mut() else {
                            return;
                        };
                        ui.add_space(3.0);
                        ui.label(RichText::new("Название").size(12.0).color(SECONDARY));
                        let width = ui.available_width();
                        ui.add_sized(
                            [width, 40.0],
                            TextEdit::singleline(&mut draft.title)
                                .hint_text("Например, Работа")
                                .margin(Margin::symmetric(12, 9)),
                        );
                        ui.add_space(15.0);
                        ui.horizontal(|ui| {
                            if let Some(png) = draft.icon_png.as_deref() {
                                show_custom_icon(ui, &mut self.textures, png, 42.0);
                            } else {
                                let (preview, _) =
                                    ui.allocate_exact_size(Vec2::splat(42.0), egui::Sense::hover());
                                paint_standard_icon_badge(
                                    ui.painter(),
                                    egui::Rect::from_center_size(
                                        preview.center(),
                                        Vec2::splat(26.0),
                                    ),
                                    standard_icon_glyph(draft.icon_id),
                                    false,
                                );
                            }
                            if ui
                                .button(if draft.icon_png.is_some() {
                                    "Заменить картинку"
                                } else {
                                    "Добавить картинку"
                                })
                                .clicked()
                            {
                                if let Some(path) = rfd::FileDialog::new()
                                    .set_title("Изображение значка папки")
                                    .add_filter(
                                        "Изображения",
                                        &["png", "jpg", "jpeg", "bmp", "ico"],
                                    )
                                    .pick_file()
                                {
                                    match std::fs::read(&path).and_then(|bytes| {
                                        vault::encode_icon_png(&bytes).map_err(|e| {
                                            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                                        })
                                    }) {
                                        Ok(bytes) => {
                                            draft.icon_png = Some(bytes);
                                            draft.icon_changed = true;
                                            self.error = None;
                                        }
                                        Err(error) => {
                                            self.error = Some(format!(
                                                "Значок не удалось загрузить: {error}"
                                            ))
                                        }
                                    }
                                }
                            }
                            if draft.icon_png.is_some() && ui.button("Стандартный значок").clicked()
                            {
                                draft.icon_png = None;
                                draft.icon_changed = true;
                            }
                        });
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new("СТАНДАРТНЫЕ ЗНАЧКИ KEEPASS")
                                .size(10.0)
                                .strong()
                                .color(SECONDARY),
                        );
                        ui.add_space(5.0);
                        egui::ScrollArea::vertical()
                            .max_height(icon_list_height)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                egui::Grid::new("keepass-standard-icon-grid")
                                    .num_columns(8)
                                    .spacing(Vec2::new(5.0, 5.0))
                                    .show(ui, |ui| {
                                        for (position, (id, glyph)) in
                                            standard_icon_choices().into_iter().enumerate()
                                        {
                                            let selected =
                                                draft.icon_id == id && draft.icon_png.is_none();
                                            let (rect, response) = ui.allocate_exact_size(
                                                Vec2::new(48.0, 38.0),
                                                egui::Sense::click(),
                                            );
                                            ui.painter().rect_filled(
                                                rect,
                                                CornerRadius::same(10),
                                                if response.hovered() {
                                                    lighten_color(SURFACE, 8)
                                                } else {
                                                    SURFACE
                                                },
                                            );
                                            paint_standard_icon_badge(
                                                ui.painter(),
                                                egui::Rect::from_center_size(
                                                    rect.center(),
                                                    Vec2::splat(26.0),
                                                ),
                                                glyph,
                                                selected || response.hovered(),
                                            );
                                            if response
                                                .on_hover_text(format!(
                                                    "Значок KeePass №{}",
                                                    id + 1
                                                ))
                                                .clicked()
                                            {
                                                draft.icon_id = id;
                                                draft.icon_id_changed = true;
                                                if draft.icon_png.take().is_some() {
                                                    draft.icon_changed = true;
                                                }
                                            }
                                            if (position + 1) % 8 == 0 {
                                                ui.end_row();
                                            }
                                        }
                                    });
                            });
                        ui.add_space(12.0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if filled_button(ui, "Сохранить", [112.0, 38.0], ACCENT, WHITE)
                                .clicked()
                            {
                                save = true;
                            }
                            if filled_button(ui, "Отмена", [95.0, 38.0], SURFACE, WHITE).clicked()
                            {
                                cancel = true;
                            }
                        });
                    });
            });
        if cancel {
            self.group_editor = None;
        }
        if save {
            if let Some(mut draft) = self.group_editor.take() {
                if draft.title.trim().is_empty() {
                    self.error = Some("Введите название папки".into());
                    self.group_editor = Some(draft);
                    return;
                }
                if let Some(id) = draft.id.clone() {
                    if draft.title != draft.original_title {
                        let _ = self.command_tx.send(Command::RenameGroup {
                            id: id.clone(),
                            title: draft.title.trim().to_string(),
                        });
                    }
                    if draft.icon_changed || draft.icon_id_changed {
                        let _ = self.command_tx.send(Command::SetGroupIcon {
                            id,
                            icon_id: draft.icon_id,
                            png: draft.icon_png.take(),
                        });
                    }
                } else if !draft.parent_id.is_empty() {
                    let _ = self.command_tx.send(Command::CreateGroup {
                        parent_id: draft.parent_id,
                        title: draft.title.trim().to_string(),
                        icon_id: draft.icon_id,
                        png: draft.icon_png.take(),
                    });
                }
                self.group_editor = None;
                self.busy = true;
            }
        }
    }

    fn show_entry_dialog(&mut self, ctx: &egui::Context) {
        let mut save = false;
        let mut cancel = false;
        let mut delete = false;
        let editing = self
            .entry_editor
            .as_ref()
            .is_some_and(|draft| draft.id.is_some());
        let in_recycle_bin = editing && self.entry_editor.as_ref()
            .is_some_and(|draft| self.folder_in_recycle_bin(&draft.group_id));
        let dialog_title = if editing {
            "РЕДАКТИРОВАТЬ ЗАПИСЬ"
        } else {
            "НОВАЯ ЗАПИСЬ"
        };
        let dialog_height = (ctx.content_rect().height() - 44.0).clamp(460.0, 560.0);
        egui::Window::new(dialog_title)
            .id(egui::Id::unique("edit_entry"))
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .title_bar(false)
            .fixed_size([520.0, dialog_height])
            .frame(
                Frame::new()
                    .fill(SURFACE_RAISED)
                    .corner_radius(CornerRadius::same(20))
                    .shadow(popup_shadow())
                    .inner_margin(Margin::ZERO),
            )
            .show(ctx, |ui| {
                modal_header(ui, dialog_title);

                Frame::new()
                    .fill(Color32::TRANSPARENT)
                    .inner_margin(Margin::symmetric(22, 12))
                    .show(ui, |ui| {
                        let Some(draft) = self.entry_editor.as_mut() else {
                            return;
                        };
                        egui::ScrollArea::vertical()
                            .id_salt("entry-editor-fields")
                            .auto_shrink([false, false])
                            .max_height((ui.available_height() - 56.0).max(260.0))
                            .show(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = 5.0;

                                ui.label(RichText::new("Название").size(11.5).color(SECONDARY));
                                ui.horizontal(|ui| {
                                    let width = (ui.available_width() - 46.0).max(100.0);
                                    ui.add_sized(
                                        [width, 37.0],
                                        TextEdit::singleline(&mut draft.title)
                                            .hint_text("Почта, сервер, приложение")
                                            .margin(Margin::symmetric(12, 8)),
                                    );
                                    if icon_action(ui, 0xf044, 17.0, 36.0, SECONDARY)
                                        .on_hover_text("Выбрать значок записи")
                                        .clicked()
                                    {
                                        match choose_icon_image("Изображение значка записи")
                                        {
                                            Ok(Some(bytes)) => {
                                                draft.icon_png = Some(bytes);
                                                draft.icon_changed = true;
                                                self.error = None;
                                            }
                                            Ok(None) => {}
                                            Err(error) => {
                                                self.error = Some(format!(
                                                    "Значок не удалось загрузить: {error}"
                                                ));
                                            }
                                        }
                                    }
                                });

                                form_field(ui, "Логин", &mut draft.username, "Имя пользователя");
                                ui.label(RichText::new("Пароль").size(11.5).color(SECONDARY));
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 6.0;
                                    let width = (ui.available_width() - 80.0).max(100.0);
                                    let password_hint = if draft.password_loading {
                                        "Загружается пароль…"
                                    } else if draft.id.is_some() && draft.password.is_empty() {
                                        "Оставьте пустым, чтобы не менять"
                                    } else {
                                        "Пароль"
                                    };
                                    ui.add_sized(
                                        [width, 37.0],
                                        TextEdit::singleline(&mut draft.password)
                                            .password(!draft.show_password)
                                            .hint_text(password_hint)
                                            .margin(Margin::symmetric(12, 8)),
                                    );
                                    let eye = if draft.show_password { 0xf070 } else { 0xf06e };
                                    if icon_action(ui, eye, 15.0, 34.0, SECONDARY)
                                        .on_hover_text(if draft.show_password {
                                            "Скрыть пароль"
                                        } else {
                                            "Показать пароль"
                                        })
                                        .clicked()
                                    {
                                        draft.show_password = !draft.show_password;
                                    }
                                    if icon_action(ui, 0xf084, 16.0, 34.0, SECONDARY)
                                        .on_hover_text("Сгенерировать пароль · 12 символов")
                                        .clicked()
                                    {
                                        match generate_password() {
                                            Ok(password) => {
                                                draft.password = password.to_string();
                                                draft.show_password = false;
                                                draft.password_loading = false;
                                            }
                                            Err(error) => {
                                                self.error = Some(format!(
                                                    "Не удалось сгенерировать пароль: {error}"
                                                ));
                                            }
                                        }
                                    }
                                });
                                if draft.id.is_some() {
                                    ui.checkbox(&mut draft.clear_password, "Очистить пароль");
                                }
                                form_field(ui, "Адрес", &mut draft.url, "https://example.com");
                                ui.label(RichText::new("Notes").size(11.5).color(SECONDARY));
                                let width = ui.available_width();
                                ui.add_sized(
                                    [width, 66.0],
                                    TextEdit::multiline(&mut draft.notes)
                                        .hint_text("Дополнительные заметки")
                                        .desired_rows(3)
                                        .margin(Margin::symmetric(12, 8)),
                                );
                                ui.add_space(8.0);
                                form_field(
                                    ui,
                                    "Теги",
                                    &mut draft.tags_input,
                                    "Например: работа, финансы",
                                );
                                ui.label(
                                    RichText::new(
                                        "Разделяйте теги запятой. Поиск по всем папкам: #тег",
                                    )
                                    .size(10.5)
                                    .color(MUTED),
                                );
                                ui.add_space(12.0);
                                ui.separator();
                                ui.add_space(12.0);
                                ui.label(
                                    RichText::new("СВЕДЕНИЯ О ЗАПИСИ").size(14.0).color(SECONDARY),
                                );
                                ui.add_space(10.0);
                                ui.columns(2, |columns| {
                                    entry_metadata_field(&mut columns[0], "Создана", &format_entry_time(draft.creation_time), true);
                                    entry_metadata_field(&mut columns[1], "Изменена", &format_entry_time(draft.last_modification_time), true);
                                });
                                ui.add_space(6.0);
                                entry_metadata_field(
                                    ui,
                                    "Обращений",
                                    &draft.usage_count.to_string(),
                                    false,
                                );
                                if draft.icon_png.is_some()
                                && ui
                                    .small_button("Убрать индивидуальный значок")
                                    .on_hover_text(
                                        "Использовать значок родительской папки для этой записи",
                                    )
                                    .clicked()
                            {
                                draft.icon_png = None;
                                draft.icon_changed = true;
                            }
                            });

                        ui.add_space(7.0);
                        ui.horizontal(|ui| {
                            if filled_button(ui, "Сохранить", [105.0, 36.0], ACCENT, WHITE)
                                .clicked()
                            {
                                save = true;
                            }
                            if filled_button(ui, "Отмена", [90.0, 36.0], SURFACE, WHITE).clicked()
                            {
                                cancel = true;
                            }
                            if editing {
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    let (label, width) = if in_recycle_bin {
                                        ("Удалить навсегда", 148.0)
                                    } else {
                                        ("Удалить", 100.0)
                                    };
                                    if filled_button(ui, label, [width, 36.0], SURFACE, Color32::from_rgb(224, 130, 123)).clicked() {
                                        delete = true;
                                    }
                                });
                            }
                        });
                    });
            });
        if delete {
            let (title, description) = if in_recycle_bin {
                ("Удалить запись навсегда", "Окончательно удалить эту запись из базы? Восстановить её из корзины будет невозможно.")
            } else {
                ("Удалить запись", "Переместить запись в корзину? Несохранённые изменения в этом окне будут потеряны.")
            };
            let confirmed = rfd::MessageDialog::new()
                .set_title(title)
                .set_description(description)
                .set_buttons(rfd::MessageButtons::YesNo)
                .set_level(rfd::MessageLevel::Warning)
                .show() == rfd::MessageDialogResult::Yes;
            if confirmed {
                if let Some(id) = self.entry_editor.as_ref().and_then(|draft| draft.id.clone()) {
                    let command = if in_recycle_bin {
                        Command::DeleteRecycledEntry { id }
                    } else {
                        Command::MoveEntryToRecycleBin { id }
                    };
                    if self.command_tx.send(command).is_ok() {
                        self.entry_editor = None;
                        self.selected_entry = None;
                        self.busy = true;
                        self.status = if in_recycle_bin {
                            "Удаляю запись из корзины…".into()
                        } else {
                            "Перемещаю запись в корзину…".into()
                        };
                    } else {
                        self.error = Some("Не удалось запустить удаление записи".into());
                    }
                }
            }
        }
        if cancel {
            self.entry_editor = None;
        }
        if save {
            if let Some(mut draft) = self.entry_editor.take() {
                if draft.title.trim().is_empty() {
                    self.error = Some("У записи должно быть название".into());
                    self.entry_editor = Some(draft);
                    return;
                }
                if let Some(id) = draft.id.clone() {
                    let tags = parse_tags(&draft.tags_input);
                    let password = if draft.password.is_empty() {
                        None
                    } else {
                        Some(Zeroizing::new(std::mem::take(&mut draft.password)))
                    };
                    let _ = self.command_tx.send(Command::EditEntry {
                        id: id.clone(),
                        title: draft.title.trim().to_string(),
                        username: std::mem::take(&mut draft.username),
                        password,
                        clear_password: draft.clear_password,
                        url: std::mem::take(&mut draft.url),
                        notes: std::mem::take(&mut draft.notes),
                        tags,
                    });
                    if draft.icon_changed {
                        let _ = self.command_tx.send(Command::SetEntryIcon {
                            id,
                            png: draft.icon_png.take(),
                        });
                    }
                } else {
                    let tags = parse_tags(&draft.tags_input);
                    let password = Zeroizing::new(std::mem::take(&mut draft.password));
                    let _ = self.command_tx.send(Command::CreateEntry {
                        group_id: std::mem::take(&mut draft.group_id),
                        title: draft.title.trim().to_string(),
                        username: std::mem::take(&mut draft.username),
                        password,
                        url: std::mem::take(&mut draft.url),
                        notes: std::mem::take(&mut draft.notes),
                        tags,
                        png: draft.icon_png.take(),
                    });
                }
                self.entry_editor = None;
                self.busy = true;
            }
        }
    }

    fn show_sync_conflict(&mut self, ctx: &egui::Context) {
        let Some(conflict) = self.sync_conflict.as_ref() else { return };
        let mut decision = None;
        let width = (ctx.content_rect().width() - 56.0).clamp(530.0, 920.0);
        egui::Modal::new(egui::Id::unique("sync_conflict"))
            .frame(Frame::new()
                .fill(SURFACE_RAISED)
                .corner_radius(CornerRadius::same(20))
                .inner_margin(Margin::same(22))
                .shadow(popup_shadow()))
            .show(ctx, |ui| {
                ui.set_width(width);
                ui.heading("Сравнение записей");
                ui.label(format!("Записей на рассмотрении: {}", conflict.remaining));
                if let (Some(local), Some(server)) = (&conflict.local, &conflict.server) {
                    if local.password.as_str() != server.password.as_str() {
                        ui.label(RichText::new("В этой записи различаются пароли.").color(GOLD));
                    }
                }
                ui.checkbox(&mut self.show_conflict_secrets, "Показать пароли и защищённые поля");
                ui.separator();
                egui::ScrollArea::vertical()
                    .max_height((ctx.content_rect().height() * 0.52).min(480.0))
                    .id_salt("compared_entry_details")
                    .show(ui, |ui| {
                        ui.columns(2, |columns| {
                            conflict_entry(&mut columns[0], "А · Локальная версия", conflict.local.as_ref(),
                                &conflict.local_folder, self.show_conflict_secrets);
                            conflict_entry(&mut columns[1], "Б · Версия на сервере", conflict.server.as_ref(),
                                &conflict.server_folder, self.show_conflict_secrets);
                        });
                    });
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    if filled_button(ui, "Оставить А", [110.0, 36.0], ACCENT, WHITE).clicked() {
                        decision = Some(Decision::Local);
                    }
                    if filled_button(ui, "Принять Б", [110.0, 36.0], ACCENT, WHITE).clicked() {
                        decision = Some(Decision::Server);
                    }
                    if ui.add_enabled(conflict.local.is_some() && conflict.server.is_some(),
                        egui::Button::new("Сохранить А и Б").min_size(egui::vec2(132.0, 36.0))).clicked()
                    {
                        decision = Some(Decision::Both);
                    }
                    if filled_button(ui, "Позже", [78.0, 36.0], SURFACE, WHITE).clicked() {
                        decision = Some(Decision::Later);
                    }
                });
            });
        if let Some(decision) = decision {
            if self.command_tx.send(Command::ResolveSync(decision)).is_ok() {
                self.sync_conflict = None;
                self.show_conflict_secrets = false;
                self.busy = true;
                self.sync_in_flight = true;
            }
        }
    }

    fn show_sync_dialog(&mut self, ctx: &egui::Context) {
        let mut save = false;
        let mut cancel = false;
        let mut test_connection = false;
        let mut change_master_password = false;
        let path = self.database_path.clone();
        let state = path.as_deref().and_then(|p| self.settings.sync_state_for(p)).cloned().unwrap_or_default();
        let local_hash = path.as_deref().and_then(|p| file_sha256(p).ok());
        let modified = self.snapshot.as_ref().is_some_and(|s| s.modified);
        let pending = modified || local_hash.as_ref() != state.last_uploaded_sha256.as_ref();
        let file_name = path.as_deref().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("—").to_string();
        let last_sync = state.last_success.and_then(|seconds| chrono::DateTime::from_timestamp(seconds as i64, 0))
            .map(|time| time.with_timezone(&chrono::Local).format("%d.%m.%Y %H:%M").to_string())
            .unwrap_or_else(|| "Ещё не было".into());
        let dialog_height = (ctx.content_rect().height() - 20.0).clamp(430.0, 760.0);
        egui::Window::new("НАСТРОЙКИ БАЗЫ")
            .id(egui::Id::unique("sync_settings"))
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .title_bar(false)
            .fixed_size([760.0, dialog_height])
            .frame(
                Frame::new()
                    .fill(SURFACE_RAISED)
                    .corner_radius(CornerRadius::same(20))
                    .shadow(popup_shadow())
                    .inner_margin(Margin::ZERO),
            )
            .show(ctx, |ui| {
                ui.set_min_height(dialog_height);
                ui.horizontal(|ui| {
                ui.vertical(|ui| {
                Frame::new().fill(SURFACE).inner_margin(Margin::symmetric(12, 12)).show(ui, |ui| {
                    ui.set_width(184.0);
                    ui.set_min_height(dialog_height - 24.0);
                    ui.add_space(12.0);
                    for (tab, label, icon) in [(SettingsTab::Overview, "Обзор", 0xf06e), (SettingsTab::Connection, "Подключение FTPS", 0xf0ac), (SettingsTab::Security, "Безопасность", 0xf023)] {
                        let selected = self.settings_tab == tab;
                        if settings_nav_button(ui, label, icon, selected).clicked() {
                            self.settings_tab = tab;
                        }
                        ui.add_space(6.0);
                    }
                });
                });
                ui.vertical(|ui| {
                Frame::new()
                    .fill(Color32::TRANSPARENT)
                    .inner_margin(Margin::symmetric(20, 12))
                    .show(ui, |ui| {
                        ui.set_width(500.0);
                        ui.set_min_height(dialog_height - 24.0);
                        let Some(draft) = self.sync_editor.as_mut() else {
                            return;
                        };
                        let scroll_top = ui.cursor().top();
                        egui::ScrollArea::vertical()
                            .id_salt("database-settings-scroll")
                            .auto_shrink([false, false])
                            .content_margin(Margin {
                                left: 0,
                                right: 12,
                                top: 0,
                                bottom: 0,
                            })
                            .max_height((dialog_height - 96.0).max(260.0))
                            .show(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = 7.0;
                                if self.settings_tab == SettingsTab::Overview {
                                    ui.heading("Состояние синхронизации");
                                    ui.add_space(8.0);
                                    let connected = draft.enabled && !draft.host.trim().is_empty() && draft.already_has_password;
                                    let headline = if !draft.enabled { "Синхронизация выключена" } else if !connected { "Подключение не настроено" } else if state.last_error.is_some() { "Требуется внимание" } else if self.busy && self.status.contains("синхронизац") { "Выполняется синхронизация…" } else if pending { "Есть изменения для отправки" } else { "БД синхронизирована" };
                                    Frame::new().fill(SURFACE).corner_radius(CornerRadius::same(12)).inner_margin(Margin::same(16)).show(ui, |ui| {
                                        ui.label(RichText::new(headline).size(18.0).strong().color(if pending || state.last_error.is_some() { GOLD } else { WHITE }));
                                        ui.add_space(8.0);
                                        ui.label(format!("Подключение: {}", if connected { "настроено" } else { "не настроено" }));
                                        ui.label(format!("Синхронизация при сохранении: {}", if draft.enabled { "включена" } else { "выключена" }));
                                        ui.label(format!("Последняя успешная синхронизация: {last_sync}"));
                                    });
                                    ui.add_space(14.0);
                                    ui.label(RichText::new("СИНХРОНИЗИРУЕМЫЙ ФАЙЛ").size(11.0).strong().color(SECONDARY));
                                    ui.label(RichText::new(&file_name).size(15.0).color(WHITE));
                                    ui.label(format!("Локально: {}", if modified { "изменения ещё не сохранены" } else { "зашифрованный файл сохранён" }));
                                    ui.label(format!("На сервере: {}", if state.last_error.is_some() { "текущее состояние не подтверждено" } else if state.last_success.is_none() || pending { "текущая версия ещё не подтверждена" } else { "копии совпадают" }));
                                    ui.label(format!("Неотправленные изменения: {}", if pending { "есть" } else { "нет" }));
                                    if let Some(message) = state.last_error.as_ref() {
                                        ui.add_space(12.0);
                                        ui.label(RichText::new("ПОСЛЕДНЯЯ ОШИБКА").size(11.0).strong().color(GOLD));
                                        ui.label(RichText::new(message).size(11.0).color(WHITE));
                                    }
                                    ui.add_space(14.0);
                                    ui.label(RichText::new("Изменения отправляются после «Сохранить» или «Сохранить как» в панели базы. При ошибке локальная копия остаётся сохранённой.").size(11.0).color(MUTED));
                                }
                                if self.settings_tab == SettingsTab::Connection {
                                ui.label(
                                    RichText::new("СИНХРОНИЗАЦИЯ FTPS")
                                        .size(12.0)
                                        .strong()
                                        .color(SECONDARY),
                                );
                                ui.label(
                                    RichText::new("Эти параметры относятся только к открытой базе. После сохранения Peplos отправляет зашифрованный файл по FTPS/TLS.")
                                        .size(11.0)
                                        .color(MUTED),
                                );
                                ui.checkbox(
                                    &mut draft.enabled,
                                    "Синхронизировать после сохранения",
                                );
                                form_field(
                                    ui,
                                    "Сервер",
                                    &mut draft.host,
                                    "Введите адрес сервера",
                                );
                                ui.horizontal(|ui| {
                                    ui.vertical(|ui| {
                                        ui.label(
                                            RichText::new("Порт")
                                                .size(12.0)
                                                .color(SECONDARY),
                                        );
                                        ui.add_sized(
                                            [90.0, 36.0],
                                            TextEdit::singleline(&mut draft.port),
                                        );
                                    });
                                    ui.vertical(|ui| {
                                        ui.label(
                                            RichText::new("Пользователь")
                                                .size(12.0)
                                                .color(SECONDARY),
                                        );
                                        ui.add_sized(
                                            [ui.available_width(), 36.0],
                                            TextEdit::singleline(&mut draft.username),
                                        );
                                    });
                                });
                                form_field(
                                    ui,
                                    "Папка на сервере",
                                    &mut draft.remote_directory,
                                    "Оставьте пустым для домашней папки",
                                );
                                ui.label(
                                    RichText::new("Пароль FTPS")
                                        .size(12.0)
                                        .color(SECONDARY),
                                );
                                let width = ui.available_width();
                                ui.add_sized(
                                    [width, 36.0],
                                    TextEdit::singleline(&mut draft.password)
                                        .password(true)
                                        .hint_text(if draft.already_has_password {
                                            "Оставьте пустым, чтобы не менять"
                                        } else {
                                            "Введите пароль FTPS"
                                        }),
                                );
                                ui.label(
                                    RichText::new("Пароль хранится, защищённый Windows DPAPI. Сертификат сервера проверяется.")
                                        .size(10.0)
                                        .color(MUTED),
                                );
                                if let Some(result) = self.ftps_test_result.as_ref() {
                                    ui.add_space(8.0);
                                    match result {
                                        Ok(()) => { ui.label(RichText::new("✓ Подключение FTPS работает").color(WHITE)); }
                                        Err(message) => { ui.label(RichText::new("Проверка не пройдена").color(GOLD)); ui.label(message); }
                                    }
                                }
                                }
                                if self.settings_tab == SettingsTab::Security {
                                ui.label(
                                    RichText::new("СМЕНА МАСТЕР-ПАРОЛЯ")
                                        .size(12.0)
                                        .strong()
                                        .color(SECONDARY),
                                );
                                ui.label(
                                    RichText::new("Новый пароль вступит в силу после сохранения базы. После этого прежний пароль перестанет подходить.")
                                        .size(11.0)
                                        .color(MUTED),
                                );
                                ui.label(
                                    RichText::new("Новый пароль")
                                        .size(12.0)
                                        .color(SECONDARY),
                                );
                                let width = ui.available_width();
                                ui.add_sized(
                                    [width, 36.0],
                                    TextEdit::singleline(&mut draft.master_password)
                                        .password(true)
                                        .hint_text("Введите новый мастер-пароль"),
                                );
                                ui.label(
                                    RichText::new("Повторите новый пароль")
                                        .size(12.0)
                                        .color(SECONDARY),
                                );
                                let width = ui.available_width();
                                ui.add_sized(
                                    [width, 36.0],
                                    TextEdit::singleline(&mut draft.master_password_confirm)
                                        .password(true)
                                        .hint_text("Повторите пароль для проверки"),
                                );
                                ui.add_space(2.0);
                                if filled_button(
                                    ui,
                                    "Подготовить смену мастер-пароля",
                                    [ui.available_width(), 36.0],
                                    GOLD,
                                    BG,
                                )
                                .clicked()
                                {
                                    change_master_password = true;
                                }
                                }
                            });
                        let scroll_height = ui.cursor().top() - scroll_top;
                        ui.add_space((dialog_height - 96.0 - scroll_height).max(0.0));
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if self.settings_tab == SettingsTab::Connection && filled_button(ui, "Проверить FTPS", [120.0, 36.0], SURFACE, WHITE).clicked()
                            {
                                test_connection = true;
                            }
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if filled_button(ui, "Отмена", [104.0, 36.0], SURFACE, WHITE)
                                    .clicked()
                                {
                                    cancel = true;
                                }
                                if filled_button(
                                    ui,
                                    "Сохранить",
                                    [120.0, 36.0],
                                    ACCENT,
                                    WHITE,
                                )
                                .clicked()
                                {
                                    save = true;
                                }
                            });
                        });
                    });
                });
                });
            });

        if change_master_password {
            let Some(draft) = self.sync_editor.as_mut() else {
                return;
            };
            if draft.master_password.is_empty() {
                self.error = Some("Введите новый мастер-пароль".into());
            } else if draft.master_password != draft.master_password_confirm {
                self.error = Some("Пароли не совпадают".into());
            } else {
                let password = Zeroizing::new(std::mem::take(&mut draft.master_password));
                draft.master_password_confirm.zeroize();
                if self
                    .command_tx
                    .send(Command::ChangeMasterPassword { password })
                    .is_ok()
                {
                    self.busy = true;
                    self.status = "Подготавливаю смену мастер-пароля…".into();
                    self.error = None;
                } else {
                    self.error = Some("Не удалось начать смену мастер-пароля".into());
                }
            }
        }

        if test_connection {
            if let Some(draft) = self.sync_editor.as_ref() {
                let existing = self
                    .database_path
                    .as_deref()
                    .and_then(|path| self.settings.sync_for(path));
                let port = draft.port.parse::<u16>();
                let protected = if !draft.password.trim().is_empty() {
                    protect_ftps_input(&draft.password)
                } else if let Some(existing) = existing {
                    Ok(existing.password_dpapi.clone())
                } else {
                    Err(anyhow::anyhow!(
                        "Введите пароль FTPS для проверки соединения"
                    ))
                };
                match (port, protected) {
                    (Ok(port), Ok(password_dpapi)) if !draft.host.trim().is_empty() => {
                        let config = SyncConfig {
                            enabled: draft.enabled,
                            host: draft.host.trim().to_string(),
                            port,
                            username: draft.username.trim().to_string(),
                            remote_directory: draft
                                .remote_directory
                                .trim()
                                .trim_matches('/')
                                .to_string(),
                            password_dpapi,
                        };
                        if self.command_tx.send(Command::TestFtps { config }).is_ok() {
                            self.busy = true;
                            self.status = "Проверяю FTPS-соединение…".into();
                        }
                    }
                    (Err(_), _) => self.error = Some("Укажите корректный порт FTPS".into()),
                    (_, Err(error)) => self.error = Some(error.to_string()),
                    _ => self.error = Some("Укажите сервер FTPS".into()),
                }
            }
        }
        if cancel {
            self.sync_editor = None;
        }
        if save {
            let Some(path) = self.database_path.clone() else {
                self.error = Some("Сначала откройте базу данных".into());
                return;
            };
            if let Some(draft) = self.sync_editor.take() {
                let existing = self.settings.sync_for(&path).cloned();
                let parsed_port = draft.port.parse::<u16>();
                let port = parsed_port.as_ref().copied().unwrap_or(21);
                if draft.enabled && (draft.host.trim().is_empty() || parsed_port.is_err()) {
                    self.error = Some("Для включённой синхронизации укажите сервер и порт".into());
                    self.sync_editor = Some(draft);
                    return;
                }
                let password_dpapi = if !draft.password.trim().is_empty() {
                    match protect_ftps_input(&draft.password) {
                        Ok(value) => value,
                        Err(error) => {
                            self.error = Some(error.to_string());
                            self.sync_editor = Some(draft);
                            return;
                        }
                    }
                } else if let Some(existing) = existing.as_ref() {
                    existing.password_dpapi.clone()
                } else if draft.enabled {
                    self.error = Some("Введите пароль FTPS для включённой синхронизации".into());
                    self.sync_editor = Some(draft);
                    return;
                } else {
                    String::new()
                };
                self.settings.set_sync_for(
                    &path,
                    SyncConfig {
                        enabled: draft.enabled,
                        host: draft.host.trim().to_string(),
                        port,
                        username: draft.username.trim().to_string(),
                        remote_directory: draft
                            .remote_directory
                            .trim()
                            .trim_matches('/')
                            .to_string(),
                        password_dpapi,
                    },
                );
                let changed_connection = existing.as_ref().is_none_or(|old| old.host != draft.host.trim()
                    || old.port != port || old.username != draft.username.trim()
                    || old.remote_directory != draft.remote_directory.trim().trim_matches('/'));
                if changed_connection {
                    self.settings.set_sync_state_for(&path, SyncState::default());
                }
                if let Err(error) = self.settings.save() {
                    self.error = Some(error.to_string());
                    self.sync_editor = Some(draft);
                } else {
                    self.status = "Настройки этой базы сохранены".into();
                    self.error = None;
                    self.sync_editor = None;
                }
            }
        }
    }
}

impl eframe::App for PeplosApp {
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        #[cfg(windows)]
        if autotype::take_hotkey()
            && self.selected_entry.is_some()
            && self.pending_auto_type.is_none()
            && !self.auto_type_running
            && self.unlock.is_none()
            && self.entry_editor.is_none()
            && self.group_editor.is_none()
            && self.sync_editor.is_none()
            && !self.busy
            && !ctx.egui_wants_keyboard_input()
        {
            self.auto_type_hotkey = true;
            raw_input.events.retain(|event| {
                !matches!(event, egui::Event::Paste(_) | egui::Event::PasteImage(_))
            });
        }
        #[cfg(not(windows))]
        let _ = (ctx, raw_input);
    }

    fn ui(&mut self, root_ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        let ctx = root_ui.ctx().clone();
        self.poll_events(&ctx);
        self.clear_expired_clipboard(false);
        if let Some((_, deadline)) = self.clipboard_password {
            ctx.request_repaint_after(deadline.saturating_duration_since(Instant::now()).max(Duration::from_secs(1)));
        }
        if ctx.input(|input| input.viewport().close_requested())
            && self.has_unsaved_changes() && !confirm_discard_changes()
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        self.handle_hotkeys(&ctx, frame);
        #[cfg(windows)]
        if !self.backdrop_checked {
            if let Some(window) = frame.winit_window() {
                window.set_undecorated_shadow(false);
                self.backdrop_available = configure_window_backdrop(window);
                window.set_visible(true);
                suppress_window_border(window);
                self.backdrop_checked = true;
            }
        }
        let database_open = self.snapshot.is_some();
        paint_background(&ctx, self.backdrop_available, database_open);
        let full_size = root_ui.available_size_before_wrap();
        root_ui.allocate_ui_with_layout(full_size, Layout::top_down(Align::Min), |ui| {
            Frame::new()
                .fill(Color32::TRANSPARENT)
                .inner_margin(if database_open { Margin::ZERO } else { Margin::symmetric(10, 8) })
                .show(ui, |ui| {
                    if !database_open {
                        self.show_header(ui);
                        ui.add_space(4.0);
                    }
                    let footer_reserve = if database_open { 0.0 } else { 22.0 };
                    let body_height = (ui.available_height() - footer_reserve).max(120.0);
                    ui.allocate_ui_with_layout(
                        Vec2::new(ui.available_width(), body_height),
                        Layout::top_down(Align::Min),
                        |body| {
                            if self.sync_in_flight || self.sync_conflict.is_some() {
                                body.disable();
                            }
                            if self.snapshot.is_some() {
                                self.show_database(body);
                            } else {
                                self.show_welcome(body);
                            }
                        },
                    );
                    ui.add_space(6.0);
                    if !database_open {
                        Frame::new()
                            .fill(Color32::TRANSPARENT)
                            .corner_radius(CornerRadius::ZERO)
                            .stroke(Stroke::NONE)
                            .inner_margin(Margin::symmetric(8, 6))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    if self.busy {
                                        ui.spinner();
                                    }
                                    ui.label(RichText::new(&self.status).size(12.0).color(if self.busy {
                                        SECONDARY
                                    } else {
                                        MUTED
                                    }));
                                    if self.snapshot.as_ref().is_some_and(|s| s.modified) {
                                        ui.label(
                                            RichText::new("Несохранённые изменения")
                                                .size(12.0)
                                                .color(GOLD),
                                        );
                                    }
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if self.snapshot.is_some() {
                                            ui.label(
                                                RichText::new(
                                                    "Ctrl+V ввод   ·   Ctrl+C пароль   ·   Ctrl+B логин",
                                                )
                                                .size(12.0)
                                                .color(MUTED),
                                            );
                                        }
                                    });
                                });
                            });
                    }
                            });
                        });
        if self.unlock.is_some() {
            self.show_unlock_dialog(&ctx);
        }
        if self.group_editor.is_some() {
            self.show_group_dialog(&ctx);
        }
        if self.entry_editor.is_some() {
            self.show_entry_dialog(&ctx);
        }
        if self.sync_editor.is_some() {
            self.show_sync_dialog(&ctx);
        }
        if self.sync_conflict.is_some() {
            self.show_sync_conflict(&ctx);
        }
        if let Some(message) = self.error.clone() {
            egui::Window::new("Peplos")
                .anchor(Align2::RIGHT_BOTTOM, Vec2::new(-24.0, -48.0))
                .collapsible(false)
                .resizable(false)
                .fixed_size([420.0, 115.0])
                .frame(
                    Frame::new()
                        .fill(Color32::from_rgb(53, 35, 37))
                        .corner_radius(CornerRadius::same(10))
                        .shadow(popup_shadow())
                        .stroke(Stroke::new(1.0, Color32::from_rgb(137, 82, 79)))
                        .inner_margin(Margin::same(16)),
                )
                .show(&ctx, |ui| {
                    ui.label(RichText::new(message).size(12.0).color(WHITE));
                    if ui.small_button("Закрыть").clicked() {
                        self.error = None;
                    }
                });
        }
        #[cfg(windows)]
        if !self.resize_hit_test_installed {
            if let Some(window) = frame.winit_window() {
                self.resize_hit_test_installed = install_window_resize_hit_test(window);
            }
        }
        #[cfg(not(windows))]
        resize_hit_targets(root_ui, &ctx, root_ui.max_rect(), frame.winit_window());
    }
}

fn entry_column_widths(text_width: f32) -> ([f32; 4], f32) {
    let gap = 12.0;
    let each = ((text_width - gap * 3.0) / 4.0).max(24.0);
    ([each; 4], gap)
}

fn single_line(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn ellipsize_text(
    painter: &egui::Painter,
    text: &str,
    font: &FontId,
    color: Color32,
    max_width: f32,
) -> String {
    if painter
        .layout_no_wrap(text.to_owned(), font.clone(), color)
        .size()
        .x
        <= max_width
    {
        return text.to_owned();
    }
    let mut shortened = String::new();
    for character in text.chars() {
        let candidate = format!("{shortened}{character}…");
        if painter
            .layout_no_wrap(candidate, font.clone(), color)
            .size()
            .x
            > max_width
        {
            break;
        }
        shortened.push(character);
    }
    format!("{shortened}…")
}

#[derive(Clone, Copy)]
enum WindowControl {
    Minimize,
    Maximize,
    Close,
}

fn window_control(ui: &mut egui::Ui, control: WindowControl, maximized: bool) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(38.0, 32.0), egui::Sense::click());
    if response.hovered() {
        let fill = if matches!(control, WindowControl::Close) {
            Color32::from_rgb(196, 43, 28)
        } else {
            Color32::from_rgb(27, 30, 35)
        };
        ui.painter().rect_filled(rect, CornerRadius::same(10), fill);
    }
    let color = if response.hovered() { WHITE } else { SECONDARY };
    let stroke = Stroke::new(1.4, color);
    let center = rect.center();
    match control {
        WindowControl::Minimize => {
            ui.painter().line_segment(
                [center + Vec2::new(-5.0, 3.0), center + Vec2::new(5.0, 3.0)],
                stroke,
            );
        }
        WindowControl::Maximize if maximized => {
            let back =
                egui::Rect::from_center_size(center + Vec2::new(-1.5, 1.5), Vec2::new(9.0, 8.0));
            let front =
                egui::Rect::from_center_size(center + Vec2::new(2.0, -1.5), Vec2::new(9.0, 8.0));
            ui.painter()
                .rect_stroke(back, 0.8, stroke, egui::StrokeKind::Inside);
            ui.painter()
                .rect_stroke(front, 0.8, stroke, egui::StrokeKind::Inside);
        }
        WindowControl::Maximize => {
            let square = egui::Rect::from_center_size(center, Vec2::splat(11.0));
            ui.painter()
                .rect_stroke(square, 0.8, stroke, egui::StrokeKind::Inside);
        }
        WindowControl::Close => {
            ui.painter().line_segment(
                [center + Vec2::splat(-4.0), center + Vec2::splat(4.0)],
                stroke,
            );
            ui.painter().line_segment(
                [center + Vec2::new(-4.0, 4.0), center + Vec2::new(4.0, -4.0)],
                stroke,
            );
        }
    }
    response
}

#[cfg(not(windows))]
fn resize_hit_targets(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    rect: egui::Rect,
    window: Option<&std::sync::Arc<winit::window::Window>>,
) {
    if ctx.input(|i| i.viewport().maximized.unwrap_or(false)) {
        return;
    }
    let corner = 17.0;
    let edge = 11.0;
    let targets = [
        (
            egui::Rect::from_min_size(rect.min, Vec2::splat(corner)),
            egui::ResizeDirection::NorthWest,
        ),
        (
            egui::Rect::from_min_size(
                egui::pos2(rect.left(), rect.bottom() - corner),
                Vec2::splat(corner),
            ),
            egui::ResizeDirection::SouthWest,
        ),
        (
            egui::Rect::from_min_size(
                rect.right_bottom() - Vec2::splat(corner),
                Vec2::splat(corner),
            ),
            egui::ResizeDirection::SouthEast,
        ),
        (
            egui::Rect::from_min_max(
                egui::pos2(rect.left() + corner, rect.top()),
                // Leave a generous dead zone above the window controls so
                // the resize target can never steal the close-button click.
                egui::pos2(rect.right() - 132.0, rect.top() + edge),
            ),
            egui::ResizeDirection::North,
        ),
        (
            egui::Rect::from_min_max(
                egui::pos2(rect.left() + corner, rect.bottom() - edge),
                egui::pos2(rect.right() - corner, rect.bottom()),
            ),
            egui::ResizeDirection::South,
        ),
        (
            egui::Rect::from_min_max(
                egui::pos2(rect.left(), rect.top() + corner),
                egui::pos2(rect.left() + edge, rect.bottom() - corner),
            ),
            egui::ResizeDirection::West,
        ),
        (
            egui::Rect::from_min_max(
                // The title bar contains the minimize, maximize and close
                // buttons. Start the east resize strip below that row.
                egui::pos2(rect.right() - edge, rect.top() + 58.0),
                egui::pos2(rect.right(), rect.bottom() - corner),
            ),
            egui::ResizeDirection::East,
        ),
    ];
    for (index, (target, direction)) in targets.into_iter().enumerate() {
        let response = ui.interact(
            target,
            egui::Id::unique(egui::IdSalt::new(("window-resize", index))),
            egui::Sense::drag(),
        );
        if response.hovered() {
            let cursor = match direction {
                egui::ResizeDirection::NorthWest | egui::ResizeDirection::SouthEast => {
                    egui::CursorIcon::ResizeNwSe
                }
                egui::ResizeDirection::NorthEast | egui::ResizeDirection::SouthWest => {
                    egui::CursorIcon::ResizeNeSw
                }
                egui::ResizeDirection::East | egui::ResizeDirection::West => {
                    egui::CursorIcon::ResizeHorizontal
                }
                egui::ResizeDirection::North | egui::ResizeDirection::South => {
                    egui::CursorIcon::ResizeVertical
                }
            };
            ctx.set_cursor_icon(cursor);
        }
        if response.drag_started() {
            if let Some(window) = window {
                let native_direction = match direction {
                    egui::ResizeDirection::North => winit::window::ResizeDirection::North,
                    egui::ResizeDirection::South => winit::window::ResizeDirection::South,
                    egui::ResizeDirection::East => winit::window::ResizeDirection::East,
                    egui::ResizeDirection::West => winit::window::ResizeDirection::West,
                    egui::ResizeDirection::NorthEast => winit::window::ResizeDirection::NorthEast,
                    egui::ResizeDirection::SouthEast => winit::window::ResizeDirection::SouthEast,
                    egui::ResizeDirection::NorthWest => winit::window::ResizeDirection::NorthWest,
                    egui::ResizeDirection::SouthWest => winit::window::ResizeDirection::SouthWest,
                };
                let _ = window.drag_resize_window(native_direction);
            }
        }
    }
    let grip_painter = ctx.layer_painter(egui::LayerId::new(
        egui::Order::Foreground,
        egui::Id::unique(egui::IdSalt::new("window-resize-grip")),
    ));
    let grip_color = Color32::from_rgba_unmultiplied(159, 154, 145, 170);
    for offset in 0..3 {
        let inset = 5.0 + offset as f32 * 4.0;
        grip_painter.line_segment(
            [
                rect.right_bottom() - Vec2::new(inset + 5.0, inset),
                rect.right_bottom() - Vec2::new(inset, inset + 5.0),
            ],
            Stroke::new(1.2, grip_color),
        );
    }
}

#[cfg(windows)]
fn configure_window_backdrop(window: &winit::window::Window) -> bool {
    use windows_sys::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMSBT_TRANSIENTWINDOW, DWMWA_SYSTEMBACKDROP_TYPE,
        DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND,
    };

    let Ok(handle) = window.window_handle() else {
        return false;
    };
    let RawWindowHandle::Win32(handle) = handle.as_raw() else {
        return false;
    };
    let hwnd = handle.hwnd.get() as windows_sys::Win32::Foundation::HWND;
    let size = std::mem::size_of::<u32>() as u32;
    let dark = 1i32;
    let system_corners = DWMWCP_ROUND;
    let acrylic = DWMSBT_TRANSIENTWINDOW;
    let acrylic_enabled = unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
            &dark as *const _ as *const _,
            size,
        );
        let _ = suppress_window_border_hwnd(hwnd);
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            &system_corners as *const _ as *const _,
            size,
        );
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_SYSTEMBACKDROP_TYPE as u32,
            &acrylic as *const _ as *const _,
            size,
        ) >= 0
    };
    acrylic_enabled
}

#[cfg(windows)]
fn suppress_window_border(window: &winit::window::Window) {
    let Ok(handle) = window.window_handle() else {
        return;
    };
    let RawWindowHandle::Win32(handle) = handle.as_raw() else {
        return;
    };
    let hwnd = handle.hwnd.get() as windows_sys::Win32::Foundation::HWND;
    let _ = suppress_window_border_hwnd(hwnd);
}

#[cfg(windows)]
fn suppress_window_border_hwnd(hwnd: windows_sys::Win32::Foundation::HWND) -> bool {
    use windows_sys::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_BORDER_COLOR, DWMWA_COLOR_NONE,
    };

    let no_border = DWMWA_COLOR_NONE;
    unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_BORDER_COLOR as u32,
            &no_border as *const _ as *const _,
            std::mem::size_of_val(&no_border) as u32,
        ) >= 0
    }
}

#[cfg(windows)]
fn install_window_resize_hit_test(window: &winit::window::Window) -> bool {
    let Ok(handle) = window.window_handle() else {
        return false;
    };
    let RawWindowHandle::Win32(handle) = handle.as_raw() else {
        return false;
    };
    let hwnd = handle.hwnd.get() as windows_sys::Win32::Foundation::HWND;
    unsafe {
        windows_sys::Win32::UI::Shell::SetWindowSubclass(
            hwnd,
            Some(window_resize_subclass),
            0x5045_504C,
            0,
        ) != 0
    }
}

#[cfg(windows)]
unsafe extern "system" fn window_resize_subclass(
    hwnd: windows_sys::Win32::Foundation::HWND,
    message: u32,
    wparam: windows_sys::Win32::Foundation::WPARAM,
    lparam: windows_sys::Win32::Foundation::LPARAM,
    subclass_id: usize,
    _reference: usize,
) -> windows_sys::Win32::Foundation::LRESULT {
    use windows_sys::Win32::{
        Foundation::RECT,
        UI::{
            HiDpi::GetDpiForWindow,
            Shell::{DefSubclassProc, RemoveWindowSubclass},
            WindowsAndMessaging::{
                GetWindowRect, IsZoomed, HTBOTTOM, HTBOTTOMLEFT, HTBOTTOMRIGHT, HTLEFT, HTRIGHT,
                HTTOP, HTTOPLEFT, WM_ACTIVATE, WM_NCACTIVATE, WM_NCDESTROY, WM_NCHITTEST,
            },
        },
    };

    if message == WM_NCDESTROY {
        unsafe { RemoveWindowSubclass(hwnd, Some(window_resize_subclass), subclass_id) };
        return unsafe { DefSubclassProc(hwnd, message, wparam, lparam) };
    }

    if message == WM_ACTIVATE && (wparam & 0xffff) != 0 {
        autotype::remember_previous_window(hwnd, lparam);
    }
    autotype::observe_key_message(message, wparam, lparam);

    if message == WM_NCHITTEST && unsafe { IsZoomed(hwnd) } == 0 {
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        if unsafe { GetWindowRect(hwnd, &mut rect) } != 0 {
            let dpi = unsafe { GetDpiForWindow(hwnd) }.max(96) as f32 / 96.0;
            let edge = (11.0 * dpi).round() as i32;
            let corner = (17.0 * dpi).round() as i32;
            let top_button_gap = (132.0 * dpi).round() as i32;
            let right_button_height = (58.0 * dpi).round() as i32;
            let packed = lparam as u32;
            let x = (packed as u16 as i16) as i32;
            let y = ((packed >> 16) as u16 as i16) as i32;
            let left = x < rect.left + edge;
            let right = x >= rect.right - edge;
            let top = y < rect.top + edge;
            let bottom = y >= rect.bottom - edge;

            let hit_test = if y < rect.top + corner && x < rect.left + corner {
                Some(HTTOPLEFT)
            } else if y >= rect.bottom - corner && x < rect.left + corner {
                Some(HTBOTTOMLEFT)
            } else if y >= rect.bottom - corner && x >= rect.right - corner {
                Some(HTBOTTOMRIGHT)
            } else if bottom && x >= rect.left + corner && x < rect.right - corner {
                Some(HTBOTTOM)
            } else if left && y >= rect.top + corner && y < rect.bottom - corner {
                Some(HTLEFT)
            } else if right && y >= rect.top + right_button_height && y < rect.bottom - corner {
                Some(HTRIGHT)
            } else if top && x >= rect.left + corner && x < rect.right - top_button_gap {
                Some(HTTOP)
            } else {
                None
            };

            if let Some(hit_test) = hit_test {
                return hit_test as isize;
            }
        }
    }

    let result = unsafe { DefSubclassProc(hwnd, message, wparam, lparam) };
    if message == WM_ACTIVATE || message == WM_NCACTIVATE {
        let _ = suppress_window_border_hwnd(hwnd);
    }
    result
}

fn icon_action(
    ui: &mut egui::Ui,
    codepoint: u32,
    glyph_size: f32,
    hit_size: f32,
    idle: Color32,
) -> egui::Response {
    icon_action_with_enabled(ui, codepoint, glyph_size, hit_size, idle, true)
}

fn icon_action_with_enabled(
    ui: &mut egui::Ui,
    codepoint: u32,
    glyph_size: f32,
    hit_size: f32,
    idle: Color32,
    interactive: bool,
) -> egui::Response {
    let sense = if interactive {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(hit_size), sense);
    let hovered = interactive && response.hovered();
    let center = rect.center();
    ui.painter().circle_filled(
        center,
        hit_size * 0.5,
        if hovered {
            Color32::from_rgba_unmultiplied(176, 134, 96, 94)
        } else {
            Color32::from_rgba_unmultiplied(255, 255, 255, 15)
        },
    );
    let glyph = char::from_u32(codepoint).unwrap_or('\u{f15c}').to_string();
    ui.painter().text(
        center,
        Align2::CENTER_CENTER,
        glyph,
        FontId::new(glyph_size, FontFamily::Name("Medeo Icons".into())),
        if hovered { WHITE } else { idle },
    );
    response
}

fn window_controls(ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    let maximized = ctx.input(|input| input.viewport().maximized.unwrap_or(false));
    if window_control(ui, WindowControl::Close, false).clicked() {
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }
    if window_control(ui, WindowControl::Maximize, maximized).clicked() {
        ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
    }
    if window_control(ui, WindowControl::Minimize, false).clicked() {
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
    }
}

fn apply_theme(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "medeo-sans".to_owned(),
        egui::FontData::from_static(include_bytes!(
            "../assets/fonts/medeo/MedeoSans-Regular.ttf"
        ))
        .into(),
    );
    fonts.font_data.insert(
        "medeo-mono".to_owned(),
        egui::FontData::from_static(include_bytes!(
            "../assets/fonts/medeo/MedeoMono-Regular.ttf"
        ))
        .into(),
    );
    fonts.font_data.insert(
        "medeo-icons".to_owned(),
        egui::FontData::from_static(include_bytes!(
            "../assets/fonts/medeo/MedeoMonoNerdFontMono-Regular.ttf"
        ))
        .into(),
    );
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "medeo-sans".to_owned());
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .insert(0, "medeo-mono".to_owned());
    fonts.families.insert(
        FontFamily::Name("Medeo Icons".into()),
        vec!["medeo-icons".to_owned()],
    );
    ctx.set_fonts(fonts);

    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = Color32::TRANSPARENT;
    style.visuals.window_fill = SURFACE_RAISED;
    style.visuals.window_shadow = popup_shadow();
    style.visuals.extreme_bg_color = Color32::from_rgb(17, 18, 23);
    style.visuals.faint_bg_color = Color32::from_rgb(43, 43, 49);
    style.visuals.override_text_color = Some(WHITE);
    style.visuals.widgets.noninteractive.bg_fill = SURFACE;
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, MUTED);
    style.visuals.widgets.noninteractive.corner_radius = CornerRadius::same(10);
    style.visuals.widgets.inactive.bg_fill = SURFACE_RAISED;
    style.visuals.widgets.inactive.bg_stroke = Stroke::NONE;
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, WHITE);
    style.visuals.widgets.inactive.corner_radius = CornerRadius::same(10);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(58, 55, 52);
    style.visuals.widgets.hovered.bg_stroke = Stroke::NONE;
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, WHITE);
    style.visuals.widgets.hovered.corner_radius = CornerRadius::same(10);
    style.visuals.widgets.active.bg_fill = ACCENT;
    style.visuals.widgets.active.bg_stroke = Stroke::NONE;
    style.visuals.widgets.active.corner_radius = CornerRadius::same(10);
    style.visuals.widgets.open.bg_stroke = Stroke::NONE;
    style.visuals.widgets.open.corner_radius = CornerRadius::same(10);
    style.visuals.selection.bg_fill = ACCENT;
    style.visuals.selection.stroke = Stroke::new(1.0, WHITE);
    style.spacing.item_spacing = Vec2::new(10.0, 8.0);
    style.spacing.menu_margin = Margin::symmetric(10, 6);
    style.spacing.button_padding = Vec2::new(13.0, 9.0);
    style.spacing.interact_size.y = 34.0;
    // Thin bars remain unobtrusive and expand only while hovered. Floating keeps
    // their appearance from changing the scroll viewport width mid-scroll.
    style.spacing.scroll = egui::style::ScrollStyle::floating();
    style.visuals.window_corner_radius = CornerRadius::same(6);
    style.text_styles.insert(
        egui::TextStyle::Heading,
        FontId::new(23.0, FontFamily::Proportional),
    );
    ctx.set_style_of(egui::Theme::Dark, style);
}

fn filled_button(
    ui: &mut egui::Ui,
    text: &str,
    size: [f32; 2],
    fill: Color32,
    text_color: Color32,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(size[0], size[1]), egui::Sense::click());
    let color = if response.is_pointer_button_down_on() {
        fill
    } else if response.hovered() {
        if fill == ACCENT {
            GOLD
        } else {
            lighten_color(fill, 20)
        }
    } else {
        fill
    };
    let label_color =
        if fill == ACCENT && response.hovered() && !response.is_pointer_button_down_on() {
            SURFACE
        } else {
            text_color
        };
    ui.painter().rect_filled(rect, CornerRadius::same(7), color);
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        text,
        FontId::new(12.0, FontFamily::Proportional),
        label_color,
    );
    response
}

fn lighten_color(color: Color32, amount: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(
        color.r().saturating_add(amount),
        color.g().saturating_add(amount),
        color.b().saturating_add(amount),
        color.a(),
    )
}

fn filled_icon_button(
    ui: &mut egui::Ui,
    icon: u32,
    size: [f32; 2],
    fill: Color32,
    icon_color: Color32,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(size[0], size[1]), egui::Sense::click());
    let color = if response.is_pointer_button_down_on() {
        fill
    } else if response.hovered() {
        if fill == ACCENT {
            GOLD
        } else {
            lighten_color(fill, 20)
        }
    } else {
        fill
    };
    let label_color =
        if fill == ACCENT && response.hovered() && !response.is_pointer_button_down_on() {
            SURFACE
        } else {
            icon_color
        };
    ui.painter().rect_filled(rect, CornerRadius::same(7), color);
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        char::from_u32(icon).unwrap_or('\u{f15c}'),
        FontId::new(14.0, FontFamily::Name("Medeo Icons".into())),
        label_color,
    );
    response
}

fn action_button(ui: &mut egui::Ui, text: &str, primary: bool) -> egui::Response {
    let fill = if primary { ACCENT } else { SURFACE_RAISED };
    let text_width = ui
        .painter()
        .layout_no_wrap(
            text.to_owned(),
            FontId::new(12.0, FontFamily::Proportional),
            WHITE,
        )
        .size()
        .x;
    filled_button(ui, text, [text_width + 26.0, 34.0], fill, WHITE)
}

fn sidebar_icon_action(ui: &mut egui::Ui, width: f32, icon: u32, modified: bool) -> egui::Response {
    let height = 38.0;
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, height), egui::Sense::click());
    let center = rect.center();
    let painter = ui.painter();
    if response.hovered() || response.is_pointer_button_down_on() {
        painter.circle_filled(
            center,
            22.0,
            Color32::from_rgba_unmultiplied(176, 134, 96, 44),
        );
    }
    painter.circle_filled(
        center,
        19.0,
        if response.hovered() || response.is_pointer_button_down_on() {
            Color32::from_rgba_unmultiplied(176, 134, 96, 92)
        } else {
            Color32::from_rgba_unmultiplied(255, 255, 255, 18)
        },
    );
    painter.text(
        center,
        Align2::CENTER_CENTER,
        char::from_u32(icon).unwrap_or('\u{f15c}'),
        FontId::new(18.0, FontFamily::Name("Medeo Icons".into())),
        if response.hovered() { WHITE } else { SECONDARY },
    );
    if modified {
        painter.circle_filled(egui::pos2(center.x + 11.0, center.y - 11.0), 3.0, GOLD);
    }
    response
}

fn sidebar_create_action(
    ui: &mut egui::Ui,
    width: f32,
    title: &str,
    primary: bool,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 38.0), egui::Sense::click());
    let fill = if primary {
        if response.hovered() {
            GOLD
        } else {
            ACCENT
        }
    } else if response.hovered() {
        Color32::from_rgba_unmultiplied(255, 255, 255, 31)
    } else {
        Color32::from_rgba_unmultiplied(255, 255, 255, 18)
    };
    ui.painter().rect_filled(rect, CornerRadius::same(19), fill);
    let icon_color = if primary && response.hovered() {
        SURFACE
    } else if primary {
        WHITE
    } else {
        SECONDARY
    };
    let stroke = Stroke::new(1.6, icon_color);
    let icon_rect = egui::Rect::from_min_size(
        egui::pos2(rect.left() + 12.0, rect.center().y - 8.0),
        Vec2::splat(16.0),
    );
    if primary {
        ui.painter().line_segment(
            [
                icon_rect.center() - Vec2::new(0.0, 5.0),
                icon_rect.center() + Vec2::new(0.0, 5.0),
            ],
            stroke,
        );
        ui.painter().line_segment(
            [
                icon_rect.center() - Vec2::new(5.0, 0.0),
                icon_rect.center() + Vec2::new(5.0, 0.0),
            ],
            stroke,
        );
    } else {
        let p = |x: f32, y: f32| {
            egui::pos2(
                icon_rect.left() + x * icon_rect.width() / 24.0,
                icon_rect.top() + y * icon_rect.height() / 24.0,
            )
        };
        let folder = [
            p(3.0, 7.0),
            p(3.0, 7.0),
            p(3.0, 6.0),
            p(4.0, 5.0),
            p(9.0, 5.0),
            p(11.0, 7.0),
            p(19.0, 7.0),
            p(21.0, 9.0),
            p(21.0, 17.0),
            p(19.0, 19.0),
            p(5.0, 19.0),
            p(3.0, 17.0),
            p(3.0, 7.0),
        ];
        for pair in folder.windows(2) {
            ui.painter().line_segment([pair[0], pair[1]], stroke);
        }
        let plus_center = egui::pos2(p(12.0, 13.0).x, p(12.0, 13.0).y);
        ui.painter().line_segment(
            [
                plus_center - Vec2::new(0.0, 3.0),
                plus_center + Vec2::new(0.0, 3.0),
            ],
            stroke,
        );
        ui.painter().line_segment(
            [
                plus_center - Vec2::new(3.0, 0.0),
                plus_center + Vec2::new(3.0, 0.0),
            ],
            stroke,
        );
    }
    ui.painter().text(
        egui::pos2(rect.left() + 36.0, rect.center().y),
        Align2::LEFT_CENTER,
        title,
        FontId::new(12.0, FontFamily::Proportional),
        if primary { icon_color } else { WHITE },
    );
    response
}

fn form_field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    ui.label(RichText::new(label).size(12.0).color(SECONDARY));
    let width = ui.available_width();
    ui.add_sized(
        [width, 37.0],
        TextEdit::singleline(value)
            .hint_text(hint)
            .margin(Margin::symmetric(12, 8)),
    );
}

fn confirm_discard_changes() -> bool {
    rfd::MessageDialog::new()
        .set_title("Несохранённые изменения")
        .set_description("Продолжить без сохранения? Чтобы сохранить изменения, отмените действие и нажмите «Сохранить» или «Сохранить как».")
        .set_buttons(rfd::MessageButtons::YesNo)
        .set_level(rfd::MessageLevel::Warning)
        .show() == rfd::MessageDialogResult::Yes
}

fn sync_transfer_retryable(message: &str) -> bool {
    [5, 6, 7, 18, 28, 52, 55, 56].into_iter()
        .any(|code| message.starts_with(&format!("FTPS ({code}):")))
}

fn conflict_entry(ui: &mut egui::Ui, heading: &str, entry: Option<&keepass_rs::Entry>, folder: &str, reveal: bool) {
    ui.label(RichText::new(heading).size(15.0).strong().color(GOLD));
    let Some(entry) = entry else {
        ui.label("В этой копии записи нет");
        return;
    };
    let secret = |value: &str, protected: bool| {
        if protected && !reveal && !value.is_empty() { "••••••••".to_owned() }
        else { value.to_owned() }
    };
    let fields = [
        ("Название", entry.title.clone()),
        ("Папка", folder.to_owned()),
        ("Логин", entry.username.as_str().to_owned()),
        ("Пароль", secret(entry.password.as_str(), true)),
        ("Адрес", entry.url.clone()),
        ("Заметки", secret(entry.notes.as_str(), entry.notes.is_protected())),
        ("Теги", entry.tags.join(", ")),
        ("Создана", format_entry_time(entry.creation_time.as_millis())),
        ("Изменена", format_entry_time(entry.last_modification_time.as_millis())),
        ("Последний доступ", format_entry_time(entry.last_access_time.as_millis())),
        ("Срок действия", if entry.expires { format_entry_time(entry.expiry_time.as_millis()) } else { "Без срока".to_owned() }),
        ("Обращений", entry.usage_count.to_string()),
    ];
    for (label, value) in fields {
        conflict_field(ui, label, &value);
    }
    for field in &entry.custom_fields {
        conflict_field(ui, &field.name, &secret(field.value.as_str(), field.is_protected || field.value.is_protected()));
    }
    if !entry.binaries.is_empty() {
        let files = entry.binaries.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>().join(", ");
        conflict_field(ui, "Вложения", &files);
    }
    if !entry.history.is_empty() {
        conflict_field(ui, "Версий в истории", &entry.history.len().to_string());
    }
    if !entry.override_url.is_empty() {
        conflict_field(ui, "Переопределение адреса", &entry.override_url);
    }
    conflict_field(ui, "Автоввод", if entry.autotype_enabled { "Включён" } else { "Выключен" });
    if !entry.autotype_sequence.is_empty() {
        conflict_field(ui, "Последовательность автоввода", &secret(&entry.autotype_sequence, true));
    }
}

fn conflict_field(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).size(11.0).color(MUTED));
    ui.add(egui::Label::new(if value.is_empty() { "—" } else { value }).wrap());
    ui.add_space(4.0);
}

fn file_sha256(path: &std::path::Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn format_entry_time(millis: Option<i64>) -> String {
    millis
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map(|time| {
            time.with_timezone(&chrono::Local)
                .format("%d-%b-%y %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| "—".to_string())
}

fn url_domain(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return "—".to_string();
    }
    let parsed = url::Url::parse(value).or_else(|_| url::Url::parse(&format!("https://{value}")));
    parsed
        .ok()
        .and_then(|url| {
            url.host_str()
                .map(|host| host.trim_start_matches("www.").to_string())
        })
        .unwrap_or_else(|| value.to_string())
}

fn parse_tags(value: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    value
        .split([',', ';'])
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .filter(|tag| seen.insert(tag.to_lowercase()))
        .map(str::to_string)
        .collect()
}

fn entry_tooltip_field(ui: &mut egui::Ui, glyph: u32, value: &str) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 16.0), egui::Sense::hover());
    let painter = ui.painter().with_clip_rect(rect);
    painter.text(
        egui::pos2(rect.left() + 2.0, rect.center().y),
        Align2::LEFT_CENTER,
        char::from_u32(glyph).unwrap_or_default().to_string(),
        FontId::new(10.0, FontFamily::Name("Medeo Icons".into())),
        GOLD,
    );
    painter.text(
        egui::pos2(rect.left() + 20.0, rect.center().y),
        Align2::LEFT_CENTER,
        value,
        FontId::new(10.5, FontFamily::Proportional),
        SECONDARY,
    );
}

fn entry_metadata_field(ui: &mut egui::Ui, label: &str, value: &str, mono: bool) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{label}:")).size(11.0).color(MUTED));
        let text = RichText::new(value).size(11.0).color(SECONDARY);
        ui.label(if mono { text.monospace() } else { text });
    });
}

fn popup_shadow() -> egui::Shadow {
    egui::Shadow {
        offset: [0, 10],
        blur: 32,
        spread: 2,
        color: Color32::from_black_alpha(170),
    }
}

fn modal_header(ui: &mut egui::Ui, title: &str) {
    let radius = CornerRadius {
        nw: 20,
        ne: 20,
        sw: 0,
        se: 0,
    };
    Frame::new()
        .fill(Color32::from_rgb(32, 33, 40))
        .corner_radius(radius)
        .inner_margin(Margin::symmetric(18, 3))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add_sized(
                [ui.available_width(), 32.0],
                egui::Label::new(RichText::new(title).size(13.0).strong().color(WHITE))
                    .halign(Align::Center),
            );
        });
}

fn choose_icon_image(title: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(path) = rfd::FileDialog::new()
        .set_title(title)
        .add_filter("Изображения", &["png", "jpg", "jpeg", "bmp", "ico"])
        .pick_file()
    else {
        return Ok(None);
    };
    let bytes = std::fs::read(path)?;
    Ok(Some(vault::encode_icon_png(&bytes)?))
}

fn generate_password() -> anyhow::Result<Zeroizing<String>> {
    const DIGITS: &[u8] = b"0123456789";
    const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}?";
    const ALL: &[u8] =
        b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_=+[]{}?";

    let mut password = Vec::with_capacity(12);
    for set in [DIGITS, LOWERCASE, UPPERCASE, SYMBOLS] {
        password.push(set[random_index(set.len())?]);
    }
    while password.len() < 12 {
        password.push(ALL[random_index(ALL.len())?]);
    }
    for index in (1..password.len()).rev() {
        let swap_index = random_index(index + 1)?;
        password.swap(index, swap_index);
    }
    Ok(Zeroizing::new(String::from_utf8(password)?))
}

fn random_index(upper_bound: usize) -> anyhow::Result<usize> {
    let accepted_limit = 256 - (256 % upper_bound);
    loop {
        let mut byte = [0u8; 1];
        getrandom::getrandom(&mut byte)?;
        if (byte[0] as usize) < accepted_limit {
            return Ok(byte[0] as usize % upper_bound);
        }
    }
}

fn protect_ftps_input(value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    let secret = if let Some((_, encoded)) = value.rsplit_once("pass64=") {
        Zeroizing::new(
            STANDARD
                .decode(encoded.trim())
                .context("В строке подключения некорректно закодирован pass64")?,
        )
    } else {
        Zeroizing::new(value.as_bytes().to_vec())
    };
    if secret.is_empty() {
        anyhow::bail!("Пароль FTPS пустой");
    }
    Ok(STANDARD.encode(storage::protect_secret(&secret)?))
}

fn settings_nav_button(ui: &mut egui::Ui, label: &str, icon: u32, selected: bool) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(184.0, 44.0), egui::Sense::click());
    let fill = if selected { ACCENT } else if response.hovered() { SURFACE_RAISED } else { SURFACE };
    ui.painter().rect_filled(rect, CornerRadius::same(10), fill);
    ui.painter().text(
        egui::pos2(rect.left() + 14.0, rect.center().y),
        Align2::LEFT_CENTER,
        char::from_u32(icon).unwrap_or('?').to_string(),
        FontId::new(15.0, FontFamily::Name("Medeo Icons".into())),
        if selected { WHITE } else { SECONDARY },
    );
    ui.painter().text(
        egui::pos2(rect.left() + 42.0, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        FontId::proportional(13.0),
        WHITE,
    );
    response
}

fn icon_text(codepoint: u32, size: f32, color: Color32) -> RichText {
    let glyph = char::from_u32(codepoint).unwrap_or('\u{f15c}').to_string();
    RichText::new(glyph)
        .font(FontId::new(size, FontFamily::Name("Medeo Icons".into())))
        .color(color)
}

fn standard_icon_choices() -> Vec<(u32, u32)> {
    (0..69).map(|id| (id, standard_icon_glyph(id))).collect()
}

fn standard_icon_glyph(id: u32) -> u32 {
    const GLYPHS: [u32; 69] = [
        0xf084, 0xf0ac, 0xf071, 0xf108, 0xf114, 0xf007, 0xf187, 0xf15c, 0xf0e0, 0xf044, 0xf023,
        0xf09c, 0xf005, 0xf015, 0xf0c7, 0xf02f, 0xf132, 0xf02d, 0xf030, 0xf001, 0xf008, 0xf10b,
        0xf109, 0xf0b1, 0xf0c3, 0xf0ad, 0xf0e3, 0xf1e6, 0xf0eb, 0xf0a2, 0xf08d, 0xf041, 0xf14e,
        0xf04b, 0xf013, 0xf233, 0xf0ea, 0xf0d6, 0xf17a, 0xf095, 0xf07a, 0xf09d, 0xf2db, 0xf1b9,
        0xf072, 0xf1ad, 0xf0f8, 0xf19d, 0xf07b, 0xf07c, 0xf1b3, 0xf06c, 0xf0f6, 0xf2c2, 0xf140,
        0xf02b, 0xf002, 0xf12e, 0xf0c6, 0xf155, 0xf201, 0xf006, 0xf17c, 0xf52d, 0xf179, 0xf266,
        0xf06e, 0xf0d0, 0xf086,
    ];
    GLYPHS.get(id as usize).copied().unwrap_or(0xf15c)
}

#[cfg(test)]
mod icon_choice_tests {
    use super::*;

    #[test]
    fn gallery_has_one_choice_per_visual_icon() {
        let choices = standard_icon_choices();
        let unique: HashSet<u32> = choices.iter().map(|(_, glyph)| *glyph).collect();
        assert_eq!(choices.len(), 69);
        assert_eq!(choices.len(), unique.len());
        assert_eq!(
            choices
                .iter()
                .find(|(_, glyph)| *glyph == 0xf084)
                .unwrap()
                .0,
            0
        );
    }
}

fn paint_background(ctx: &egui::Context, acrylic_available: bool, database_open: bool) {
    let rect = ctx.content_rect();
    let painter = ctx.layer_painter(egui::LayerId::background());
    let radius = if ctx.input(|input| input.viewport().maximized.unwrap_or(false)) {
        CornerRadius::ZERO
    } else {
        CornerRadius::same(WINDOW_RADIUS)
    };
    painter.rect_filled(
        rect,
        radius,
        if acrylic_available {
            Color32::from_rgba_unmultiplied(29, 30, 37, if database_open { 182 } else { 16 })
        } else {
            Color32::from_rgb(29, 30, 37)
        },
    );
}

fn paint_grain(painter: &egui::Painter, grain: &TextureHandle, rect: egui::Rect, opacity: f32) {
    let tile_count = rect.size() / 96.0;
    painter.image(
        grain.id(),
        rect,
        egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(tile_count.x, tile_count.y)),
        Color32::from_white_alpha((opacity.clamp(0.0, 1.0) * 255.0).round() as u8),
    );
}

fn paint_panel_grain(
    painter: &egui::Painter,
    grain: &TextureHandle,
    rect: egui::Rect,
    left_rounded: bool,
    corner: u8,
) {
    if corner == 0 {
        paint_grain(painter, grain, rect, 0.045);
        return;
    }
    let inset = corner as f32;
    let (wide, narrow) = if left_rounded {
        (
            egui::Rect::from_min_max(
                egui::pos2(rect.left() + inset, rect.top()),
                rect.right_bottom(),
            ),
            egui::Rect::from_min_max(
                egui::pos2(rect.left(), rect.top() + inset),
                egui::pos2(rect.left() + inset, rect.bottom() - inset),
            ),
        )
    } else {
        (
            egui::Rect::from_min_max(
                rect.left_top(),
                egui::pos2(rect.right() - inset, rect.bottom()),
            ),
            egui::Rect::from_min_max(
                egui::pos2(rect.right() - inset, rect.top() + inset),
                egui::pos2(rect.right(), rect.bottom() - inset),
            ),
        )
    };
    paint_grain(painter, grain, wide, 0.045);
    paint_grain(painter, grain, narrow, 0.045);
}

fn grain_image() -> egui::ColorImage {
    let side = 96usize;
    let mut pixels = Vec::with_capacity(side * side);
    let mut state = 0x8C9DAD7Au32;
    for _ in 0..side * side {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let alpha = if state & 1 == 0 { 42 } else { 28 };
        let shade = if state & 2 == 0 { 240 } else { 20 };
        pixels.push(Color32::from_rgba_unmultiplied(shade, shade, shade, alpha));
    }
    egui::ColorImage::new([side, side], pixels)
}

fn custom_icon_texture(
    ui: &mut egui::Ui,
    cache: &mut HashMap<String, TextureHandle>,
    bytes: &[u8],
) -> Option<egui::TextureId> {
    let digest = Sha256::digest(bytes);
    let key: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    if !cache.contains_key(&key) {
        if let Ok(image) = image::load_from_memory(bytes) {
            let rgba = image
                .resize(128, 128, image::imageops::FilterType::Lanczos3)
                .to_rgba8();
            let color = egui::ColorImage::from_rgba_unmultiplied(
                [rgba.width() as usize, rgba.height() as usize],
                rgba.as_raw(),
            );
            let texture =
                ui.ctx()
                    .load_texture(format!("vault-icon-{key}"), color, TextureOptions::LINEAR);
            cache.insert(key.clone(), texture);
        }
    }
    cache.get(&key).map(TextureHandle::id)
}

fn show_custom_icon(
    ui: &mut egui::Ui,
    cache: &mut HashMap<String, TextureHandle>,
    bytes: &[u8],
    size: f32,
) {
    if let Some(texture) = custom_icon_texture(ui, cache, bytes) {
        ui.image((texture, Vec2::splat(size)));
    } else {
        ui.label(icon_text(0xf03e, size * 0.7, GOLD));
    }
}

fn paint_icon_badge(
    ui: &mut egui::Ui,
    rect: egui::Rect,
    custom_icon: Option<&[u8]>,
    glyph: u32,
    cache: &mut HashMap<String, TextureHandle>,
    highlighted: bool,
) {
    let center = rect.center();
    let painter = ui.painter();
    paint_badge_background(painter, rect, highlighted);
    if let Some(texture) = custom_icon.and_then(|bytes| custom_icon_texture(ui, cache, bytes)) {
        let icon_rect = egui::Rect::from_center_size(center, Vec2::splat(rect.width() * 0.56));
        ui.painter().image(
            texture,
            icon_rect,
            egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
            WHITE,
        );
    } else {
        paint_standard_icon_glyph(ui.painter(), rect, glyph, highlighted);
    }
}

fn paint_standard_icon_badge(
    painter: &egui::Painter,
    rect: egui::Rect,
    glyph: u32,
    highlighted: bool,
) {
    paint_badge_background(painter, rect, highlighted);
    paint_standard_icon_glyph(painter, rect, glyph, highlighted);
}

fn paint_badge_background(painter: &egui::Painter, rect: egui::Rect, highlighted: bool) {
    let center = rect.center();
    if highlighted {
        painter.circle_filled(
            center,
            rect.width() * 0.58,
            Color32::from_rgba_unmultiplied(176, 134, 96, 40),
        );
        painter.circle_filled(center, rect.width() * 0.47, ACCENT);
    } else {
        painter.circle_filled(
            center,
            rect.width() * 0.47,
            Color32::from_rgba_unmultiplied(255, 255, 255, 18),
        );
    }
}

fn paint_standard_icon_glyph(
    painter: &egui::Painter,
    rect: egui::Rect,
    glyph: u32,
    highlighted: bool,
) {
    let center = rect.center();
    let color = if highlighted { WHITE } else { SECONDARY };
    if glyph == 0xf1c0 {
        paint_database_symbol(painter, center, rect.width() * 0.56, color);
    } else if glyph == 0xf084 {
        paint_key_symbol(painter, center, rect.width(), color);
    } else {
        painter.text(
            center,
            Align2::CENTER_CENTER,
            char::from_u32(glyph).unwrap_or('\u{f15c}'),
            FontId::new(15.0, FontFamily::Name("Medeo Icons".into())),
            color,
        );
    }
}

fn paint_database_symbol(painter: &egui::Painter, center: egui::Pos2, size: f32, color: Color32) {
    let unit = size / 18.0;
    let radius_x = 6.0 * unit;
    let radius_y = 2.25 * unit;
    let top_y = center.y - 4.5 * unit;
    let bottom_y = center.y + 4.5 * unit;
    let stroke = Stroke::new(1.4 * unit, color);
    let arc = |y: f32, start: f32, end: f32| {
        let steps = 12;
        for step in 0..steps {
            let first = start + (end - start) * step as f32 / steps as f32;
            let second = start + (end - start) * (step + 1) as f32 / steps as f32;
            let point = |angle: f32| {
                egui::pos2(
                    center.x + radius_x * angle.cos(),
                    y + radius_y * angle.sin(),
                )
            };
            painter.line_segment([point(first), point(second)], stroke);
        }
    };
    arc(top_y, 0.0, std::f32::consts::TAU);
    painter.line_segment(
        [
            egui::pos2(center.x - radius_x, top_y),
            egui::pos2(center.x - radius_x, bottom_y),
        ],
        stroke,
    );
    painter.line_segment(
        [
            egui::pos2(center.x + radius_x, top_y),
            egui::pos2(center.x + radius_x, bottom_y),
        ],
        stroke,
    );
    arc(center.y, 0.0, std::f32::consts::PI);
    arc(bottom_y, 0.0, std::f32::consts::PI);
}

fn paint_key_symbol(painter: &egui::Painter, center: egui::Pos2, size: f32, color: Color32) {
    let unit = size / 26.0;
    let ring_center = center + Vec2::new(-4.0 * unit, 0.0);
    let stroke = Stroke::new(1.7 * unit, color);
    painter.circle_stroke(ring_center, 3.2 * unit, stroke);
    painter.line_segment(
        [
            ring_center + Vec2::new(3.2 * unit, 0.0),
            center + Vec2::new(7.0 * unit, 0.0),
        ],
        stroke,
    );
    for x in [3.5, 6.5] {
        painter.line_segment(
            [
                center + Vec2::new(x * unit, 0.0),
                center + Vec2::new(x * unit, 3.0 * unit),
            ],
            stroke,
        );
    }
}
