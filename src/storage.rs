use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecentDatabase {
    pub path: String,
    pub name: String,
    pub last_opened: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub remote_directory: String,
    pub password_dpapi: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SyncState {
    pub last_success: Option<u64>,
    pub last_uploaded_sha256: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppSettings {
    #[serde(default)]
    pub recent_databases: Vec<RecentDatabase>,
    #[serde(default)]
    pub database_sync: HashMap<String, SyncConfig>,
    #[serde(default)]
    pub sync_state: HashMap<String, SyncState>,
    // Migrate the pre-per-database global FTPS value to only the most
    // recently opened database. It is deliberately never written again.
    #[serde(default, rename = "sync", skip_serializing)]
    legacy_sync: Option<SyncConfig>,
}

impl AppSettings {
    pub fn load() -> Self {
        let Ok(path) = settings_file() else {
            return Self::default();
        };
        let mut settings: Self = fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        if let Some(sync) = settings.legacy_sync.take() {
            if let Some(recent) = settings.recent_databases.first() {
                settings
                    .database_sync
                    .entry(database_key(Path::new(&recent.path)))
                    .or_insert(sync);
            }
        }
        settings
    }

    pub fn save(&self) -> Result<()> {
        let path = settings_file()?;
        let parent = path
            .parent()
            .context("Не удалось определить папку настроек")?;
        fs::create_dir_all(parent)?;
        let temp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)?;
        fs::write(&temp, bytes)?;
        fs::rename(&temp, &path)
            .with_context(|| format!("Не удалось сохранить настройки Peplos: {}", path.display()))
    }

    pub fn remember_database(&mut self, path: &std::path::Path) {
        let full = path.to_string_lossy().to_string();
        self.recent_databases
            .retain(|item| !item.path.eq_ignore_ascii_case(&full));
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&full)
            .to_string();
        let last_opened = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.recent_databases.insert(
            0,
            RecentDatabase {
                path: full,
                name,
                last_opened,
            },
        );
        self.recent_databases.truncate(8);
    }

    pub fn sync_for(&self, path: &Path) -> Option<&SyncConfig> {
        self.database_sync.get(&database_key(path))
    }

    pub fn set_sync_for(&mut self, path: &Path, sync: SyncConfig) {
        self.database_sync.insert(database_key(path), sync);
    }

    pub fn sync_state_for(&self, path: &Path) -> Option<&SyncState> {
        self.sync_state.get(&database_key(path))
    }

    pub fn set_sync_state_for(&mut self, path: &Path, state: SyncState) {
        self.sync_state.insert(database_key(path), state);
    }
}

fn database_key(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\").to_lowercase()
}

pub(crate) fn settings_file() -> Result<PathBuf> {
    let root = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .map(|p| PathBuf::from(p).join("AppData").join("Roaming"))
        })
        .context("Не удалось найти папку настроек Windows")?;
    Ok(root.join("Peplos").join("settings.json"))
}

pub fn protect_secret(plain: &[u8]) -> Result<Vec<u8>> {
    #[cfg(windows)]
    {
        dpapi(plain, true)
    }
    #[cfg(not(windows))]
    {
        let _ = plain;
        anyhow::bail!("Сохранение FTPS-пароля доступно в Windows")
    }
}

pub fn unprotect_secret(cipher: &[u8]) -> Result<zeroize::Zeroizing<String>> {
    #[cfg(windows)]
    {
        let bytes = zeroize::Zeroizing::new(dpapi(cipher, false)?);
        let value = std::str::from_utf8(&bytes)
            .context("Пароль FTPS повреждён")?
            .to_owned();
        Ok(zeroize::Zeroizing::new(value))
    }
    #[cfg(not(windows))]
    {
        let _ = cipher;
        anyhow::bail!("Расшифровка FTPS-пароля доступна в Windows")
    }
}

#[cfg(windows)]
fn dpapi(input: &[u8], protect: bool) -> Result<Vec<u8>> {
    use std::ptr;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };

    let mut source = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    unsafe {
        let ok = if protect {
            CryptProtectData(
                &mut source,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &mut source,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error())
                .context("Windows не смог защитить пароль синхронизации");
        }
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        if output.cbData != 0 {
            ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        }
        LocalFree(output.pbData as _);
        Ok(bytes)
    }
}
