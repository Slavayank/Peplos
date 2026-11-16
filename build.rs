use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo provides the project path"));
    let icon = manifest.join("assets").join("peplos-icon.ico");
    println!("cargo:rerun-if-changed={}", icon.display());
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let out_dir =
            PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides an output directory"));
        let resource_script = out_dir.join("peplos-icon.rc");
        let resource_file = out_dir.join("peplos-icon.res");
        let escaped_icon = icon
            .display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let version = env::var("CARGO_PKG_VERSION").expect("package version");
        let parts: Vec<&str> = version.split('.').collect();
        let version_numbers = format!("{},{},{},0", parts.first().unwrap_or(&"0"), parts.get(1).unwrap_or(&"0"), parts.get(2).unwrap_or(&"0"));
        let resource = format!(r#"1 ICON "{escaped_icon}"
1 VERSIONINFO
FILEVERSION {version_numbers}
PRODUCTVERSION {version_numbers}
FILEOS 0x40004
FILETYPE 0x1
BEGIN
 BLOCK "StringFileInfo"
 BEGIN
  BLOCK "040904B0"
  BEGIN
   VALUE "FileDescription", "Peplos password manager\0"
   VALUE "FileVersion", "{version}\0"
   VALUE "ProductName", "Peplos\0"
   VALUE "ProductVersion", "{version}\0"
  END
 END
 BLOCK "VarFileInfo"
 BEGIN
  VALUE "Translation", 0x409, 1200
 END
END
"#);
        fs::write(&resource_script, resource)
            .expect("write the icon resource script");
        println!("cargo:rerun-if-changed={}", resource_script.display());

        let architecture = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
            Ok("x86_64") => "x64",
            Ok("aarch64") => "arm64",
            Ok("x86") => "x86",
            _ => "x64",
        };
        let rc = find_resource_compiler(architecture)
            .expect("Windows SDK resource compiler rc.exe is required to embed the app icon");
        let output = Command::new(rc)
            .arg("/nologo")
            .arg(format!("/fo{}", resource_file.display()))
            .arg(&resource_script)
            .output()
            .expect("start the Windows resource compiler");
        if !output.status.success() {
            panic!(
                "Windows resource compiler failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        println!("cargo:rustc-link-arg={}", resource_file.display());
    }
}

fn find_resource_compiler(architecture: &str) -> Option<PathBuf> {
    if let Some(path) = env::var_os("RC")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
    {
        return Some(path);
    }

    let mut roots = Vec::new();
    if let Some(path) = env::var_os("WindowsSdkDir") {
        roots.push(PathBuf::from(path).join("bin"));
    }
    if let Some(program_files) = env::var_os("ProgramFiles(x86)") {
        roots.push(
            PathBuf::from(program_files)
                .join("Windows Kits")
                .join("10")
                .join("bin"),
        );
    }
    if let Some(program_files) = env::var_os("ProgramFiles") {
        roots.push(
            PathBuf::from(program_files)
                .join("Windows Kits")
                .join("10")
                .join("bin"),
        );
    }

    for root in roots {
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        let mut versions: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect();
        versions.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
        for version in versions {
            let candidate = version.join(architecture).join("rc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    find_on_path("rc.exe")
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    env::var_os("PATH")?
        .to_string_lossy()
        .split(';')
        .map(Path::new)
        .map(|dir| dir.join(name))
        .find(|path| path.is_file())
}
