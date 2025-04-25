//! Self-deploying installer for ZeroVault CLI.
//!
//! On the **first** run when the executable is **not** in the canonical
//! directory, this module:
//! 1. Copies the running exe to   ~/.zerovault/bin   (Windows: %USERPROFILE%\.zerovault\bin)
//! 2. Adds that directory to the user-level PATH (idempotent).
//! 3. Relaunches the program from its final location - so the user’s very
//!    first command already works.
//!
//! Subsequent runs detect they are already “installed” and return
//! immediately.

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Command, exit},
};

#[cfg(windows)]
const BIN_NAME: &str = "zerovault.exe";
#[cfg(not(windows))]
const BIN_NAME: &str = "zerovault";

pub(crate) fn ensure_installed() {
    if let Err(e) = inner() {
        eprintln!("⚠ ZeroVault self-install failed: {e}");
    }
}

fn inner() -> Result<(), Box<dyn std::error::Error>> {
    let current = env::current_exe()?;

    let target_dir: PathBuf = if cfg!(windows) {
        dirs::home_dir().unwrap().join(r".zerovault\bin")
    } else {
        dirs::home_dir().unwrap().join(".zerovault/bin")
    };
    let target_exe = target_dir.join(BIN_NAME);

    // already installed?
    if same_file::is_same_file(&current, &target_exe).unwrap_or(false) {
        return Ok(());
    }

    fs::create_dir_all(&target_dir)?;
    fs::copy(&current, &target_exe)?;

    #[cfg(windows)]
    add_to_path_windows(&target_dir)?;

    #[cfg(not(windows))]
    add_to_path_unix(&target_dir)?;

    println!("✔ ZeroVault installed to {}\n⟳ Relaunching …", target_dir.display());

    Command::new(&target_exe)
        .args(env::args().skip(1))
        .spawn()?;
    exit(0);
}

#[cfg(windows)]
fn add_to_path_windows(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use winreg::{RegKey, enums::*};

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (env_key, _) = hkcu.create_subkey("Environment")?;
    let mut path: String = env_key.get_value("Path").unwrap_or_default();

    let dir_s = dir.to_string_lossy();
    if !path.to_lowercase().contains(&dir_s.to_lowercase()) {
        if !path.ends_with(';') && !path.is_empty() {
            path.push(';');
        }
        path.push_str(&dir_s);
        env_key.set_value("Path", &path)?;
        println!("ℹ Added {} to user PATH (restart shell to pick up)", dir.display());
    }
    Ok(())
}

#[cfg(not(windows))]
use std::io::Write;

fn add_to_path_unix(dir: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let export = format!("export PATH=\"{}:$PATH\" # added by ZeroVault", dir.display());
    if std::env::var_os("PATH")
        .map(|p| p.to_string_lossy().split(':').any(|e| e == dir.to_string_lossy()))
        .unwrap_or(false)
    {
        return Ok(());     // already present
    }

    let rc_files = [".bashrc", ".zshrc", ".profile"];
    for rc in rc_files {
        if let Some(p) = dirs::home_dir().map(|h| h.join(rc)) {
            if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&p) {
                writeln!(f, "\n# --- ZeroVault installer ---\n{export}\n")?;
                println!("ℹ️ Added {} to PATH in {}", dir.display(), p.display());
                break;
            }
        }
    }
    Ok(())
}