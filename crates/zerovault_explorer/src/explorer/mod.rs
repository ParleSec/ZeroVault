use std::path::PathBuf;
use std::env;
use std::error::Error;

// Create submodules for platform-specific code
#[cfg(target_os = "windows")]
pub mod windows_explorer;

#[cfg(target_os = "macos")]
pub mod macos_explorer;

#[cfg(all(unix, not(target_os = "macos")))]
pub mod linux_explorer;

/// Install the explorer integration for the current platform
pub fn install_integration() -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    {
        return windows_explorer::install_integration();
    }
    
    #[cfg(target_os = "macos")]
    {
        return macos_explorer::install_integration();
    }
    
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return linux_explorer::install_integration();
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "macos", unix)))]
    {
        Err("Explorer integration is not supported on this platform".into())
    }
}

/// Uninstall the explorer integration for the current platform
pub fn uninstall_integration() -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    {
        return windows_explorer::uninstall_integration();
    }
    
    #[cfg(target_os = "macos")]
    {
        return macos_explorer::uninstall_integration();
    }
    
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return linux_explorer::uninstall_integration();
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "macos", unix)))]
    {
        Err("Explorer integration is not supported on this platform".into())
    }
}

/// Get the path to the current executable
pub fn get_executable_path() -> Result<PathBuf, Box<dyn Error>> {
    let exe_path = env::current_exe()?;
    Ok(exe_path)
}