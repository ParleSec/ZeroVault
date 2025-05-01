use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    
    // Windows-specific configuration for building as a GUI application
    #[cfg(target_os = "windows")]
    {
        // Check if building for Windows
        if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
            println!("cargo:rustc-link-arg=/SUBSYSTEM:WINDOWS");
            println!("cargo:rustc-link-arg=/ENTRY:mainCRTStartup");
            
            // Use embed-resource to include the Windows resource file if it exists
            if std::path::Path::new("zerovault.rc").exists() {
                // Use Vec<String> instead of empty slice to avoid type inference issues
                let empty_macros: Vec<String> = Vec::new();
                embed_resource::compile("zerovault.rc", &empty_macros);
            }
        }
    }
    
    // Generate build information
    built::write_built_file().expect("Failed to generate build information");
}