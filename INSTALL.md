# ZeroVault Installation Guide

This document provides comprehensive installation instructions for ZeroVault across all supported platforms.

## Table of Contents

- [Automatic Installation](#automatic-installation)
- [Platform-Specific Installation](#platform-specific-installation)
  - [Windows](#windows)
  - [Linux](#linux)
- [Package Managers](#package-managers)
- [Installation Verification](#installation-verification)
- [Troubleshooting](#troubleshooting)
- [Building from Source](#building-from-source)
- [Uninstallation](#uninstallation)

## Automatic Installation

ZeroVault features a self-installation mechanism that automatically sets everything up the first time you run it.

### How It Works

1. Download the executable for your platform
2. Run any ZeroVault command
3. The program automatically:
   - Copies itself to `~/.zerovault/bin/` (or `%USERPROFILE%\.zerovault\bin` on Windows)
   - Adds this location to your PATH
   - Continues executing your original command

You'll see a brief message during this process:
```
✔ ZeroVault installed to /Users/username/.zerovault/bin
⟳ Relaunching …
```

After this one-time setup, you can run `zerovault` from anywhere without specifying the path.

## Platform-Specific Installation

### Windows

#### Option 1: Automatic Installation (Recommended)

1. Download the executable:
   ```
   curl.exe -L -o zerovault.exe https://github.com/ParleSec/zerovault/releases/latest/download/zerovault-windows-amd64.exe
   ```
   
   Or download directly from your browser: [zerovault-windows-amd64.exe](https://github.com/ParleSec/zerovault/releases/latest/download/zerovault-windows-amd64.exe)

2. Run the executable (it will self-install):
   ```
   .\zerovault.exe --help
   ```

3. Restart your Command Prompt or PowerShell to recognize PATH changes

#### Option 2: Manual Installation

1. Download the executable as above
2. Create a directory for ZeroVault:
   ```
   mkdir "%USERPROFILE%\.zerovault\bin"
   ```
3. Move the executable:
   ```
   move zerovault.exe "%USERPROFILE%\.zerovault\bin"
   ```
4. Add to PATH (in PowerShell):
   ```powershell
   $env:Path += ";$env:USERPROFILE\.zerovault\bin"
   [Environment]::SetEnvironmentVariable("Path", $env:Path, "User")
   ```

### Linux

#### Option 1: Automatic Installation (Recommended)

1. Download the appropriate executable:

   Maximum compatibility (static binary):
   ```bash
   curl -L -o zerovault https://github.com/ParleSec/zerovault/releases/latest/download/zerovault-linux-musl-amd64
   ```

2. Make it executable:
   ```bash
   chmod +x zerovault
   ```

3. Run the executable (it will self-install):
   ```bash
   ./zerovault --help
   ```

4. Open a new terminal window to recognize PATH changes


#### Option 3: Manual Installation

1. Download and make executable as above
2. Create the destination directory:
   ```bash
   mkdir -p ~/.zerovault/bin
   ```
3. Move the executable:
   ```bash
   mv zerovault ~/.zerovault/bin/
   ```
4. Add to your PATH by adding this line to your `~/.bashrc` or `~/.profile`:
   ```bash
   export PATH="$HOME/.zerovault/bin:$PATH"
   ```
5. Reload your shell configuration:
   ```bash
   source ~/.bashrc  # or ~/.profile
   ```

## Installation Verification

Verify that ZeroVault is correctly installed:

```bash
zerovault --version
```

You should see output displaying the version number, like:

```
zerovault 1.0.0
```

You can also run a self-test:

```bash
zerovault test
```

This will perform encryption/decryption tests to ensure everything is working correctly.

## Troubleshooting

### PATH Issues

If you get a "command not found" error after installation:

**Windows**:
1. Restart your Command Prompt/PowerShell
2. Verify the PATH includes ZeroVault:
   ```powershell
   $env:Path
   ```
3. If needed, manually add to PATH:
   ```powershell
   [Environment]::SetEnvironmentVariable("Path", "$env:Path;$env:USERPROFILE\.zerovault\bin", "User")
   ```

**Linux**:
1. Restart your terminal session
2. Verify the PATH includes ZeroVault:
   ```bash
   echo $PATH
   ```
3. If needed, manually add to PATH in your shell configuration file:
   ```bash
   echo 'export PATH="$HOME/.zerovault/bin:$PATH"' >> ~/.bashrc
   source ~/.bashrc
   ```

### Permission Issues

**Linux**:
1. If you get a permission error:
   ```bash
   chmod +x ~/.zerovault/bin/zerovault
   ```

### Installation Failure

If automatic installation fails:

1. Try the manual installation steps for your platform
2. Check file permissions in the destination directory
3. Ensure you have write access to the destination directory
4. For package manager installations, ensure you have admin privileges

## Building from Source

### Prerequisites

- Rust 1.70 or higher
- Cargo build tools
- Git

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/ParleSec/zerovault
   cd zerovault
   ```

2. Build and install with Cargo:
   ```bash
   cargo install --path .
   ```

3. Verify installation:
   ```bash
   zerovault --version
   ```

### Build Options

For optimized performance:
```bash
cargo install --path . --release
```

For cross-compilation to other platforms:
```bash
# Install target
rustup target add x86_64-pc-windows-msvc

# Build
cargo build --release --target x86_64-pc-windows-msvc
```

### Common Build Issues

- **Missing dependencies**: Install the build essentials for your platform
  - Debian/Ubuntu: `sudo apt install build-essential`
  - CentOS/RHEL: `sudo yum groupinstall "Development Tools"`
  - Windows: Install Visual Studio Build Tools
  
- **OpenSSL issues**: Install the OpenSSL development package
  - Debian/Ubuntu: `sudo apt install libssl-dev pkg-config`
  - CentOS/RHEL: `sudo yum install openssl-devel`

## Uninstallation

### Automatic Installation

**Windows**:
1. Delete the directory:
   ```
   rmdir /s /q "%USERPROFILE%\.zerovault"
   ```
2. Remove from PATH (PowerShell):
   ```powershell
   $path = [Environment]::GetEnvironmentVariable("Path", "User")
   $path = $path -replace "$env:USERPROFILE\\\.zerovault\\bin;", ""
   [Environment]::SetEnvironmentVariable("Path", $path, "User")
   ```

**Linux**:
1. Delete the directory:
   ```bash
   rm -rf ~/.zerovault
   ```
2. Remove the PATH entry from your shell configuration file (`~/.bashrc`, `~/.zshrc`, or `~/.profile`)

### Package Manager Installation

**Homebrew**:
```bash
brew uninstall zerovault
```

**Debian/Ubuntu**:
```bash
sudo dpkg -r zerovault
```

**Cargo Installation**:
```bash
cargo uninstall zerovault
```
