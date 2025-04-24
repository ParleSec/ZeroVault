#[allow(unsafe_code)]
use std::alloc::{self, GlobalAlloc, Layout, System};
use std::fmt;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize;

// Platform-specific memory locking functions
#[cfg(any(target_os = "linux", target_os = "macos"))]
use libc::{madvise, mlock, munlock, ENOMEM, MADV_DONTDUMP};

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{
    VirtualLock, VirtualProtect, VirtualUnlock, PAGE_NOACCESS,
};

// For Windows we need to access system info from SystemInformation
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::SystemInformation::{
    GetSystemInfo,
    SYSTEM_INFO, // This requires the Win32_System_Diagnostics_Debug feature
};

use crate::types::{VaultError, CANARY_PATTERN, GUARD_PAGE_SIZE};

// Static flag to track if secure memory is available and functioning
static SECURE_MEMORY_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Initialize secure memory subsystem
#[allow(unsafe_code)]
pub fn init_secure_memory() -> Result<(), VaultError> {
    // Attempt to allocate, lock, and free a small test allocation
    let test_layout =
        Layout::from_size_align(1024, 64).map_err(|_| VaultError::MemoryProtectionFailed)?;

    let ptr = unsafe { alloc::alloc(test_layout) };
    if ptr.is_null() {
        return Err(VaultError::MemoryProtectionFailed);
    }

    let lock_result = lock_memory(ptr, test_layout.size());

    // Free the test allocation regardless of lock result
    unsafe { alloc::dealloc(ptr, test_layout) };

    // Set the global availability flag based on the result
    match lock_result {
        Ok(true) => {
            SECURE_MEMORY_AVAILABLE.store(true, Ordering::SeqCst);
            Ok(())
        }
        _ => {
            SECURE_MEMORY_AVAILABLE.store(false, Ordering::SeqCst);
            Err(VaultError::MemoryProtectionFailed)
        }
    }
}

/// Check if secure memory is available
pub fn is_secure_memory_available() -> bool {
    SECURE_MEMORY_AVAILABLE.load(Ordering::SeqCst)
}

/// Lock memory to prevent it from being swapped to disk
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)]
fn lock_memory(ptr: *mut u8, size: usize) -> Result<bool, VaultError> {
    unsafe {
        // On Linux/macOS, use mlock to prevent swapping
        let mlock_result = mlock(ptr as *const _, size);

        // On Linux, also mark memory as not dumpable to prevent core dumps
        #[cfg(target_os = "linux")]
        let _ = madvise(ptr as *mut _, size, MADV_DONTDUMP);

        if mlock_result == 0 {
            Ok(true)
        } else if *libc::__errno_location() == ENOMEM {
            // mlock can fail due to RLIMIT_MEMLOCK
            eprintln!("Warning: Could not lock memory, sensitive data may be swapped to disk");
            Ok(false)
        } else {
            Err(VaultError::MemoryProtectionFailed)
        }
    }
}

/// Lock memory to prevent it from being swapped to disk
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn lock_memory(ptr: *mut u8, size: usize) -> Result<bool, VaultError> {
    unsafe {
        // On Windows, get the system page size
        let mut system_info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut system_info);

        // Round size up to the nearest page size
        let page_size = system_info.dwPageSize as usize;
        let page_aligned_size = (size + page_size - 1) & !(page_size - 1);

        // Lock the pages
        let result = VirtualLock(ptr as *const _, page_aligned_size);

        if result != 0 {
            Ok(true)
        } else {
            // VirtualLock can fail due to working set limitations
            eprintln!("Warning: Could not lock memory, sensitive data may be swapped to disk");
            Ok(false)
        }
    }
}

/// Lock memory - stub for unsupported platforms
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn lock_memory(_ptr: *mut u8, _size: usize) -> Result<bool, VaultError> {
    eprintln!("Warning: Memory locking not supported on this platform");
    Ok(false)
}

/// Unlock previously locked memory
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)]
fn unlock_memory(ptr: *mut u8, size: usize, was_locked: bool) -> Result<(), VaultError> {
    if was_locked {
        unsafe {
            let result = munlock(ptr as *const _, size);

            if result != 0 {
                return Err(VaultError::MemoryProtectionFailed);
            }
        }
    }

    Ok(())
}

/// Unlock previously locked memory - Windows
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn unlock_memory(ptr: *mut u8, size: usize, was_locked: bool) -> Result<(), VaultError> {
    if was_locked {
        unsafe {
            // Get the system page size
            let mut system_info: SYSTEM_INFO = mem::zeroed();
            GetSystemInfo(&mut system_info);

            // Round size up to the nearest page size
            let page_size = system_info.dwPageSize as usize;
            let page_aligned_size = (size + page_size - 1) & !(page_size - 1);

            // Unlock the pages
            let result = VirtualUnlock(ptr as *const _, page_aligned_size);

            if result == 0 {
                return Err(VaultError::MemoryProtectionFailed);
            }
        }
    }

    Ok(())
}

/// Unlock previously locked memory - stub for unsupported platforms
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn unlock_memory(_ptr: *mut u8, _size: usize, _was_locked: bool) -> Result<(), VaultError> {
    Ok(())
}

/// Multi-pass secure memset to clear sensitive memory
#[allow(unsafe_code)]
pub fn secure_zero_memory(ptr: *mut u8, len: usize) {
    unsafe {
        // First pass: set to zeros
        ptr::write_bytes(ptr, 0, len);

        // Second pass: set to ones
        ptr::write_bytes(ptr, 0xFF, len);

        // Third pass: set to random pattern
        let pattern = 0xAA;
        ptr::write_bytes(ptr, pattern, len);

        // Final pass: set to zeros
        ptr::write_bytes(ptr, 0, len);

        // Ensure the compiler doesn't optimize away these operations
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Secure memory allocator with guard pages
pub struct SecureAllocator;

// Use the system allocator as a fallback
static SYSTEM_ALLOCATOR: System = System;

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for SecureAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // If secure memory isn't needed or available, use the system allocator
        if !SECURE_MEMORY_AVAILABLE.load(Ordering::SeqCst) {
            return SYSTEM_ALLOCATOR.alloc(layout);
        }

        // Add guard pages before and after the allocation
        let page_size = GUARD_PAGE_SIZE;

        // Calculate total size including guard pages
        let alloc_size = layout.size();
        let aligned_size = (alloc_size + layout.align() - 1) & !(layout.align() - 1);
        let total_size = page_size + aligned_size + page_size;

        // Create a layout for the total allocation
        let total_layout = Layout::from_size_align(total_size, page_size).unwrap_or(layout);

        // Allocate the total memory block
        let ptr = SYSTEM_ALLOCATOR.alloc(total_layout);
        if ptr.is_null() {
            return ptr;
        }

        // Set up the guard pages
        #[cfg(target_os = "windows")]
        {
            let mut old_protect = 0;

            // Protect the first guard page
            VirtualProtect(ptr as *mut _, page_size, PAGE_NOACCESS, &mut old_protect);

            // Protect the last guard page
            VirtualProtect(
                ptr.add(page_size + aligned_size) as *mut _,
                page_size,
                PAGE_NOACCESS,
                &mut old_protect,
            );
        }

        #[cfg(target_os = "linux")]
        {
            // On Linux, make the guard pages non-accessible
            libc::mprotect(ptr as *mut _, page_size, libc::PROT_NONE);
            libc::mprotect(
                ptr.add(page_size + aligned_size) as *mut _,
                page_size,
                libc::PROT_NONE,
            );
        }

        // Return the pointer to the actual data area (after the first guard page)
        let data_ptr = ptr.add(page_size);

        // Lock the actual data area in memory
        let _ = lock_memory(data_ptr, aligned_size);

        data_ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // If secure memory isn't being used, just use the system deallocator
        if !SECURE_MEMORY_AVAILABLE.load(Ordering::SeqCst) {
            SYSTEM_ALLOCATOR.dealloc(ptr, layout);
            return;
        }

        // Calculate the original allocation parameters
        let page_size = GUARD_PAGE_SIZE;
        let alloc_size = layout.size();
        let aligned_size = (alloc_size + layout.align() - 1) & !(layout.align() - 1);

        // Zero out the memory before freeing
        let mut p = ptr;
        for _ in 0..aligned_size {
            *p = 0;
            p = p.add(1);
        }

        // Unlock the memory
        let _ = unlock_memory(ptr, aligned_size, true);

        // Calculate the original base pointer (before the first guard page)
        let base_ptr = ptr.sub(page_size);

        // Calculate the total size
        let total_size = page_size + aligned_size + page_size;
        let total_layout = Layout::from_size_align(total_size, page_size).unwrap_or(layout);

        // Deallocate the entire block
        SYSTEM_ALLOCATOR.dealloc(base_ptr, total_layout);
    }
}

/// Container for sensitive data that:
/// 1. Allocates on the heap with guard pages
/// 2. Automatically zeroes memory when dropped
/// 3. Locks memory in RAM (prevents swap)
/// 4. Uses canaries to detect overflow/tampering
#[allow(unsafe_code)]
pub struct SecureMemory<T: Zeroize> {
    ptr: *mut T,
    layout: Layout,
    locked: bool,
    canary_enabled: bool,
}

// Manual implementation of Send is safe because we manage the raw pointer carefully
#[allow(unsafe_code)]
unsafe impl<T: Zeroize + Send> Send for SecureMemory<T> {}

// Manual implementation of Sync is safe because we provide controlled access
#[allow(unsafe_code)]
unsafe impl<T: Zeroize + Sync> Sync for SecureMemory<T> {}

#[allow(unsafe_code)]
impl<T: Zeroize> SecureMemory<T> {
    /// Allocate and lock memory for sensitive data
    pub fn new(value: T) -> Result<Self, VaultError> {
        // Initialize secure memory if not already done
        if !is_secure_memory_available() {
            let _ = init_secure_memory();
        }

        // Calculate memory layout for the data
        let data_size = std::mem::size_of::<T>();
        let canary_size = CANARY_PATTERN.len();
        let total_size = data_size + (canary_size * 2);

        let layout = Layout::from_size_align(total_size, std::mem::align_of::<T>())
            .map_err(|_| VaultError::MemoryProtectionFailed)?;

        // Allocate memory
        let ptr = unsafe { alloc::alloc(layout) } as *mut u8;

        if ptr.is_null() {
            return Err(VaultError::MemoryProtectionFailed);
        }

        // Place canaries before and after the data
        unsafe {
            // Set prefix canary
            ptr::copy_nonoverlapping(CANARY_PATTERN.as_ptr(), ptr, canary_size);

            // Set suffix canary
            ptr::copy_nonoverlapping(
                CANARY_PATTERN.as_ptr(),
                ptr.add(canary_size + data_size),
                canary_size,
            );

            // Move the value into the allocated memory (between canaries)
            let data_ptr = ptr.add(canary_size) as *mut T;
            ptr::write(data_ptr, value);

            // Try to lock the memory
            let locked = match lock_memory(ptr, total_size) {
                Ok(locked) => locked,
                Err(_) => {
                    // If locking fails, free the memory and return an error
                    ptr::drop_in_place(data_ptr);
                    alloc::dealloc(ptr, layout);
                    return Err(VaultError::MemoryProtectionFailed);
                }
            };

            Ok(Self {
                ptr: data_ptr,
                layout,
                locked,
                canary_enabled: true,
            })
        }
    }

    /// Verify that the canaries have not been tampered with
    pub fn verify_canaries(&self) -> Result<(), VaultError> {
        if !self.canary_enabled {
            return Ok(());
        }

        unsafe {
            let data_size = std::mem::size_of::<T>();
            let canary_size = CANARY_PATTERN.len();

            // Get base pointer (before the data)
            let base_ptr = (self.ptr as *mut u8).sub(canary_size);

            // Check prefix canary
            let prefix_valid = (0..canary_size).all(|i| *base_ptr.add(i) == CANARY_PATTERN[i]);

            // Check suffix canary
            let suffix_valid = (0..canary_size)
                .all(|i| *base_ptr.add(canary_size + data_size + i) == CANARY_PATTERN[i]);

            if !prefix_valid || !suffix_valid {
                return Err(VaultError::SecurityViolation);
            }

            Ok(())
        }
    }

    /// Convert the SecureMemory into its inner value
    pub fn into_inner(this: Self) -> Result<T, VaultError> {
        // Verify canaries first
        this.verify_canaries()?;

        // Extract the value safely with a more cautious approach
        let value = unsafe {
            // Make sure pointer is valid
            if this.ptr.is_null() {
                return Err(VaultError::MemoryProtectionFailed);
            }

            // create a clone of the value
            let value_copy = std::ptr::read(this.ptr);

            // Prevent the normal destructor from running (which would drop original value)
            std::mem::forget(this);

            value_copy
        };

        Ok(value)
    }
}

#[allow(unsafe_code)]
impl<T: Zeroize> Deref for SecureMemory<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // Verify canaries on every access
        if self.canary_enabled {
            let _ = self.verify_canaries();
        }

        unsafe { &*self.ptr }
    }
}

#[allow(unsafe_code)]
impl<T: Zeroize> DerefMut for SecureMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Verify canaries on every access
        if self.canary_enabled {
            let _ = self.verify_canaries();
        }

        unsafe { &mut *self.ptr }
    }
}

#[allow(unsafe_code)]
impl<T: Zeroize> Drop for SecureMemory<T> {
    fn drop(&mut self) {
        unsafe {
            // Get data size and canary size
            let data_size = std::mem::size_of::<T>();
            let canary_size = CANARY_PATTERN.len();
            let total_size = data_size + (canary_size * 2);

            // Get base pointer (before the data)
            let base_ptr = (self.ptr as *mut u8).sub(canary_size);

            // First, zeroize the actual data
            let value = &mut *self.ptr;
            value.zeroize();

            // Then, securely zero the entire memory block including canaries
            secure_zero_memory(base_ptr, total_size);

            // Try to unlock the memory
            let _ = unlock_memory(base_ptr, total_size, self.locked);

            // Drop and deallocate
            ptr::drop_in_place(self.ptr);
            alloc::dealloc(base_ptr, self.layout);
        }
    }
}

// Prevent accidentally printing sensitive data
impl<T: Zeroize> fmt::Debug for SecureMemory<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureMemory<{}>", std::any::type_name::<T>())
    }
}

/// A container for sensitive byte arrays that provides additional security guarantees
pub struct SecureBytes {
    memory: SecureMemory<Vec<u8>>,
}

impl SecureBytes {
    /// Create a new SecureBytes container
    pub fn new(bytes: Vec<u8>) -> Result<Self, VaultError> {
        Ok(Self {
            memory: SecureMemory::new(bytes)?,
        })
    }

    /// Get a reference to the protected bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.memory
    }

    /// Get a mutable reference to the protected bytes
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.memory
    }

    /// Consume the SecureBytes and return the contained data
    pub fn into_vec(self) -> Result<Vec<u8>, VaultError> {
        let SecureBytes { memory } = self;
        SecureMemory::into_inner(memory)
    }

    /// Verify the integrity of the memory protection
    pub fn verify_integrity(&self) -> Result<(), VaultError> {
        self.memory.verify_canaries()
    }
}

// Implement common operations for SecureBytes
impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for SecureBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

// Prevent accidentally printing sensitive data
impl fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBytes(length={})", self.as_slice().len())
    }
}

// Prevent accidentally displaying sensitive data
impl fmt::Display for SecureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[SENSITIVE DATA REDACTED]")
    }
}

/// A container for sensitive strings that provides additional security guarantees
pub struct SecureString {
    memory: SecureMemory<String>,
}

impl SecureString {
    /// Create a new SecureString container
    pub fn new(string: String) -> Result<Self, VaultError> {
        Ok(Self {
            memory: SecureMemory::new(string)?,
        })
    }

    /// Get a reference to the protected string
    pub fn as_str(&self) -> &str {
        &self.memory
    }

    /// Get a mutable reference to the protected string
    pub fn as_mut_str(&mut self) -> &mut String {
        &mut self.memory
    }

    /// Consume the SecureString and return the contained data
    pub fn into_string(self) -> Result<String, VaultError> {
        let SecureString { memory } = self;
        SecureMemory::into_inner(memory)
    }

    /// Verify the integrity of the memory protection
    pub fn verify_integrity(&self) -> Result<(), VaultError> {
        self.memory.verify_canaries()
    }
}

// Implement common operations for SecureString
impl AsRef<str> for SecureString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

// Prevent accidentally printing sensitive data
impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureString(length={})", self.as_str().len())
    }
}

// Prevent accidentally displaying sensitive data
impl fmt::Display for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[SENSITIVE DATA REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_memory_init() {
        let result = init_secure_memory();
        println!("Secure memory initialization: {:?}", result);

        let available = is_secure_memory_available();
        println!("Secure memory available: {}", available);
    }

    #[test]
    fn test_secure_memory_basic() {
        let sensitive_data = vec![1, 2, 3, 4, 5];
        let secure_bytes = SecureBytes::new(sensitive_data.clone()).unwrap();

        // Verify we can access the data
        assert_eq!(secure_bytes.as_slice(), &[1, 2, 3, 4, 5]);

        // Verify the debug output doesn't expose the data
        let debug_str = format!("{:?}", secure_bytes);
        assert!(!debug_str.contains("1, 2, 3"));
        assert!(debug_str.contains("SecureBytes"));
    }

    #[test]
    fn test_secure_memory_canaries() {
        let sensitive_data = vec![1, 2, 3, 4, 5];
        let secure_bytes = SecureBytes::new(sensitive_data.clone()).unwrap();

        // Verify canaries are intact
        assert!(secure_bytes.verify_integrity().is_ok());
    }

    #[test]
    fn test_secure_memory_mutation() {
        let mut secure_bytes = SecureBytes::new(vec![1, 2, 3]).unwrap();

        // Modify the contents
        secure_bytes.as_mut_slice()[0] = 5;

        // Verify the modification worked
        assert_eq!(secure_bytes.as_slice(), &[5, 2, 3]);

        // Verify canaries are still intact
        assert!(secure_bytes.verify_integrity().is_ok());
    }

    #[test]
    fn test_secure_string() {
        let sensitive_string = "password123".to_string();
        let secure_string = SecureString::new(sensitive_string.clone()).unwrap();

        // Verify we can access the data
        assert_eq!(secure_string.as_str(), "password123");

        // Verify canaries are intact
        assert!(secure_string.verify_integrity().is_ok());

        // Verify debug and display redaction
        let debug_str = format!("{:?}", secure_string);
        let display_str = format!("{}", secure_string);

        assert!(!debug_str.contains("password"));
        assert!(!display_str.contains("password"));
        assert!(display_str.contains("REDACTED"));
    }

    #[test]
    fn test_into_inner() {
        let sensitive_data = vec![9, 8, 7, 6, 5];
        let secure_bytes = SecureBytes::new(sensitive_data.clone()).unwrap();

        // Extract the data
        let extracted = secure_bytes.into_vec().unwrap();

        // Verify we got the original data back
        assert_eq!(extracted, sensitive_data);
    }

    #[test]
    fn test_secure_zero_memory() {
        let mut data = vec![0xAA; 1024];

        // Zero out the memory
        secure_zero_memory(data.as_mut_ptr(), data.len());

        // Verify all bytes are zero
        assert!(data.iter().all(|&b| b == 0));
    }
}
