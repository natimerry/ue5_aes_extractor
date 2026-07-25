#![allow(non_snake_case)]
#![allow(unsafe_op_in_unsafe_fn)]
use libwinexploit::hooking::HookEntry;
use libwinexploit::hooking::pattern::{Pattern, PatternScanOption};
use libwinexploit::runtime::memory::LocalMemory;
use libwinexploit::runtime::pe64_runtime::PE64Runtime;
use libwinexploit::winapi::{
    BOOL, DWORD, DisableThreadLibraryCalls, HINSTANCE, LPVOID, MessageBoxA, SetConsoleCtrlHandler,
};
use std::io::Write;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{LazyLock, Mutex};
use std::thread;

static SEEN_KEYS: LazyLock<Mutex<HashSet<Vec<u8>>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

static TRAMPOLINE_AES: AtomicPtr<()> = AtomicPtr::new(null_mut());

const DLL_PROCESS_ATTACH: DWORD = 1;

static HOOKED_ADDRS: LazyLock<Mutex<HashSet<u64>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

const AES_CALLER_FN: &str = "48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 20 49 8b d8 48 8b fa 48 8b f1 e8 d3 d4 ff ff 4c 8b c7 48 8b d6 48 8b cb 84 c0 74 14 48 8b 5c 24 30 48 8b 74 24 38 48 83 c4 20 5f e9 32 ba ff ff";

static LOG_FILE: LazyLock<Mutex<Option<File>>> = LazyLock::new(|| {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(r"C:\aes_dumper.txt")
        .ok();

    Mutex::new(file)
});


macro_rules! file_log {
    ($($arg:tt)*) => {{
        if let Ok(mut guard) = LOG_FILE.lock() {
            if let Some(file) = guard.as_mut() {
                let _ = writeln!(file, $($arg)*);
                let _ = file.flush();
            }
        }
    }};
}

// The hook function whick will call and trampoline to execute the actual decrypt logic
extern "system" fn hooked_aes_fn(data_ptr: *mut u8, block_count: u64, key_ptr: *const u8,) {
    if !key_ptr.is_null() {
        unsafe {
            let key = std::slice::from_raw_parts(key_ptr, 32);

            if key.iter().any(|&b| b != 0) {
                let mut seen = SEEN_KEYS.lock().unwrap();
                if seen.insert(key.to_vec()) {
                    let mut hex = String::with_capacity(2 + 64);
                    hex.push_str("0x");
                    for b in key {
                        use std::fmt::Write;
                        write!(&mut hex, "{:02x}", b).unwrap();
                    }

                    file_log!("[AES-256 KEY] {}", hex);
                }
            }
        }
    }

    let orig = TRAMPOLINE_AES.load(Ordering::SeqCst);
    if !orig.is_null() {
        unsafe {
            let f: extern "system" fn(*mut u8, u64, *const u8) = std::mem::transmute(orig);
            f(data_ptr, block_count, key_ptr);
        }
    }
}


unsafe fn install_hook(addr: u64) {
    if HOOKED_ADDRS.lock().unwrap().contains(&addr) {
        file_log!("[install] aes_dec @ {:#x} already hooked", addr);
        return;
    }

    file_log!("[install] aes_dec @ {:#x}", addr);

    let memory = LocalMemory {};
    let mut entry = match HookEntry::new(addr as *mut u8, hooked_aes_fn as *mut u8, memory) {
        Ok(e) => {
            TRAMPOLINE_AES.store(e.original() as *mut (), Ordering::SeqCst);
            e
        }
        Err(e) => {
            file_log!("[install] HookEntry failed: {:?}", e);
            return;
        }
    };
    let memory = LocalMemory {};

    match entry.toggle(&memory) {
        Ok(_) => file_log!("[install] Hook is active"),
        Err(e) => file_log!("[install] Failed to install hook: {:?}", e),
    }
}

unsafe fn init() -> BOOL {
    let module = match PE64Runtime::from_current_module() {
        Ok(m) => m,
        Err(e) => {
            file_log!("PE64Runtime failed: {:?}", e);
            return 1;
        }
    };

    let base = module.module_base as *const u8;
    let size = module.image_size.min(15826958) as usize;
    file_log!("base={:p} size={:#x}", base, size);

    let pattern = match Pattern::builder().pattern(AES_CALLER_FN) {
        Ok(p) => p,
        Err(e) => {
            file_log!("Pattern::from failed: {:?}", e);
            return 1;
        }
    };

    let mut pattern = pattern.generate_wildcards().build();
    let mut vec_addr = HashSet::new();

    match pattern.scan(&module.memory, base, size, PatternScanOption::Begin) {
        Some(addrs) if addrs.is_empty() => {
            file_log!("[scan] no matches found — verify pattern against current binary");
        }
        Some(addrs) => {
            let addr = *addrs.first().unwrap();
            file_log!("[scan]   {:p}", addr);

            vec_addr.insert(addr as u64);
        }
        None => {
            file_log!("[scan] Scan failed (wtf?)");
        }
    }

    for addr in vec_addr {
        install_hook(addr);
    }

    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: DWORD,
    _lpv_reserved: LPVOID,
) -> BOOL {
    if fdw_reason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(hinst_dll as *mut _);

        unsafe extern "C" fn ctrl_handler(_ctrl_type: u32) -> BOOL {
            file_log!("Process crashed or exited - press any key to close...");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).ok();
            0
        }
        SetConsoleCtrlHandler(Some(ctrl_handler), 1);

        std::panic::set_hook(Box::new(|info| {
            let msg = format!("{}\0", info);
            file_log!("PANIC: {}", info);
            let caption = b"DLL Panic\0";
            MessageBoxA(
                std::ptr::null_mut(),
                msg.as_ptr() as *const _,
                caption.as_ptr() as *const _,
                0x10,
            );
        }));

        file_log!("AES Dumper loaded!!");
        thread::spawn(|| unsafe { init() });
    }
    1
}
