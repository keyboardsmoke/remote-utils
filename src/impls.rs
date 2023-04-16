#[derive(Clone, Copy)]
pub struct Pointer
{
    value: *mut std::ffi::c_void
}

impl Pointer
{
    pub fn from<T>(ptr: *mut T) -> Pointer
    {
        Pointer { value: unsafe { std::mem::transmute::<*mut T, *mut std::ffi::c_void>(ptr) } }
    }

    pub fn cast_mut<T>(&self) -> *mut T
    {
        self.value as *mut T
    }
}

pub struct Handle
{
    handle: u64
}

impl Handle
{
    pub fn generic(&self) -> u64 {
        self.handle
    }

    pub fn cast<T>(&self) -> *const T {
        self.handle as *const T
    }

    pub fn cast_mut<T>(&mut self) -> *mut T {
        self.handle as *mut T
    }

    pub fn is_ok(&self) -> bool {
        !self.is_invalid() && !self.is_null()
    }

    #[cfg(target_os = "windows")]
    pub fn is_invalid(&self) -> bool {
        self.handle == winapi::um::handleapi::INVALID_HANDLE_VALUE as u64
    }

    #[cfg(target_os = "linux")]
    pub fn is_invalid(&self) -> bool {
        std::fs::metadata(std::path::Path::new(format!("/proc/{}", self.handle).as_str())).is_err()
    }

    pub fn is_null(&self) -> bool {
        self.handle == 0
    }
}

pub struct Library
{
    // The containing process
    pub parent_handle: Handle,

    // Name read upon discovery in a lookup function
    pub cached_name: Option<String>,

    // Address of the module
    pub address: u64
}

#[cfg(target_os = "windows")]
fn drop_handle(handle: *mut std::ffi::c_void) -> bool
{
    if !handle.is_null() {
        let p = handle as *mut winapi::ctypes::c_void;
        if unsafe { winapi::um::handleapi::CloseHandle(p) } == winapi::shared::minwindef::TRUE {
            return true;
        }
    }
    false
}

#[cfg(target_os = "windows")]
impl Drop for Handle
{
    fn drop(&mut self)
    {
        let res = drop_handle(self.handle as *mut std::ffi::c_void);
        if !res {
            println!("Warning: Failed to deallocate handle at 0x{:X}", self.handle);
        } else {
            self.handle = 0;
        }
    }
}

#[cfg(target_os = "windows")]
pub fn handle_from_pid(pid: u32) -> anyhow::Result<Handle, anyhow::Error>
{
    let res = unsafe { winapi::um::processthreadsapi::OpenProcess(winapi::um::winnt::PROCESS_ALL_ACCESS, winapi::shared::minwindef::FALSE, pid) };
    if res == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        anyhow::bail!("OpenProcess failed (Code: 0x{:X}", unsafe { winapi::um::errhandlingapi::GetLastError() })
    }
    Ok(Handle { handle: res as u64 })
}

#[cfg(target_os = "linux")]
pub fn handle_from_pid(pid: u32) -> anyhow::Result<Handle, anyhow::Error>
{
    Ok(Handle { handle: pid as u64 })
}

#[cfg(target_os = "windows")]
pub fn handle_from_name(name: &str) -> anyhow::Result<Handle, anyhow::Error>
{
    use winapi::um::tlhelp32::PROCESSENTRY32W;

    let th = unsafe { winapi::um::tlhelp32::CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPPROCESS, 0) };
    if th.is_null() {
        anyhow::bail!("CreateToolhelp32Snapshot failed (Code: 0x{:X})", unsafe { winapi::um::errhandlingapi::GetLastError() });
    }

    let default_exe: [u16; 260] = [0; 260];
    let mut entry: PROCESSENTRY32W = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, cntUsage: 0, th32ProcessID: 0, th32DefaultHeapID: 0, th32ModuleID: 0, cntThreads: 0, th32ParentProcessID: 0, pcPriClassBase: 0, dwFlags: 0, szExeFile: default_exe };

    if unsafe { winapi::um::tlhelp32::Process32FirstW(th as *mut winapi::ctypes::c_void, &mut entry) } == winapi::shared::minwindef::FALSE {
        anyhow::bail!("Process32FirstW failed (Code: 0x{:X})", unsafe { winapi::um::errhandlingapi::GetLastError() });
    }

    loop {
        let s = String::from_utf16(&entry.szExeFile);
        if let Ok(process_name) = s {
            let process_name_trim = process_name.trim_end_matches(char::from(0));
            if process_name_trim == name.to_uppercase() {
                let res = handle_from_pid(entry.th32ProcessID)?;
                return Ok(res);
            }
        }

        if unsafe { winapi::um::tlhelp32::Process32NextW(th as *mut winapi::ctypes::c_void, &mut entry) } == winapi::shared::minwindef::FALSE {
            break;
        }
    }
    Err(anyhow::Error::msg(format!("Unable to locate process with name {}", name)))
}

#[cfg(target_os = "linux")]
pub fn handle_from_name(name: &str) -> anyhow::Result<Handle, anyhow::Error>
{
    anyhow::bail!("Unimplemented.")
}

#[cfg(target_os = "windows")]
pub fn get_local_process_handle() -> anyhow::Result<Handle, anyhow::Error>
{
    handle_from_pid(unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() })
}

#[cfg(target_os = "linux")]
pub fn get_local_process_handle() -> anyhow::Result<Handle, anyhow::Error>
{
    use syscalls::raw::syscall0;

    Ok(Handle { handle: unsafe { syscall0(syscalls::Sysno::getpid) as u64 } })
}

#[cfg(target_os = "windows")]
pub fn allocate(handle: &Handle, size: usize) -> anyhow::Result<Pointer, anyhow::Error>
{
    let res = unsafe { winapi::um::memoryapi::VirtualAllocEx(handle.generic() as *mut winapi::ctypes::c_void, std::ptr::null_mut(), size, winapi::um::winnt::MEM_COMMIT, winapi::um::winnt::PAGE_EXECUTE_READWRITE) } as *mut std::ffi::c_void;
    if res.is_null() {
        anyhow::bail!("VirtualAllocEx failed (Code: 0x{:X}", unsafe { winapi::um::errhandlingapi::GetLastError() })
    }
    Ok(Pointer { value: res })
}

#[cfg(target_os = "linux")]
pub fn allocate(handle: &Handle, size: usize) -> anyhow::Result<Pointer, anyhow::Error>
{
    anyhow::bail!("Unimplemented.")
}

#[cfg(target_os = "windows")]
pub fn deallocate(handle: &Handle, ptr: Pointer) -> anyhow::Result<(), anyhow::Error>
{
    let res = unsafe { winapi::um::memoryapi::VirtualFreeEx(handle.generic() as *mut winapi::ctypes::c_void, ptr.cast_mut(), 0, winapi::um::winnt::MEM_FREE) };
    if res == winapi::shared::minwindef::FALSE {
        anyhow::bail!("VirtualFreeEx failed (Code: 0x{:X}", unsafe { winapi::um::errhandlingapi::GetLastError() })
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn deallocate(handle: &Handle, ptr: Pointer) -> anyhow::Result<(), anyhow::Error>
{
    anyhow::bail!("Unimplemented.")
}

#[cfg(target_os = "windows")]
pub fn read(handle: &Handle, address: u64, size: usize) -> anyhow::Result<Vec<u8>, anyhow::Error>
{
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    vec.resize(size, 0);

    let res = unsafe { 
        winapi::um::memoryapi::ReadProcessMemory(
            handle.generic() as *mut winapi::ctypes::c_void, 
            address as *const winapi::ctypes::c_void, 
            vec.as_ptr() as *mut winapi::ctypes::c_void, size, std::ptr::null_mut())
    };
    if res == winapi::shared::minwindef::FALSE {
        anyhow::bail!("ReadProcessMemory failed (Code: 0x{:X})", unsafe { winapi::um::errhandlingapi::GetLastError() })
    }
    Ok(vec)
}

#[cfg(target_os = "linux")]
pub fn read(handle: &Handle, address: u64, size: usize) -> anyhow::Result<Vec<u8>, anyhow::Error>
{
    use linux_raw_sys::general::iovec;
    use syscalls::raw::syscall6;

    let mut vec: Vec<u8> = Vec::with_capacity(size);
    vec.resize(size, 0);

    let local = iovec { iov_base: vec.as_ptr() as *mut linux_raw_sys::ctypes::c_void, iov_len: size as u64 };
    let remote = iovec { iov_base: address as *mut linux_raw_sys::ctypes::c_void, iov_len: size as u64 };
    let res = unsafe { syscall6(syscalls::Sysno::process_vm_readv, handle.generic() as usize, std::ptr::addr_of!(local) as usize, 1, std::ptr::addr_of!(remote) as usize, 1, 0) };
    if res != size {
        anyhow::bail!("Failed to read memory. 0x{:X}", res)
    }
    Ok(vec)
}

#[cfg(target_os = "windows")]
pub fn write(handle: &Handle, address: u64, data: &Vec<u8>) -> anyhow::Result<(), anyhow::Error>
{
    let res = unsafe {
        let p = data.as_ptr();
        winapi::um::memoryapi::WriteProcessMemory(
            handle.generic() as *mut winapi::ctypes::c_void, 
            Pointer::from(address as *mut u8).cast_mut(), 
            Pointer::from(p as *mut u8).cast_mut(), data.len(), std::ptr::null_mut())
    };
    if res == winapi::shared::minwindef::FALSE {
        anyhow::bail!("WriteProcessMemory failed (Code: 0x{:X})", unsafe { winapi::um::errhandlingapi::GetLastError() })
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn write(handle: &Handle, address: u64, data: &Vec<u8>) -> anyhow::Result<(), anyhow::Error>
{
    use linux_raw_sys::general::iovec;
    use syscalls::raw::syscall6;

    let local = iovec { iov_base: data.as_ptr() as *mut linux_raw_sys::ctypes::c_void, iov_len: data.len() as u64 };
    let remote = iovec { iov_base: address as *mut linux_raw_sys::ctypes::c_void, iov_len: data.len() as u64 };
    let res = unsafe { syscall6(syscalls::Sysno::process_vm_writev, handle.generic() as usize, std::ptr::addr_of!(local) as usize, 1, std::ptr::addr_of!(remote) as usize, 1, 0) };
    if res != data.len() {
        anyhow::bail!("Failed to write memory. 0x{:X}", res)
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn get_shared_library(handle: &Handle, library_name: &str) -> anyhow::Result<Library, anyhow::Error>
{
    use winapi::um::tlhelp32::MODULEENTRY32W;

    let mut th = Handle { handle: unsafe { winapi::um::tlhelp32::CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPMODULE, winapi::um::processthreadsapi::GetProcessId(handle.generic() as *mut winapi::ctypes::c_void)) } as u64 };
    if !th.is_ok() {
        anyhow::bail!("CreateToolhelp32Snapshot failed (Code: 0x{:X})", unsafe { winapi::um::errhandlingapi::GetLastError() })
    }

    let default_module: [u16; 256] = [0; 256];
    let default_exe: [u16; 260] = [0; 260];
    let mut entry: MODULEENTRY32W = MODULEENTRY32W { dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32, th32ModuleID: 0, th32ProcessID: 0, GlblcntUsage: 0, ProccntUsage: 0, modBaseAddr: std::ptr::null_mut(), modBaseSize: 0, hModule: std::ptr::null_mut(), szModule: default_module, szExePath: default_exe };

    if unsafe { winapi::um::tlhelp32::Module32FirstW(th.cast_mut(), &mut entry) } == winapi::shared::minwindef::FALSE {
        anyhow::bail!("Module32FirstW failed (Code: 0x{:X})", unsafe { winapi::um::errhandlingapi::GetLastError() })
    }

    loop {
        let utf_name = String::from_utf16_lossy(&entry.szModule);
        let mod_name = utf_name.trim_end_matches('\0');
        if mod_name == library_name {
            return Ok(Library { parent_handle: Handle { handle: handle.handle }, cached_name: Some(mod_name.to_string()), address: entry.modBaseAddr as u64 });
        }

        if unsafe { winapi::um::tlhelp32::Module32NextW(th.cast_mut(), &mut entry) } == winapi::shared::minwindef::FALSE {
            break;
        }
    }
    anyhow::bail!("Failed to find library.")
}

#[cfg(target_os = "linux")]
pub fn get_shared_library(handle: &Handle, library_name: &str) -> anyhow::Result<Library, anyhow::Error>
{
    let maps = proc_maps::get_process_maps(handle.generic() as i32)?;
    for map in maps {
        let m = map.filename();
        if m.is_some() {
            let s = m.unwrap().to_str();
            if s.is_some() {
                let n = s.unwrap();
                if n.contains(library_name) {
                    return Ok(Library { parent_handle: Handle { handle: handle.handle }, cached_name: Some(n.to_string()), address: map.start() as u64 });
                }
            }
        }
    }
    anyhow::bail!("Failed to find library.")
}