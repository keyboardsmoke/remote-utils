mod impls;

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

    pub fn u64(&self) -> u64
    {
        self.value as u64
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

#[cfg(target_os = "windows")]
impl Drop for Handle
{
    fn drop(&mut self)
    {
        let res = impls::drop_handle(self.handle as *mut std::ffi::c_void);
        if !res {
            println!("Warning: Failed to deallocate handle at 0x{:X}", self.handle);
        } else {
            self.handle = 0;
        }
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

pub struct Process
{
    handle: Handle
}

impl Process
{
    pub fn get_pid(&self) -> u32
    {
        0
    }
}

impl Process
{
    pub fn handle(&self) -> &Handle
    {
        &self.handle
    }

    pub fn local() -> anyhow::Result<Process, anyhow::Error>
    {
        Ok(Process { handle: impls::get_local_process_handle()? })
    }

    pub fn from_pid(pid: u32) -> anyhow::Result<Process, anyhow::Error>
    {
        Ok(Process { handle: impls::handle_from_pid(pid)? })
    }

    pub fn from_name(name: &str) -> anyhow::Result<Process, anyhow::Error>
    {
        Ok(Process { handle: impls::handle_from_name(name)? })
    }

    pub fn allocate(&self, size: usize) -> anyhow::Result<Pointer, anyhow::Error>
    {
        impls::allocate(&self.handle, size)
    }

    pub fn deallocate(&self, ptr: Pointer) -> anyhow::Result<(), anyhow::Error>
    {
        impls::deallocate(&self.handle, ptr)
    }

    pub fn read_memory(&self, address: u64, size: usize) -> anyhow::Result<Vec<u8>, anyhow::Error>
    {
        impls::read(&self.handle, address, size)
    }

    pub fn write_memory(&self, address: u64, data: &Vec<u8>) -> anyhow::Result<(), anyhow::Error>
    {
        impls::write(&self.handle, address, data)
    }

    pub fn commit_memory(&self, data: &Vec<u8>) -> anyhow::Result<Pointer, anyhow::Error>
    {
        let alloc = impls::allocate(&self.handle, data.len())?;
        impls::write(&self.handle, alloc.u64(), data)?;
        Ok(alloc)
    }

    pub fn get_shared_library(&self, library_name: &str) -> anyhow::Result<Library, anyhow::Error>
    {
        impls::get_shared_library(&self.handle, library_name)
    }
}

pub fn from_name(name: &str) -> anyhow::Result<Process, anyhow::Error>
{
    let res = impls::handle_from_name(name)?;
    Ok(Process { handle: res })
}

pub fn from_id(id: u32) -> anyhow::Result<Process, anyhow::Error>
{
    let handle = impls::handle_from_pid(id)?;
    Ok(Process { handle })
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_mem_read() -> anyhow::Result<(), anyhow::Error>
    {
        let proc = Process::local()?;
        let num: u64 = 123456789;
        let num_addr = std::ptr::addr_of!(num) as u64;
        let mem_value = proc.read_memory(num_addr, std::mem::size_of::<u64>())?;
        let raw_mem = mem_value.into_boxed_slice();
        let box_mem = unsafe { Box::from_raw(Box::into_raw(raw_mem) as *mut [u8; 8]) };
        let unbox = *box_mem;
        let read_value = u64::from_le_bytes(unbox);
        assert_eq!(read_value, num);
        Ok(())
    }

    #[test]
    fn test_mem_write() -> anyhow::Result<(), anyhow::Error>
    {
        let proc = Process::local()?;
        let num: u64 = 123456789;
        let num_addr = std::ptr::addr_of!(num) as u64;
        let new_num: u64 = 987654321;
        let new_num_vec = new_num.to_le_bytes().to_vec();
        proc.write_memory(num_addr, &new_num_vec)?;
        assert_eq!(num, new_num);
        Ok(())
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_get_library() -> anyhow::Result<(), anyhow::Error>
    {
        let proc = Process::local()?;
        let found_library = proc.get_shared_library("ntdll.dll")?;
        assert_eq!(found_library.cached_name.is_some(), true);
        assert_eq!(found_library.cached_name.unwrap(), "ntdll.dll");
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_get_library() -> anyhow::Result<(), anyhow::Error>
    {
        let proc = Process::local()?;
        proc.get_shared_library("libc.so")?;
        Ok(())
    }
}