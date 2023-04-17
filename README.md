# remote-utils

```rust
    // Example of usage
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
```
