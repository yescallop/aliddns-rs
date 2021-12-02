use std::ffi::CString;
use std::net::IpAddr;

#[cfg(not(windows))]
pub use posix::list;
#[cfg(windows)]
pub use win::list;

#[derive(Debug)]
pub struct Interface {
    pub desc: String,
    pub name: CString,
    pub addrs: Vec<IpAddr>,
}

#[cfg(windows)]
mod win {
    use super::Interface;
    use crate::sockaddr::to_ipaddr;

    use std::{
        ffi::{CStr, OsString},
        io,
        os::windows::prelude::OsStringExt,
    };
    use winapi::shared::{
        ifdef::IfOperStatusUp,
        ipifcons::{IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211},
        nldef::IpSuffixOriginRandom,
        ws2def::AF_UNSPEC,
    };
    use winapi::um::heapapi::*;
    use winapi::um::iphlpapi;
    use winapi::um::iptypes::*;

    pub fn list(static_v6: bool) -> io::Result<Vec<Interface>> {
        let mut adapt_addrs_ptr = get_adapter_addresses()?;
        let mut res = Vec::new();

        while !adapt_addrs_ptr.is_null() {
            let adapt_addrs = unsafe { &*adapt_addrs_ptr };
            if adapt_addrs.OperStatus != IfOperStatusUp
                || !matches!(
                    adapt_addrs.IfType,
                    IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211
                )
            {
                adapt_addrs_ptr = adapt_addrs.Next;
                continue;
            }

            let desc = unsafe { os_string_from_ptr(adapt_addrs.Description) }
                .into_string()
                .unwrap_or_else(|s| s.to_string_lossy().into_owned());
            if desc.contains("Virtual") {
                // Skip potentially virtual adapters.
                adapt_addrs_ptr = adapt_addrs.Next;
                continue;
            }

            let name = unsafe { CStr::from_ptr(adapt_addrs.AdapterName) }.to_owned();

            let mut addr_ptr = adapt_addrs.FirstUnicastAddress;
            let mut addrs = Vec::new();

            while !addr_ptr.is_null() {
                let addr = unsafe { &*addr_ptr };
                if let Some(ip_addr) = to_ipaddr(addr.Address.lpSockaddr) {
                    // Random IPv6 address is preferred by default.
                    if !static_v6 && addr.SuffixOrigin == IpSuffixOriginRandom {
                        addrs.insert(0, ip_addr)
                    } else {
                        addrs.push(ip_addr);
                    }
                }
                addr_ptr = addr.Next;
            }

            res.push(Interface { desc, name, addrs });
            adapt_addrs_ptr = adapt_addrs.Next;
        }

        unsafe {
            HeapFree(GetProcessHeap(), 0, adapt_addrs_ptr as *mut _);
        }

        Ok(res)
    }

    unsafe fn os_string_from_ptr(ptr: *mut u16) -> OsString {
        let len = (0..).take_while(|&i| *ptr.add(i) != 0).count();
        let slice = std::slice::from_raw_parts(ptr, len);
        OsString::from_wide(slice)
    }

    fn get_adapter_addresses() -> io::Result<*mut IP_ADAPTER_ADDRESSES> {
        let mut buffer_size = 15000;
        let mut addrs: *mut IP_ADAPTER_ADDRESSES;
        loop {
            unsafe {
                let heap = GetProcessHeap();
                addrs = HeapAlloc(heap, 0, buffer_size as usize) as *mut _;
                if addrs.is_null() {
                    panic!("unable to allocate buffer for GetAdaptersAddresses");
                }
                let ret = iphlpapi::GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    GAA_FLAG_SKIP_ANYCAST
                        | GAA_FLAG_SKIP_MULTICAST
                        | GAA_FLAG_SKIP_DNS_SERVER
                        | GAA_FLAG_SKIP_FRIENDLY_NAME,
                    std::ptr::null_mut(),
                    addrs,
                    &mut buffer_size,
                );

                match ret {
                    // ERROR_SUCCESS
                    0 => break,
                    // ERROR_BUFFER_OVERFLOW
                    111 => {
                        HeapFree(heap, 0, addrs as *mut _);
                        continue;
                    }
                    _ => {
                        HeapFree(heap, 0, addrs as *mut _);
                        return Err(io::Error::last_os_error());
                    }
                }
            }
        }
        Ok(addrs)
    }
}

#[cfg(not(windows))]
mod posix {
    pub fn list(_static_v6: bool) -> ! {
        todo!()
    }
}
