use std::net::IpAddr;

#[cfg(not(windows))]
pub use posix::list;
#[cfg(windows)]
pub use win::list;

pub struct Interface {
    pub name: String,
    pub addrs: Vec<IpAddr>,
}

#[cfg(windows)]
mod win {
    use super::Interface;
    use crate::sockaddr::to_ipaddr;
    use std::ffi::CStr;
    use std::io;
    use winapi::shared::{
        ifdef::IfOperStatusUp, ipifcons::IF_TYPE_SOFTWARE_LOOPBACK, nldef::IpSuffixOriginRandom,
        ws2def::AF_UNSPEC,
    };
    use winapi::um::iphlpapi;
    use winapi::um::iptypes::*;

    pub fn list() -> io::Result<Vec<Interface>> {
        let mut adapt_addrs_ptr = get_ip_adapter_addrs()?;
        let mut res = Vec::new();

        while !adapt_addrs_ptr.is_null() {
            let adapt_addrs = unsafe { &*adapt_addrs_ptr };
            if adapt_addrs.OperStatus != IfOperStatusUp
                || adapt_addrs.IfType == IF_TYPE_SOFTWARE_LOOPBACK
            {
                adapt_addrs_ptr = adapt_addrs.Next;
                continue;
            }

            let name = unsafe { CStr::from_ptr(adapt_addrs.AdapterName) }
                .to_string_lossy()
                .into_owned();

            let mut addr_ptr = adapt_addrs.FirstUnicastAddress;
            let mut addrs = Vec::new();

            while !addr_ptr.is_null() {
                let addr = unsafe { &*addr_ptr };
                if let Some(ip_addr) = to_ipaddr(addr.Address.lpSockaddr) {
                    // Random IPv6 address is preferred.
                    if addr.SuffixOrigin == IpSuffixOriginRandom {
                        addrs.insert(0, ip_addr)
                    } else {
                        addrs.push(ip_addr);
                    }
                }
                addr_ptr = addr.Next;
            }

            res.push(Interface { name, addrs });
            adapt_addrs_ptr = adapt_addrs.Next;
        }

        unsafe { libc::free(adapt_addrs_ptr as *mut _) };
        Ok(res)
    }

    fn get_ip_adapter_addrs() -> io::Result<*const IP_ADAPTER_ADDRESSES> {
        let mut buffer_size = 15000;
        let mut addrs: *mut IP_ADAPTER_ADDRESSES;
        loop {
            unsafe {
                addrs = libc::malloc(buffer_size as usize) as *mut _;
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
                        libc::free(addrs as *mut _);
                        continue;
                    }
                    _ => {
                        libc::free(addrs as *mut _);
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
    pub fn list() -> ! {
        todo!()
    }
}
