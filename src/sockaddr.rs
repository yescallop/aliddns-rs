// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#[cfg(not(windows))]
use libc::{sockaddr, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::NonNull;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SOCKADDR as sockaddr, SOCKADDR_IN as sockaddr_in,
    SOCKADDR_IN6 as sockaddr_in6,
};

pub fn to_ipaddr(sockaddr: *const sockaddr) -> Option<IpAddr> {
    if sockaddr.is_null() {
        return None;
    }
    SockAddr::new(sockaddr)?.as_ipaddr()
}

// Wrapper around a sockaddr pointer. Guaranteed to not be null.
struct SockAddr {
    inner: NonNull<sockaddr>,
}

impl SockAddr {
    fn new(sockaddr: *const sockaddr) -> Option<Self> {
        NonNull::new(sockaddr as *mut _).map(|inner| Self { inner })
    }

    #[cfg(not(windows))]
    fn as_ipaddr(&self) -> Option<IpAddr> {
        match self.sockaddr_in() {
            Some(SockAddrIn::In(sa)) => Some(IpAddr::V4(Ipv4Addr::new(
                ((sa.sin_addr.s_addr) & 255) as u8,
                ((sa.sin_addr.s_addr >> 8) & 255) as u8,
                ((sa.sin_addr.s_addr >> 16) & 255) as u8,
                ((sa.sin_addr.s_addr >> 24) & 255) as u8,
            ))),
            Some(SockAddrIn::In6(sa)) => Some(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr))),
            None => None,
        }
    }

    #[cfg(windows)]
    fn as_ipaddr(&self) -> Option<IpAddr> {
        match self.sockaddr_in() {
            Some(SockAddrIn::In(sa)) => {
                let s_addr = unsafe { sa.sin_addr.S_un.S_addr };
                Some(IpAddr::V4(Ipv4Addr::new(
                    ((s_addr >> 0) & 255) as u8,
                    ((s_addr >> 8) & 255) as u8,
                    ((s_addr >> 16) & 255) as u8,
                    ((s_addr >> 24) & 255) as u8,
                )))
            }
            Some(SockAddrIn::In6(sa)) => {
                let s6_addr = unsafe { sa.sin6_addr.u.Byte };
                Some(IpAddr::V6(Ipv6Addr::from(s6_addr)))
            }
            None => None,
        }
    }

    fn sockaddr_in(&self) -> Option<SockAddrIn> {
        const AF_INET_U32: u32 = AF_INET as u32;
        const AF_INET6_U32: u32 = AF_INET6 as u32;

        match self.sa_family() {
            AF_INET_U32 => Some(SockAddrIn::In(self.sa_in())),
            AF_INET6_U32 => Some(SockAddrIn::In6(self.sa_in6())),
            _ => None,
        }
    }

    fn sa_family(&self) -> u32 {
        unsafe { u32::from(self.inner.as_ref().sa_family) }
    }

    fn sa_in(&self) -> sockaddr_in {
        unsafe { *(self.inner.as_ptr() as *const sockaddr_in) }
    }

    fn sa_in6(&self) -> sockaddr_in6 {
        unsafe { *(self.inner.as_ptr() as *const sockaddr_in6) }
    }
}

enum SockAddrIn {
    In(sockaddr_in),
    In6(sockaddr_in6),
}
