//! Linux socket plumbing that std and socket2 do not expose: kernel receive
//! timestamps, received TTL/TOS, per-packet TOS on send, and TCP_INFO.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::RawFd;

/// Metadata the kernel attaches to a received datagram.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecvMeta {
    pub len: usize,
    pub src: Option<SocketAddrV4>,
    /// SO_TIMESTAMPNS software receive timestamp (CLOCK_REALTIME), ns.
    pub kernel_ts_ns: Option<i64>,
    pub ttl: Option<u8>,
    pub tos: Option<u8>,
    /// The kernel had to drop ancillary data (buffer too small).
    pub ctrunc: bool,
}

fn setsockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    // SAFETY: passes a pointer to a live c_int and its exact size.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&value as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Kernel software receive timestamps (`SO_TIMESTAMPNS`).
pub fn enable_rx_timestamps(fd: RawFd) -> io::Result<()> {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, 1)
}

/// Deliver the received IP TTL as ancillary data (`IP_RECVTTL`).
pub fn enable_recv_ttl(fd: RawFd) -> io::Result<()> {
    setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_RECVTTL, 1)
}

/// Deliver the received IP TOS byte as ancillary data (`IP_RECVTOS`).
pub fn enable_recv_tos(fd: RawFd) -> io::Result<()> {
    setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_RECVTOS, 1)
}

/// Aligned control-message buffer.
#[repr(C, align(8))]
struct CmsgBuf([u8; 256]);

/// `recvmsg` returning the payload length and the kernel's metadata.
/// Honors the socket's receive timeout (`WouldBlock` / `TimedOut` on expiry).
pub fn recv_meta(fd: RawFd, buf: &mut [u8]) -> io::Result<RecvMeta> {
    // SAFETY: all pointers handed to recvmsg reference live, correctly sized
    // stack/heap buffers for the duration of the call; the kernel writes at
    // most msg_namelen / msg_controllen / iov_len bytes into them.
    unsafe {
        let mut addr: libc::sockaddr_in = zeroed();
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
        let mut control = CmsgBuf([0; 256]);
        let mut msg: libc::msghdr = zeroed();
        msg.msg_name = (&mut addr as *mut libc::sockaddr_in).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr().cast();
        msg.msg_controllen = control.0.len() as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut meta =
            RecvMeta { len: n as usize, ctrunc: msg.msg_flags & libc::MSG_CTRUNC != 0, ..RecvMeta::default() };
        if msg.msg_namelen as usize >= size_of::<libc::sockaddr_in>() && addr.sin_family as libc::c_int == libc::AF_INET
        {
            meta.src = Some(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
                u16::from_be(addr.sin_port),
            ));
        }

        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            let data = libc::CMSG_DATA(cmsg);
            match (hdr.cmsg_level, hdr.cmsg_type) {
                (libc::SOL_SOCKET, libc::SCM_TIMESTAMPNS) => {
                    let ts: libc::timespec = std::ptr::read_unaligned(data.cast());
                    meta.kernel_ts_ns = Some(ts.tv_sec as i64 * 1_000_000_000 + ts.tv_nsec as i64);
                }
                (libc::IPPROTO_IP, libc::IP_TTL) => {
                    let v: libc::c_int = std::ptr::read_unaligned(data.cast());
                    meta.ttl = u8::try_from(v).ok();
                }
                (libc::IPPROTO_IP, libc::IP_TOS) => {
                    // IP_TOS is delivered as a single byte on receive.
                    meta.tos = Some(*data);
                }
                _ => {}
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        Ok(meta)
    }
}

/// `sendmsg` to `dst`, optionally overriding the IP TOS byte for this packet only.
pub fn send_to_tos(fd: RawFd, payload: &[u8], dst: SocketAddrV4, tos: Option<u8>) -> io::Result<usize> {
    // SAFETY: as in recv_meta; the control buffer is large enough for one
    // c_int cmsg (CMSG_SPACE(4) = 16 on 64-bit Linux) and stays alive for the call.
    unsafe {
        let mut addr: libc::sockaddr_in = zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = dst.port().to_be();
        addr.sin_addr.s_addr = u32::from(*dst.ip()).to_be();
        let mut iov = libc::iovec { iov_base: payload.as_ptr() as *mut libc::c_void, iov_len: payload.len() };
        let mut control = CmsgBuf([0; 256]);
        let mut msg: libc::msghdr = zeroed();
        msg.msg_name = (&mut addr as *mut libc::sockaddr_in).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if let Some(tos) = tos {
            let space = libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) as usize;
            msg.msg_control = control.0.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::IPPROTO_IP;
            (*cmsg).cmsg_type = libc::IP_TOS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>(), libc::c_int::from(tos));
        }
        let n = libc::sendmsg(fd, &msg, 0);
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

/// The kernel's smoothed RTT for a connected TCP socket, in microseconds.
/// Right after the handshake this is the SYN → SYN-ACK sample.
pub fn tcp_rtt_us(fd: RawFd) -> Option<u32> {
    // SAFETY: tcp_info is POD; len tells the kernel how much it may write.
    unsafe {
        let mut info: libc::tcp_info = zeroed();
        let mut len = size_of::<libc::tcp_info>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&mut info as *mut libc::tcp_info).cast(),
            &mut len,
        );
        if rc == 0 && info.tcpi_rtt > 0 {
            Some(info.tcpi_rtt)
        } else {
            None
        }
    }
}

/// Waits for `fd` to become writable (non-blocking connect completion).
/// Returns `Ok(false)` on timeout.
pub fn wait_writable(fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
    let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
    loop {
        // SAFETY: one valid pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        return Ok(rc > 0);
    }
}

/// IPv4-only for Phase 1.
pub fn v4(addr: SocketAddr) -> io::Result<SocketAddrV4> {
    match addr {
        SocketAddr::V4(a) => Ok(a),
        SocketAddr::V6(a) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{a}: IPv6 is not supported yet (Phase 1 is IPv4-only)"),
        )),
    }
}

/// True for the errors a socket read timeout (or a signal) produces: not failures.
pub fn is_timeout(err: &io::Error) -> bool {
    matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted)
}
