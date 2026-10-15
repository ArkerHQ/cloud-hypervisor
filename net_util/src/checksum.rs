// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::fd::RawFd;

// The frame must be host-owned: validating guest memory before writev would
// let the guest change the checked headers before the kernel copies them.
pub(super) fn write_frame(fd: RawFd, frame: &[u8], vnet_hdr_len: usize) -> io::Result<usize> {
    if !valid_checksum_start(frame, vnet_hdr_len) {
        return Ok(0);
    }
    // SAFETY: frame is a live, immutable slice for the duration of the write.
    let result = unsafe { libc::write(fd, frame.as_ptr().cast(), frame.len()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

fn valid_checksum_start(frame: &[u8], vnet_hdr_len: usize) -> bool {
    if vnet_hdr_len < 10 || frame.len() < vnet_hdr_len {
        return false;
    }
    // VIRTIO_NET_HDR_F_NEEDS_CSUM. Virtio 1.0 fields are little endian.
    if frame[0] & 1 == 0 {
        return true;
    }
    let csum_start = usize::from(u16::from_le_bytes([frame[6], frame[7]]));
    let csum_offset = usize::from(u16::from_le_bytes([frame[8], frame[9]]));
    let ethernet = &frame[vnet_hdr_len..];
    if ethernet.len() < 14 || csum_start + csum_offset + 2 > ethernet.len() {
        return false;
    }
    let mut protocol = u16::from_be_bytes([ethernet[12], ethernet[13]]);
    let mut l3 = 14;
    while matches!(protocol, 0x8100 | 0x88a8) {
        if ethernet.len() < l3 + 4 {
            return false;
        }
        protocol = u16::from_be_bytes([ethernet[l3 + 2], ethernet[l3 + 3]]);
        l3 += 4;
    }
    if protocol != 0x0800 {
        return true;
    }
    if ethernet.len() < l3 + 20 || ethernet[l3] >> 4 != 4 {
        return false;
    }
    let ihl = usize::from(ethernet[l3] & 0x0f) * 4;
    // Mirror Linux ip_check_csum_start(), including IPv4 options and VLANs.
    // Reject malformed IHLs as well, before any kernel checksum completion.
    ihl >= 20 && ethernet.len() >= l3 + ihl && csum_start >= l3 + ihl
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;

    use super::*;

    #[test]
    fn drops_checksum_start_inside_ipv4_header() {
        let (tx, rx) = UnixDatagram::pair().unwrap();
        rx.set_nonblocking(true).unwrap();
        for vnet_len in [10, 12] {
            for vlan_tags in 0..=2 {
                for ihl in [5, 6, 15] {
                    let l3 = 14 + vlan_tags * 4;
                    let ip_end = l3 + ihl * 4;
                    let mut frame = vec![0; vnet_len + ip_end + 20];
                    frame[0] = 1;
                    let eth = &mut frame[vnet_len..];
                    for tag in 0..vlan_tags {
                        eth[12 + tag * 4..14 + tag * 4].copy_from_slice(&0x8100u16.to_be_bytes());
                    }
                    eth[l3 - 2..l3].copy_from_slice(&0x0800u16.to_be_bytes());
                    eth[l3] = 0x40 | ihl as u8;
                    for start in [0, l3, ip_end - 1] {
                        frame[6..8].copy_from_slice(&(start as u16).to_le_bytes());
                        assert_eq!(write_frame(tx.as_raw_fd(), &frame, vnet_len).unwrap(), 0);
                        assert_eq!(
                            rx.recv(&mut [0; 256]).unwrap_err().kind(),
                            io::ErrorKind::WouldBlock
                        );
                    }
                    // A checksum starting exactly after the IP options still transmits.
                    frame[6..8].copy_from_slice(&(ip_end as u16).to_le_bytes());
                    assert_eq!(
                        write_frame(tx.as_raw_fd(), &frame, vnet_len).unwrap(),
                        frame.len()
                    );
                    let mut received = [0; 256];
                    let len = rx.recv(&mut received).unwrap();
                    assert_eq!(&received[..len], frame.as_slice());
                }
            }
        }
    }
}
