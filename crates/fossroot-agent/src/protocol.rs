//! Chrome/Edge native-messaging wire framing.
//!
//! Each message is a little-endian `u32` byte length followed by that many bytes
//! of UTF-8 JSON. The browser closes stdin to end the conversation.

use std::io::{self, Read, Write};

/// The browser will not send a host a message larger than this; we mirror the
/// limit defensively so a bad length prefix can't make us allocate wildly.
const MAX_MESSAGE_LEN: u32 = 64 * 1024 * 1024;

/// Read one framed message. Returns `Ok(None)` on a clean EOF at a message
/// boundary (the browser closed the port), `Err` on a partial/oversized frame.
pub fn read_message<R: Read>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("native-messaging frame too large: {len} bytes"),
        ));
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Write one framed message.
pub fn write_message<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message exceeds u32 length"))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_frames() {
        let mut buf = Vec::new();
        write_message(&mut buf, b"{\"method\":\"ping\"}").unwrap();
        write_message(&mut buf, b"second").unwrap();

        let mut cur = Cursor::new(buf);
        assert_eq!(
            read_message(&mut cur).unwrap().unwrap(),
            b"{\"method\":\"ping\"}"
        );
        assert_eq!(read_message(&mut cur).unwrap().unwrap(), b"second");
        // Clean EOF at a boundary yields None, not an error.
        assert!(read_message(&mut cur).unwrap().is_none());
    }

    #[test]
    fn rejects_oversized_frame() {
        // Length prefix claims 100 MB but no body follows.
        let mut buf = (200_000_000u32).to_le_bytes().to_vec();
        buf.extend_from_slice(b"x");
        let mut cur = Cursor::new(buf);
        assert!(read_message(&mut cur).is_err());
    }

    #[test]
    fn partial_frame_is_error() {
        // Says 10 bytes, provides 3.
        let mut buf = (10u32).to_le_bytes().to_vec();
        buf.extend_from_slice(b"abc");
        let mut cur = Cursor::new(buf);
        assert!(read_message(&mut cur).is_err());
    }
}
