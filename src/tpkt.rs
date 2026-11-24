/// TPKT framing layer — RFC 1006 / MS-RDPBCGR §2.2.1.1
///
/// Each TPKT packet has a 4-byte header:
///   [0] Version  = 0x03
///   [1] Reserved = 0x00
///   [2] Length high byte (includes the 4-byte header)
///   [3] Length low byte
///
/// This module provides zero-copy encode/decode helpers.
use crate::error::{RdpError, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const TPKT_VERSION: u8 = 0x03;
const TPKT_HEADER_LEN: usize = 4;

/// Write a TPKT frame containing `payload` to the writer.
pub async fn write_tpkt<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let total_len = TPKT_HEADER_LEN + payload.len();
    if total_len > 0xFFFF {
        return Err(RdpError::Protocol("TPKT payload too large"));
    }
    let len = total_len as u16;
    let header = [TPKT_VERSION, 0x00, (len >> 8) as u8, (len & 0xFF) as u8];
    tracing::debug!(
        "TPKT: Sending frame (version={}, payload_len={})",
        TPKT_VERSION,
        payload.len()
    );
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read exactly one TPKT frame from the reader, returning its payload.
///
/// Allocates a `Vec<u8>` per frame — acceptable since NLA only exchanges ~10 frames total.
pub async fn read_tpkt<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; TPKT_HEADER_LEN];
    reader.read_exact(&mut header).await?;

    if header[0] != TPKT_VERSION {
        return Err(RdpError::ProtocolMsg(format!(
            "TPKT: expected version 0x03, got 0x{:02X}",
            header[0]
        )));
    }

    let total_len = (u16::from(header[2]) << 8 | u16::from(header[3])) as usize;
    if total_len < TPKT_HEADER_LEN {
        return Err(RdpError::Protocol("TPKT: length field too small"));
    }

    let payload_len = total_len - TPKT_HEADER_LEN;
    tracing::debug!(
        "TPKT: Received frame (version={}, payload_len={})",
        TPKT_VERSION,
        payload_len
    );
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip() {
        let payload = b"hello tpkt";
        let mut buf = Vec::new();
        write_tpkt(&mut buf, payload).await.unwrap();

        // buf is now [0x03, 0x00, 0x00, 0x0E, h, e, l, l, o, ...]
        assert_eq!(buf[0], 0x03);
        assert_eq!(buf[1], 0x00);
        let len = (buf[2] as usize) << 8 | buf[3] as usize;
        assert_eq!(len, 4 + payload.len());

        let mut cursor = std::io::Cursor::new(&buf);
        let out = read_tpkt(&mut cursor).await.unwrap();
        assert_eq!(out, payload);
    }
}
