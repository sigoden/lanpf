//! Length-prefixed JSON framing: `u32 BE length + JSON payload`.
//!
//! Used by the local IPC channel, the control stream and the grant/identity channels.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum accepted frame size (16 MiB). Inventory frames are far smaller.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

pub async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> io::Result<()> {
    let payload =
        serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_frame(writer, &payload).await
}

pub async fn read_json<R: AsyncRead + Unpin, T: DeserializeOwned>(reader: &mut R) -> io::Result<T> {
    let payload = read_frame(reader).await?;
    serde_json::from_slice(&payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let payload = b"hello".to_vec();
        let p = payload.clone();
        tokio::spawn(async move {
            write_frame(&mut a, &p).await.unwrap();
        });
        assert_eq!(read_frame(&mut b).await.unwrap(), payload);
    }

    #[tokio::test]
    async fn json_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let value = serde_json::json!({"schema": 2, "x": [1, 2, 3]});
        let v = value.clone();
        tokio::spawn(async move {
            write_json(&mut a, &v).await.unwrap();
        });
        let back: serde_json::Value = read_json(&mut b).await.unwrap();
        assert_eq!(back, value);
    }

    #[tokio::test]
    async fn rejects_oversized_frame() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            a.write_all(&(MAX_FRAME_LEN as u32 + 1).to_be_bytes())
                .await
                .unwrap();
        });
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
