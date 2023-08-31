use std::io::Read;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use async_trait::async_trait;
use log::error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NettyReadError {
    #[error("{0}")]
    IoError(std::io::Error),
    #[error("Was not a netty packet, but a Legacy ServerListPing")]
    LegacyServerListPing,
}

impl From<std::io::Error> for NettyReadError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

impl From<std::io::ErrorKind> for NettyReadError {
    fn from(value: std::io::ErrorKind) -> Self {
        Self::IoError(value.into())
    }
}

pub trait ReadExtNetty: Read {
    fn read_u8(&mut self) -> Result<u8, NettyReadError> {
        let mut buf = [0u8];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u16(&mut self) -> Result<u16, NettyReadError> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    fn read_string(&mut self) -> Result<String, NettyReadError> {
        let len = self.read_varint()?;
        let mut buf = vec![0u8; len as usize];
        self.read_exact(&mut buf)?;
        String::from_utf8(buf).map_err(|_| std::io::ErrorKind::InvalidData.into())
    }

    fn read_varint(&mut self) -> Result<i32, NettyReadError> {
        let mut res = 0i32;
        for i in 0..5 {
            let part = self.read_u8()?;
            res |= (part as i32 & 0x7F) << (7 * i);
            if part & 0x80 == 0 {
                return Ok(res);
            }
        }
        error!("Varint is invalid");
        Err(std::io::ErrorKind::InvalidData.into())
    }
}

pub async fn read_packet(mut reader: impl AsyncReadExt + Unpin) -> Result<Vec<u8>, NettyReadError> {
    let len = read_varint(&mut reader).await?;
    let mut buf = vec![0u8; len as usize];
    if len == 254 {
        let mut temp = [0u8];
        reader.read_exact(&mut temp).await?;
        if temp[0] == 0xFA {
            return Err(NettyReadError::LegacyServerListPing);
        }
        buf[0] = temp[0];
        reader.read_exact(&mut buf[1..]).await?;
    } else {
        reader.read_exact(&mut buf).await?;
    }
    Ok(buf)
}

async fn read_varint(mut reader: impl AsyncReadExt + Unpin) -> Result<i32, NettyReadError> {
    let mut res = 0i32;
    for i in 0..5 {
        let part = reader.read_u8().await?;
        res |= (part as i32 & 0x7F) << (7 * i);
        if part & 0x80 == 0 {
            return Ok(res);
        }
    }
    error!("Varint is invalid");
    Err(std::io::ErrorKind::InvalidData.into())
}

impl<T: Read> ReadExtNetty for T {}

#[async_trait]
pub trait WriteExtNetty: AsyncWriteExt + Unpin {
    async fn write_varint(&mut self, mut val: i32) -> std::io::Result<()> {
        for _ in 0..5 {
            if val & !0x7F == 0 {
                self.write_all(&[val as u8]).await?;
                return Ok(());
            }
            self.write_all(&[(val & 0x7F | 0x80) as u8]).await?;
            val >>= 7;
        }
        Err(std::io::ErrorKind::InvalidData.into())
    }

    async fn write_string(&mut self, s: &str) -> std::io::Result<()> {
        self.write_varint(s.len() as i32).await?;
        self.write_all(s.as_bytes()).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Handshake {
    protocol_version: i32,
    server_address: String,
    server_port: u16,
    pub next_state: HandshakeType,
}

#[derive(Debug, Clone, Copy)]
#[repr(i32)]
pub enum HandshakeType {
    Status = 1,
    Login = 2,
}

impl Handshake {
    pub fn new(mut packet: &[u8]) -> anyhow::Result<Self> {
        let packet_type = packet.read_varint()?;
        if packet_type != 0 {
            Err(anyhow::anyhow!("Not a Handshake packet"))
        } else {
            let protocol_version = packet.read_varint()?;
            let server_address = packet.read_string()?;
            let server_port = ReadExtNetty::read_u16(&mut packet)?;
            let next_state = match packet.read_varint()? {
                1 => HandshakeType::Status,
                2 => HandshakeType::Login,
                _ => return Err(anyhow::anyhow!("Invalid next state")),
            };
            Ok(Self {
                protocol_version,
                server_address,
                server_port,
                next_state,
            })
        }
    }

    pub async fn send(
        &self,
        mut writer: impl AsyncWriteExt + Unpin + Send,
    ) -> tokio::io::Result<()> {
        let mut buf = vec![];
        buf.write_varint(0).await?;
        buf.write_varint(self.protocol_version).await?;
        buf.write_string(&self.server_address).await?;
        buf.write_all(&self.server_port.to_be_bytes()).await?;
        buf.write_varint(self.next_state as i32).await?;
        writer.write_varint(buf.len() as i32).await?;
        writer.write_all(&buf).await?;
        Ok(())
    }

    pub fn normalized_address(&self) -> Option<String> {
        crate::validation::validate_and_normalize_domain(
            if let Some(fml3_stripped) = self.server_address.strip_suffix("\0FML3\0") {
                fml3_stripped
            } else if let Some(fml2_stripped) = self.server_address.strip_suffix("\0FML2\0") {
                fml2_stripped
            } else if let Some(fml_stripped) = self.server_address.strip_suffix("\0FML\0") {
                fml_stripped
            } else {
                &self.server_address
            },
        )
    }
}

impl<T: AsyncWriteExt + Unpin> WriteExtNetty for T {}
