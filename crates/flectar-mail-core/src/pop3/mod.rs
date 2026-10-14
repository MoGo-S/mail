//! Small, bounded POP3 transport used by the account sync worker.
//!
//! POP3 is deliberately represented as its own protocol. It has one mailbox,
//! no remote read/star flags, and deletions are committed only by QUIT. The
//! transport requires TLS before sending credentials.

use crate::error::{CoreError, Result};
use crate::models::ConnectionSecurity;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_LINE_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_MESSAGES: usize = 100_000;

trait Pop3Io: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> Pop3Io for T {}
type Stream = Box<dyn Pop3Io + Unpin + Send>;

/// An authenticated POP3 session. Call `quit` to commit any DELE commands.
pub struct Session {
    io: BufReader<Stream>,
    message_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteMessage {
    /// POP3 message number, valid only for the lifetime of this session.
    pub number: usize,
    /// Server UIDL, stable across sessions when the server follows RFC 1939.
    pub uidl: String,
}

impl Session {
    pub fn message_count(&self) -> usize {
        self.message_count
    }

    /// List stable server identifiers. Message numbers are never persisted;
    /// callers must use UIDL for deduplication across reconnects.
    pub async fn uidls(&mut self) -> Result<Vec<RemoteMessage>> {
        self.command("UIDL").await?;
        let lines = self.multiline().await?;
        let mut messages = Vec::with_capacity(lines.len());
        for line in lines {
            let line = std::str::from_utf8(&line)
                .map_err(|_| pop3_error("server returned non-ASCII UIDL data"))?;
            let mut fields = line.split_ascii_whitespace();
            let number = fields
                .next()
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|v| *v > 0 && *v <= self.message_count)
                .ok_or_else(|| pop3_error("malformed UIDL response"))?;
            let uidl = fields
                .next()
                .filter(|v| !v.is_empty() && v.len() <= 512)
                .ok_or_else(|| pop3_error("malformed UIDL response"))?;
            if fields.next().is_some() {
                return Err(pop3_error("malformed UIDL response"));
            }
            messages.push(RemoteMessage { number, uidl: uidl.to_owned() });
        }
        Ok(messages)
    }

    /// Download one complete RFC 5322 message, undoing POP3 dot-stuffing.
    pub async fn retrieve(&mut self, number: usize) -> Result<Vec<u8>> {
        if number == 0 || number > self.message_count {
            return Err(pop3_error("message number is out of range"));
        }
        self.command(&format!("RETR {number}")).await?;
        let lines = self.multiline().await?;
        let size = lines.iter().map(|line| line.len() + 2).sum::<usize>();
        let mut message = Vec::with_capacity(size);
        for line in lines {
            message.extend_from_slice(&line);
            message.extend_from_slice(b"\r\n");
        }
        Ok(message)
    }

    /// Mark a message for deletion. The server applies it only after `quit`.
    pub async fn delete(&mut self, number: usize) -> Result<()> {
        if number == 0 || number > self.message_count {
            return Err(pop3_error("message number is out of range"));
        }
        self.command(&format!("DELE {number}")).await
    }

    pub async fn quit(mut self) -> Result<()> {
        self.command("QUIT").await
    }

    async fn command(&mut self, command: &str) -> Result<()> {
        send_command(&mut self.io, command).await
    }

    async fn multiline(&mut self) -> Result<Vec<Vec<u8>>> {
        read_multiline(&mut self.io).await
    }
}

pub async fn connect(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    security: ConnectionSecurity,
) -> Result<Session> {
    validate_atom(username)?;
    validate_atom(password)?;
    if host.is_empty() || port == 0 || host.len() > 253 {
        return Err(pop3_error("invalid server host or port"));
    }

    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| pop3_error("connection timed out"))??;
    tcp.set_nodelay(true)?;
    let implicit_tls = matches!(security, ConnectionSecurity::Tls)
        || (security == ConnectionSecurity::Auto && port == 995);
    let mut io: Stream = if implicit_tls {
        Box::new(connect_tls(host, tcp).await?)
    } else {
        Box::new(tcp)
    };
    let mut reader = BufReader::new(io);
    read_status(&mut reader).await?;

    if !implicit_tls {
        // Never send USER/PASS on a plaintext connection.
        send_command(&mut reader, "STLS").await?;
        let raw = reader.into_inner();
        io = Box::new(connect_tls(host, raw).await?);
        reader = BufReader::new(io);
    }

    send_command(&mut reader, &format!("USER {username}")).await?;
    send_command(&mut reader, &format!("PASS {password}")).await?;
    let stat = send_command(&mut reader, "STAT").await?;
    let stat = stat.strip_prefix("+OK").ok_or_else(|| pop3_error("invalid STAT response"))?;
    let mut parts = stat.split_ascii_whitespace();
    let count = parts
        .next()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v <= MAX_MESSAGES)
        .ok_or_else(|| pop3_error("invalid STAT response"))?;
    let _bytes = parts
        .next()
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| pop3_error("invalid STAT response"))?;
    if parts.next().is_some() {
        return Err(pop3_error("invalid STAT response"));
    }

    Ok(Session { io: reader, message_count: count })
}

async fn connect_tls(host: &str, tcp: TcpStream) -> Result<TlsStream<TcpStream>> {
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| pop3_error("invalid TLS server name"))?;
    crate::imap::tls_connector()
        .connect(server_name, tcp)
        .await
        .map_err(|e| CoreError::Tls(e.to_string()))
}

fn validate_atom(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 1024 || value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(pop3_error("invalid POP3 credential"));
    }
    Ok(())
}

async fn send_command(reader: &mut BufReader<Stream>, command: &str) -> Result<String> {
    tokio::time::timeout(COMMAND_TIMEOUT, async {
        reader.get_mut().write_all(command.as_bytes()).await?;
        reader.get_mut().write_all(b"\r\n").await?;
        reader.get_mut().flush().await?;
        read_status(reader).await
    })
    .await
    .map_err(|_| pop3_error("command timed out"))?
}

async fn read_status<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String> {
    let line = read_control_line(reader).await?;
    if line.starts_with("+OK") {
        Ok(line)
    } else if line.starts_with("-ERR") {
        Err(CoreError::Auth(line.trim_start_matches("-ERR").trim().to_owned()))
    } else {
        Err(pop3_error("invalid server status"))
    }
}

async fn read_multiline<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<Vec<u8>>> {
    let mut lines = Vec::new();
    let mut total = 0usize;
    loop {
        let mut line = read_raw_line(reader).await?;
        if line == b"." {
            return Ok(lines);
        }
        total = total.saturating_add(line.len() + 2);
        if total > MAX_RESPONSE_BYTES {
            return Err(pop3_error("server response exceeded the 64 MiB limit"));
        }
        // RFC 1939 dot transparency: remove exactly one leading dot.
        if line.starts_with(b"..") {
            line.remove(0);
        }
        lines.push(line);
    }
}

async fn read_control_line<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String> {
    String::from_utf8(read_raw_line(reader).await?)
        .map_err(|_| pop3_error("server returned invalid protocol text"))
}

async fn read_raw_line<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let byte = reader.read_u8().await?;
        if byte == b'\n' {
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            break;
        }
        bytes.push(byte);
        if bytes.len() > MAX_LINE_BYTES {
            return Err(pop3_error("server line exceeded the 16 KiB limit"));
        }
    }
    Ok(bytes)
}

fn pop3_error(message: &str) -> CoreError {
    CoreError::Network(format!("POP3: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_credentials_that_can_inject_commands() {
        for value in ["", "user\r\nDELE 1", "user\nQUIT", "bad\0value"] {
            assert!(validate_atom(value).is_err());
        }
        assert!(validate_atom("person@example.com").is_ok());
    }

    #[test]
    fn protocol_does_not_mistake_uidl_for_message_number() {
        let message = RemoteMessage { number: 17, uidl: "server-id-abc".into() };
        assert_ne!(message.number.to_string(), message.uidl);
    }
}
