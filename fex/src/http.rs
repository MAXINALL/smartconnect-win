//! Just enough HTTP/1.1 to `GET /download` from the fex server: one request per connection
//! (`Connection: close`), a `Content-Length` or chunked body, a size cap.

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEAD: usize = 16 * 1024;

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Percent-encodes a query value (everything but RFC 3986 unreserved characters).
pub fn encode_query_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The request bytes for `GET target`.
pub fn request(host: &str, target: &str) -> String {
    format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: smartconnect-fex\r\nAccept: */*\r\nConnection: close\r\n\r\n")
}

/// Sends `GET target` on `stream` and reads the response, refusing bodies over `max_body` bytes.
pub async fn get<S>(stream: &mut S, host: &str, target: &str, max_body: usize) -> Result<Response>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request(host, target).as_bytes()).await?;
    stream.flush().await?;
    let mut buf = Vec::with_capacity(64 * 1024);
    let mut chunk = vec![0u8; 64 * 1024];
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEAD {
            bail!("HTTP response head too large");
        }
        let n = read_some(stream, &mut chunk).await?;
        if n == 0 {
            bail!("connection closed before the HTTP response head");
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let (status, headers) = parse_head(&buf[..head_end])?;
    let mut body = buf.split_off(head_end);
    let header = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str());
    let chunked = header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let length = match header("content-length") {
        Some(v) if !chunked => Some(v.trim().parse::<usize>().context("bad Content-Length")?),
        _ => None,
    };
    if length.is_some_and(|l| l > max_body) {
        bail!("HTTP body of {} bytes is over the {max_body}-byte limit", length.unwrap_or_default());
    }
    loop {
        if length.is_some_and(|l| body.len() >= l) {
            break;
        }
        if body.len() > max_body + if chunked { 64 * 1024 } else { 0 } {
            bail!("HTTP body over the {max_body}-byte limit");
        }
        let n = read_some(stream, &mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    if let Some(l) = length {
        if body.len() < l {
            bail!("HTTP body truncated: {} of {l} bytes", body.len());
        }
        body.truncate(l);
    } else if chunked {
        body = decode_chunked(&body)?;
        if body.len() > max_body {
            bail!("HTTP body over the {max_body}-byte limit");
        }
    }
    Ok(Response { status, headers, body })
}

/// Reads once; a peer that closes without a TLS close_notify counts as end of stream.
async fn read_some<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut [u8]) -> Result<usize> {
    match stream.read(buf).await {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
        Err(e) => Err(e.into()),
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parses the status line and headers (the head including its final blank line).
pub fn parse_head(head: &[u8]) -> Result<(u16, Vec<(String, String)>)> {
    let text = std::str::from_utf8(head).context("HTTP head is not UTF-8")?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        bail!("not an HTTP/1.x response: {status_line:?}");
    }
    let status = parts.next().and_then(|s| s.parse().ok()).with_context(|| format!("bad status line {status_line:?}"))?;
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Ok((status, headers))
}

/// Decodes a `Transfer-Encoding: chunked` body (trailers ignored).
pub fn decode_chunked(mut data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = find(data, b"\r\n").context("chunked body: missing chunk size line")?;
        let size_line = std::str::from_utf8(&data[..eol]).context("chunked body: bad size line")?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16).context("chunked body: bad chunk size")?;
        data = &data[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if data.len() < size + 2 {
            bail!("chunked body truncated");
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_query_values() {
        // A base64 token with the characters that need escaping.
        assert_eq!(encode_query_value("Ab+/9z=="), "Ab%2B%2F9z%3D%3D");
        assert_eq!(encode_query_value("TASK-0_1.~"), "TASK-0_1.~");
    }

    #[test]
    fn builds_the_request() {
        assert_eq!(
            request("192.168.1.20:50000", "/download?taskId=T1"),
            "GET /download?taskId=T1 HTTP/1.1\r\nHost: 192.168.1.20:50000\r\nUser-Agent: smartconnect-fex\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn parses_heads_and_chunks() {
        let (status, headers) =
            parse_head(b"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: 5\r\n\r\n").unwrap();
        assert_eq!(status, 200);
        assert_eq!(headers[1], ("Content-Length".to_owned(), "5".to_owned()));
        assert!(parse_head(b"SSH-2.0-x\r\n\r\n").is_err());
        assert_eq!(decode_chunked(b"4\r\nWiki\r\n5;x=1\r\npedia\r\n0\r\n\r\n").unwrap(), b"Wikipedia");
        assert!(decode_chunked(b"9\r\nabc").is_err());
    }

    #[tokio::test]
    async fn reads_a_content_length_body() {
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        let srv = tokio::spawn(async move {
            let mut req = vec![0u8; 1024];
            let n = server.read(&mut req).await.unwrap();
            assert!(req[..n].starts_with(b"GET /download?taskId=T1 HTTP/1.1\r\n"));
            server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nPK!").await.unwrap();
        });
        let r = get(&mut client, "h", "/download?taskId=T1", 10).await.unwrap();
        srv.await.unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"PK!"[..]));
        assert_eq!(r.header("content-length"), Some("3"));
    }

    #[tokio::test]
    async fn enforces_the_size_cap() {
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let mut req = vec![0u8; 1024];
            let _ = server.read(&mut req).await;
            let _ = server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n").await;
        });
        assert!(get(&mut client, "h", "/", 10).await.is_err());
    }
}
