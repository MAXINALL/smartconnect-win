//! Reads the zip that `/download` returns, and writes one for our own sends ([`write_stored`]).
//!
//! The phone's library writes it in streaming mode (general-purpose flag bit 3: sizes and CRC in a
//! data descriptor after each entry, zeros in the local headers), so entries are located through
//! the central directory, which has the real sizes. Icon archives are Store-only (PNGs are already
//! compressed); Deflate is supported too. Zip64 and encryption are not.

use anyhow::{Context, Result, bail};

const EOCD_SIG: u32 = 0x0605_4b50;
const CDH_SIG: u32 = 0x0201_4b50;
const LFH_SIG: u32 = 0x0403_4b50;
const METHOD_STORE: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
/// Refuse to inflate any single entry past this, whatever its header claims.
const MAX_ENTRY: usize = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The name as stored (may contain `/` for nested paths; callers sanitise).
    pub name: String,
    pub data: Vec<u8>,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16> {
    let s = b.get(at..at + 2).context("zip: truncated")?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32> {
    let s = b.get(at..at + 4).context("zip: truncated")?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// CRC-32 (IEEE 802.3, reflected, as zip uses).
pub fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
    !data.iter().fold(!0u32, |c, &b| TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8))
}

/// Every file entry (directories skipped), in central-directory order.
pub fn read_all(archive: &[u8]) -> Result<Vec<Entry>> {
    // End of central directory: 22 bytes + up to 64 KiB of comment, searched from the end.
    if archive.len() < 22 {
        bail!("zip: too short");
    }
    let lowest = archive.len().saturating_sub(22 + 0xFFFF);
    let eocd = (lowest..=archive.len() - 22)
        .rev()
        .find(|&i| u32_at(archive, i).ok() == Some(EOCD_SIG))
        .context("zip: no end-of-central-directory record")?;
    let count = u16_at(archive, eocd + 10)? as usize;
    let cd_size = u32_at(archive, eocd + 12)?;
    let cd_offset = u32_at(archive, eocd + 16)?;
    if count == 0xFFFF || cd_size == u32::MAX || cd_offset == u32::MAX {
        bail!("zip: Zip64 archives are not supported");
    }
    if count > MAX_ENTRIES {
        bail!("zip: too many entries");
    }
    let mut at = cd_offset as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if u32_at(archive, at)? != CDH_SIG {
            bail!("zip: bad central directory header at {at}");
        }
        let flags = u16_at(archive, at + 8)?;
        let method = u16_at(archive, at + 10)?;
        let crc = u32_at(archive, at + 16)?;
        let csize = u32_at(archive, at + 20)? as usize;
        let usize_ = u32_at(archive, at + 24)? as usize;
        let name_len = u16_at(archive, at + 28)? as usize;
        let extra_len = u16_at(archive, at + 30)? as usize;
        let comment_len = u16_at(archive, at + 32)? as usize;
        let local = u32_at(archive, at + 42)? as usize;
        let name_bytes = archive.get(at + 46..at + 46 + name_len).context("zip: truncated name")?;
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        at += 46 + name_len + extra_len + comment_len;

        if name.ends_with('/') {
            continue;
        }
        if flags & 1 != 0 {
            bail!("zip: {name} is encrypted");
        }
        if csize == u32::MAX as usize || usize_ == u32::MAX as usize {
            bail!("zip: {name} needs Zip64");
        }
        if usize_ > MAX_ENTRY {
            bail!("zip: {name} is too large ({usize_} bytes)");
        }
        if u32_at(archive, local)? != LFH_SIG {
            bail!("zip: bad local header for {name}");
        }
        let start = local + 30 + u16_at(archive, local + 26)? as usize + u16_at(archive, local + 28)? as usize;
        let raw = archive.get(start..start + csize).with_context(|| format!("zip: {name} runs past the end"))?;
        let data = match method {
            METHOD_STORE => {
                if csize != usize_ {
                    bail!("zip: stored entry {name} has mismatched sizes");
                }
                raw.to_vec()
            }
            METHOD_DEFLATE => miniz_oxide::inflate::decompress_to_vec_with_limit(raw, usize_)
                .map_err(|e| anyhow::anyhow!("zip: inflating {name}: {e:?}"))?,
            m => bail!("zip: {name} uses unsupported compression method {m}"),
        };
        if data.len() != usize_ {
            bail!("zip: {name} is {} bytes, expected {usize_}", data.len());
        }
        if crc32(&data) != crc {
            bail!("zip: CRC mismatch in {name}");
        }
        out.push(Entry { name, data });
    }
    Ok(out)
}

/// A zip of `entries` (name, bytes), all stored uncompressed (images are compressed already), with
/// sizes and CRCs in the local headers, as any reader accepts. Names are UTF-8 (flag bit 11).
pub fn write_stored(entries: &[(&str, &[u8])]) -> Vec<u8> {
    const FLAG_UTF8: u16 = 1 << 11;
    // 1980-01-01 00:00, the zip epoch: the phone doesn't look at dates.
    const DOS_DATE: u16 = (1 << 5) | 1;
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let offset = out.len() as u32;
        let crc = crc32(data);
        let (len, name_len) = (data.len() as u32, name.len() as u16);
        let header = |out: &mut Vec<u8>, central_entry: bool| {
            out.extend_from_slice(&(if central_entry { CDH_SIG } else { LFH_SIG }).to_le_bytes());
            if central_entry {
                out.extend_from_slice(&20u16.to_le_bytes()); // version made by
            }
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&FLAG_UTF8.to_le_bytes());
            out.extend_from_slice(&METHOD_STORE.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // time
            out.extend_from_slice(&DOS_DATE.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes()); // compressed
            out.extend_from_slice(&len.to_le_bytes()); // uncompressed
            out.extend_from_slice(&name_len.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra
            if central_entry {
                out.extend_from_slice(&0u16.to_le_bytes()); // comment
                out.extend_from_slice(&0u16.to_le_bytes()); // disk
                out.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
                out.extend_from_slice(&0u32.to_le_bytes()); // external attributes
                out.extend_from_slice(&offset.to_le_bytes());
            }
            out.extend_from_slice(name.as_bytes());
        };
        header(&mut out, false);
        out.extend_from_slice(data);
        header(&mut central, true);
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]); // disk numbers
    let count = entries.len() as u16;
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn stored_zips_round_trip() {
        let zip = write_stored(&[("Screenshot 1.png", b"\x89PNG fake"), ("b.txt", b"")]);
        let back = read_all(&zip).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!((back[0].name.as_str(), back[0].data.as_slice()), ("Screenshot 1.png", &b"\x89PNG fake"[..]));
        assert_eq!(back[1].data, b"");
    }

    /// Builds a streaming-mode zip like the phone's (flag bit 3, zeros in the local headers, a data
    /// descriptor after each entry). `deflate` stores each entry as one raw Deflate block.
    pub(crate) fn build_zip(entries: &[(&str, &[u8])], deflate: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let crc = crc32(data);
            let body = if deflate { miniz_oxide::deflate::compress_to_vec(data, 6) } else { data.to_vec() };
            let method: u16 = if deflate { 8 } else { 0 };
            let offset = out.len() as u32;
            out.extend_from_slice(&LFH_SIG.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&8u16.to_le_bytes()); // flags: data descriptor
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 4]); // time, date
            out.extend_from_slice(&[0; 12]); // crc, sizes: in the descriptor
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&body);
            out.extend_from_slice(&0x0807_4b50u32.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());

            central.extend_from_slice(&CDH_SIG.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&8u16.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(body.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 12]); // extra, comment, disk, int attr, ext attr (part)
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn crc32_known_answers() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414F_A339);
    }

    #[test]
    fn reads_streaming_store_and_deflate_archives() {
        let png = b"\x89PNG\r\n\x1a\nnot really an image";
        for deflate in [false, true] {
            let zip = build_zip(&[("a.b_a.b.Main.png", png), ("dir/", b""), ("10_c.d_c.d.Main.png", b"x")], deflate);
            let entries = read_all(&zip).unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0], Entry { name: "a.b_a.b.Main.png".into(), data: png.to_vec() });
            assert_eq!(entries[1].name, "10_c.d_c.d.Main.png");
        }
    }

    #[test]
    fn rejects_corruption() {
        let mut zip = build_zip(&[("a.png", b"hello world")], false);
        assert!(read_all(&zip[..zip.len() - 1]).is_err());
        let i = zip.windows(5).position(|w| w == b"hello").unwrap();
        zip[i] = b'j';
        assert!(read_all(&zip).unwrap_err().to_string().contains("CRC"));
        assert!(read_all(b"PK").is_err());
    }
}
