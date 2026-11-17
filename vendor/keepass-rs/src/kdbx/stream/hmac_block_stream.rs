//! HMAC block stream for KDBX 4.0
//!
//! Provides read/write streaming with per-block HMAC-SHA-256 integrity verification.
//! This is the unified module used by both kdbx4_reader and kdbx4_writer.

use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::model::exception::{DatabaseError, DatabaseResult};

type HmacSha512 = Hmac<Sha512>;

/// Default HMAC block size (1 MB)
pub const HMAC_BLOCK_SIZE: usize = 1024 * 1024;

// ─── Key derivation ──────────────────────────────────────────────

/// Derive the per-block HMAC key from the master key and block index.
/// Uses HMAC-SHA-512(master_key, block_index_le_bytes) and takes first 32 bytes.
pub fn derive_block_hmac_key(master_key: &[u8], block_index: u64) -> DatabaseResult<[u8; 64]> {
    let mut mac = HmacSha512::new_from_slice(master_key)
        .map_err(|e| DatabaseError::EncryptionError(e.to_string()))?;
    mac.update(&block_index.to_le_bytes());
    Ok(mac.finalize().into_bytes().into())
}

/// Compute HMAC-SHA-256 for a data block.
/// Input: key || block_index_le || data
pub fn compute_block_hmac(key: &[u8], block_index: u64, data: &[u8]) -> DatabaseResult<[u8; 32]> {
    let mut msg = Vec::with_capacity(8 + data.len());
    msg.extend_from_slice(&block_index.to_le_bytes());
    msg.extend_from_slice(data);
    crate::crypto::HmacCompute::hmac_sha256(key, &msg)
        .map_err(|e| DatabaseError::EncryptionError(e.to_string()))
}

/// Compute the header HMAC for KDBX 4.0 integrity check.
pub fn compute_header_hmac(master_key: &[u8], header_bytes: &[u8]) -> DatabaseResult<[u8; 32]> {
    let mut input = Vec::with_capacity(32 + 1 + 8);
    input.extend_from_slice(master_key);
    input.push(0x01);
    input.extend_from_slice(&(header_bytes.len() as u64).to_le_bytes());
    let hmac_key = crate::crypto::HashEngine::sha256(&input);
    crate::crypto::HmacCompute::hmac_sha256(&hmac_key, header_bytes)
        .map_err(|e| DatabaseError::EncryptionError(e.to_string()))
}

// ─── Stream Reader ───────────────────────────────────────────────

pub fn standard_block_key(base: &[u8], index: u64) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new(); h.update(index.to_le_bytes()); h.update(base); h.finalize().into()
}
pub fn standard_header_hmac(base: &[u8], header: &[u8]) -> DatabaseResult<[u8; 32]> {
    crate::crypto::HmacCompute::hmac_sha256(&standard_block_key(base, u64::MAX), header)
        .map_err(|e| DatabaseError::EncryptionError(e.to_string()))
}
pub fn standard_read<R: Read>(reader: &mut R, base: &[u8]) -> DatabaseResult<Vec<u8>> {
    let mut result = Vec::new();
    for index in 0u64.. {
        let mut stored = [0u8; 32]; reader.read_exact(&mut stored)?;
        let size = reader.read_u32::<LittleEndian>()?;
        if size > 16 * 1024 * 1024 { return Err(DatabaseError::InvalidFormat("HMAC block too large".into())); }
        let mut data = vec![0; size as usize]; reader.read_exact(&mut data)?;
        let mut message = Vec::with_capacity(12 + data.len());
        message.extend_from_slice(&index.to_le_bytes()); message.extend_from_slice(&size.to_le_bytes()); message.extend_from_slice(&data);
        let expected = crate::crypto::HmacCompute::hmac_sha256(&standard_block_key(base, index), &message)
            .map_err(|e| DatabaseError::EncryptionError(e.to_string()))?;
        if stored != expected { return Err(DatabaseError::DecryptionError("HMAC block mismatch".into())); }
        if size == 0 { return Ok(result); }
        result.extend_from_slice(&data);
    }
    unreachable!()
}
pub fn standard_write<W: Write>(writer: &mut W, base: &[u8], data: &[u8]) -> DatabaseResult<()> {
    for (index, chunk) in data.chunks(HMAC_BLOCK_SIZE).chain(std::iter::once(&[][..])).enumerate() {
        let index = index as u64; let size = chunk.len() as u32;
        let mut message = Vec::with_capacity(12 + chunk.len());
        message.extend_from_slice(&index.to_le_bytes()); message.extend_from_slice(&size.to_le_bytes()); message.extend_from_slice(chunk);
        let hash = crate::crypto::HmacCompute::hmac_sha256(&standard_block_key(base, index), &message)
            .map_err(|e| DatabaseError::EncryptionError(e.to_string()))?;
        writer.write_all(&hash)?; writer.write_u32::<LittleEndian>(size)?; writer.write_all(chunk)?;
    }
    Ok(())
}

/// Read an HMAC block stream, verifying each block's integrity.
pub fn read_hmac_block_stream<R: Read>(
    reader: &mut R,
    master_key: &[u8],
) -> DatabaseResult<Vec<u8>> {
    let mut result = Vec::new();
    let mut block_index: u64 = 0;

    loop {
        let mut stored_hmac = [0u8; 32];
        reader.read_exact(&mut stored_hmac)?;

        let block_size = reader.read_u64::<LittleEndian>()?;
        if block_size == 0 {
            break;
        }

        let mut data = vec![0u8; block_size as usize];
        reader.read_exact(&mut data)?;

        let block_key = derive_block_hmac_key(master_key, block_index)?;
        let expected = compute_block_hmac(&block_key[..32], block_index, &data)?;
        if stored_hmac != expected {
            return Err(DatabaseError::DecryptionError(format!(
                "HMAC mismatch in block {block_index}"
            )));
        }

        result.extend_from_slice(&data);
        block_index += 1;
    }

    Ok(result)
}

// ─── Stream Writer ───────────────────────────────────────────────

/// Write data as an HMAC block stream.
pub fn write_hmac_block_stream<W: Write>(
    writer: &mut W,
    master_key: &[u8],
    data: &[u8],
) -> DatabaseResult<()> {
    for (i, chunk) in data.chunks(HMAC_BLOCK_SIZE).enumerate() {
        let block_index = i as u64;
        let block_key = derive_block_hmac_key(master_key, block_index)?;
        let hmac_val = compute_block_hmac(&block_key[..32], block_index, chunk)?;

        writer.write_all(&hmac_val)?;
        writer.write_u64::<LittleEndian>(chunk.len() as u64)?;
        writer.write_all(chunk)?;
    }

    // Terminator block
    let term_index = (data.len().div_ceil(HMAC_BLOCK_SIZE)) as u64;
    let term_key = derive_block_hmac_key(master_key, term_index)?;
    let term_hmac = compute_block_hmac(&term_key[..32], term_index, &[])?;
    writer.write_all(&term_hmac)?;
    writer.write_u64::<LittleEndian>(0)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_hmac_block_stream_roundtrip() {
        let data = vec![0x42u8; 2048];
        let key = b"master_key_for_test";

        let mut buf = Vec::new();
        write_hmac_block_stream(&mut buf, key, &data).unwrap();

        let mut cursor = Cursor::new(buf);
        let result = read_hmac_block_stream(&mut cursor, key).unwrap();

        assert_eq!(result, data);
    }

    #[test]
    fn test_hmac_block_stream_empty() {
        let data: Vec<u8> = Vec::new();
        let key = b"master_key";

        let mut buf = Vec::new();
        write_hmac_block_stream(&mut buf, key, &data).unwrap();

        let mut cursor = Cursor::new(buf);
        let result = read_hmac_block_stream(&mut cursor, key).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_hmac_block_stream_tamper_detected() {
        let data = vec![0x42u8; 1024];
        let key = b"master_key";

        let mut buf = Vec::new();
        write_hmac_block_stream(&mut buf, key, &data).unwrap();

        // Tamper with the data (after HMAC, before block data)
        // Layout: [32-byte hmac][8-byte size][data...]
        if buf.len() > 50 {
            buf[44] ^= 0xFF;
        }

        let mut cursor = Cursor::new(buf);
        assert!(read_hmac_block_stream(&mut cursor, key).is_err());
    }

    #[test]
    fn test_hmac_block_stream_wrong_key() {
        let data = vec![0x42u8; 512];
        let key1 = b"correct_key";
        let key2 = b"wrong_key";

        let mut buf = Vec::new();
        write_hmac_block_stream(&mut buf, key1, &data).unwrap();

        let mut cursor = Cursor::new(buf);
        assert!(read_hmac_block_stream(&mut cursor, key2).is_err());
    }

    #[test]
    fn test_derive_block_hmac_key_deterministic() {
        let key = b"test_key";
        let k1 = derive_block_hmac_key(key, 0).unwrap();
        let k2 = derive_block_hmac_key(key, 0).unwrap();
        assert_eq!(k1, k2);

        let k3 = derive_block_hmac_key(key, 1).unwrap();
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_compute_header_hmac() {
        let master_key = b"master";
        let header = b"header_bytes";
        let h1 = compute_header_hmac(master_key, header).unwrap();
        let h2 = compute_header_hmac(master_key, header).unwrap();
        assert_eq!(h1, h2);

        // Different header → different HMAC
        let h3 = compute_header_hmac(master_key, b"different").unwrap();
        assert_ne!(h1, h3);
    }
}
