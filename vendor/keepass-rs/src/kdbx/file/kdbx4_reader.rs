//! KDBX 4.0 complete read pipeline
//!
//! Pipeline: signature → outer header → header HMAC → HMAC block stream
//!           → decrypt → inner header → decompress → inner stream → XML → Database

use std::io::Read;
use sha2::{Digest, Sha256, Sha512};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::crypto::compression::CompressionAlgorithm;
use crate::crypto::inner_stream::create_inner_stream;
use crate::kdbx::file::header::{
    header_field_4, inner_header_field_4, CrsAlgorithm, KdbxHeader4, KdbxInnerHeader4,
    FILE_VERSION_4,
};
use crate::kdbx::file::reader::DatabaseReader;
use crate::kdbx::kdf::create_kdf;
use crate::kdbx::stream::hmac_block_stream::{compute_header_hmac, read_hmac_block_stream, standard_header_hmac, standard_read};
use crate::kdbx::xml::KdbxXmlReader;
use crate::model::db::composite_key::CompositeKey;
use crate::model::db::database::{Database, DatabaseVersion};
use crate::model::exception::{DatabaseError, DatabaseResult};

/// Read a KDBX 4.0 database from a reader.
pub fn read_kdbx4<R: Read>(
    reader: &mut R,
    composite_key: &CompositeKey,
) -> DatabaseResult<Database> {
    let mut header_buf = Vec::new();
    let version = { let mut tee = TeeReader::new(reader, &mut header_buf); DatabaseReader::detect_version(&mut tee)? };
    if version != DatabaseVersion::KDBX4 { return Err(DatabaseError::InvalidVersion("Expected KDBX4".into())); }
    let header = { let mut tee = TeeReader::new(reader, &mut header_buf); read_kdbx4_outer_header_from(&mut tee)? };
    let (master_key, hmac_base) = derive_master_key(composite_key, &header)?;
    let mut first = [0u8; 32]; reader.read_exact(&mut first)?;
    let standard = first.as_slice() == Sha256::digest(&header_buf).as_slice();
    let encrypted = if standard {
        let mut hmac = [0u8; 32]; reader.read_exact(&mut hmac)?;
        if hmac != standard_header_hmac(&hmac_base, &header_buf)? { return Err(DatabaseError::DecryptionError("Header HMAC mismatch".into())); }
        standard_read(reader, &hmac_base)?
    } else {
        if first != compute_header_hmac(&master_key, &header_buf)? { return Err(DatabaseError::DecryptionError("Header integrity check failed".into())); }
        read_hmac_block_stream(reader, &master_key)?
    };
    let cipher = crate::crypto::cipher_engine::create_cipher_engine(header.encryption_algorithm);
    let decrypted = cipher.decrypt(&master_key, &header.encryption_iv, &encrypted)
        .map_err(|e| DatabaseError::DecryptionError(e.to_string()))?;
    let data = if standard && header.compression == CompressionAlgorithm::Gzip {
        crate::crypto::compression::decompress(&decrypted)?
    } else { decrypted };
    let mut cursor = std::io::Cursor::new(&data);
    let mut inner = read_kdbx4_inner_header(&mut cursor)?;
    if !inner.binaries.is_empty() {
        return Err(DatabaseError::Unsupported("KDBX 4 attachments are not supported; database was not modified".into()));
    }
    let remaining = &data[cursor.position() as usize..];
    let xml_bytes = if !standard && header.compression == CompressionAlgorithm::Gzip {
        crate::crypto::compression::decompress(remaining)?
    } else { remaining.to_vec() };

    // 9. Parse XML with inner stream cipher
    let mut inner_stream =
        create_inner_stream(inner.inner_random_stream, &inner.inner_random_stream_key)?;
    // Protected binaries in the KDBX4 inner header share the same continuous
    // random stream as protected XML fields. Consume their bytes first, in
    // inner-header order, or every protected value in XML is shifted and
    // decrypts to unrelated text whenever a protected attachment is present.
    for binary in &mut inner.binaries {
        if binary.is_protected() {
            inner_stream.process(&mut binary.data);
        }
    }
    let xml_str =
        std::str::from_utf8(&xml_bytes).map_err(|e| DatabaseError::InvalidFormat(e.to_string()))?;
    let mut db = KdbxXmlReader::read(xml_str, inner_stream.as_mut())?;
    // Preserve the outer-header cipher when the database is saved again.
    db.encryption_algorithm = header.encryption_algorithm;
    db.compression = header.compression;
    db.kdf_parameters = header.kdf_parameters;

    Ok(db)
}

/// Derive the master key from composite key and header.
fn derive_master_key(
    composite_key: &CompositeKey,
    header: &KdbxHeader4,
) -> DatabaseResult<(Vec<u8>, Vec<u8>)> {
    let raw_key = composite_key.build_raw_key();
    if raw_key.is_empty() {
        return Err(DatabaseError::InvalidKey);
    }

    let kdf_uuid = header
        .kdf_parameters
        .as_ref()
        .map(|p| p.kdf_uuid)
        .ok_or_else(|| DatabaseError::InvalidFormat("No KDF parameters".into()))?;

    let kdf =
        create_kdf(&kdf_uuid).ok_or_else(|| DatabaseError::InvalidFormat("Unknown KDF".into()))?;
    let params = header
        .kdf_parameters
        .as_ref()
        .ok_or_else(|| DatabaseError::InvalidFormat("No KDF parameters".into()))?;

    let transformed = kdf.transform(&raw_key, params)?;

    let mut combined = Vec::with_capacity(header.master_seed.len() + transformed.len());
    combined.extend_from_slice(&header.master_seed);
    combined.extend_from_slice(&transformed);
    let master = crate::crypto::HashEngine::sha256(&combined).to_vec();
    combined.push(1);
    Ok((master, Sha512::digest(&combined).to_vec()))
}

/// Read KDBX 4.0 outer header from reader, TeeReader captures all bytes.
fn read_kdbx4_outer_header_from<R: Read>(reader: &mut R) -> DatabaseResult<KdbxHeader4> {
    let mut header = KdbxHeader4 {
        version: FILE_VERSION_4,
        encryption_algorithm: crate::crypto::encryption_algorithm::EncryptionAlgorithm::AesRijndael,
        compression: CompressionAlgorithm::Gzip,
        master_seed: Vec::new(),
        encryption_iv: Vec::new(),
        kdf_parameters: None,
        public_custom_data: Vec::new(),
    };

    loop {
        let field_id = reader.read_u8()?;
        let field_size = reader.read_u32::<LittleEndian>()? as usize;

        if field_size > 0 {
            let mut data = vec![0u8; field_size];
            reader.read_exact(&mut data)?;

            match field_id {
                header_field_4::END_OF_HEADER => break,
                header_field_4::CIPHER_ID => {
                    let uuid = uuid::Uuid::from_slice(&data)
                        .map_err(|e| DatabaseError::InvalidFormat(e.to_string()))?;
                    header.encryption_algorithm =
                        crate::crypto::encryption_algorithm::EncryptionAlgorithm::from_uuid(&uuid)
                            .unwrap_or(
                            crate::crypto::encryption_algorithm::EncryptionAlgorithm::AesRijndael,
                        );
                }
                header_field_4::COMPRESSION_FLAGS => {
                    if data.len() >= 4 {
                        let flags = u32::from_le_bytes(data[..4].try_into().map_err(|_| {
                            DatabaseError::InvalidFormat("Invalid COMPRESSION_FLAGS".into())
                        })?);
                        header.compression = CompressionAlgorithm::from_id(flags)
                            .unwrap_or(CompressionAlgorithm::Gzip);
                    }
                }
                header_field_4::MASTER_SEED => header.master_seed = data,
                header_field_4::ENCRYPTION_IV => header.encryption_iv = data,
                header_field_4::KDF_PARAMETERS => {
                    header.kdf_parameters =
                        crate::kdbx::kdf::kdf_parameters::KdfParameters::deserialize(&data);
                }
                header_field_4::PUBLIC_CUSTOM_DATA => header.public_custom_data = data,
                _ => {}
            }
        } else if field_id == header_field_4::END_OF_HEADER {
            break;
        }
    }

    Ok(header)
}

/// Read KDBX 4.0 inner header.
fn read_kdbx4_inner_header<R: Read>(reader: &mut R) -> DatabaseResult<KdbxInnerHeader4> {
    let mut inner = KdbxInnerHeader4 {
        inner_random_stream: CrsAlgorithm::ChaCha20,
        inner_random_stream_key: Vec::new(),
        binaries: Vec::new(),
    };

    loop {
        let field_id = reader.read_u8()?;
        let field_size = reader.read_u32::<LittleEndian>()? as usize;

        if field_size > 0 {
            let mut data = vec![0u8; field_size];
            reader.read_exact(&mut data)?;

            match field_id {
                inner_header_field_4::END_OF_HEADER => break,
                inner_header_field_4::INNER_RANDOM_STREAM_ID => {
                    if data.len() >= 4 {
                        let id = u32::from_le_bytes(data[..4].try_into().map_err(|_| {
                            DatabaseError::InvalidFormat("Invalid INNER_RANDOM_STREAM_ID".into())
                        })?);
                        inner.inner_random_stream =
                            CrsAlgorithm::from_id(id).unwrap_or(CrsAlgorithm::ChaCha20);
                    }
                }
                inner_header_field_4::INNER_RANDOM_STREAM_KEY => {
                    inner.inner_random_stream_key = data;
                }
                inner_header_field_4::BINARY if !data.is_empty() => {
                    inner.binaries.push(crate::kdbx::file::header::KdbxBinary {
                        flags: data[0],
                        data: data[1..].to_vec(),
                    });
                }
                _ => {}
            }
        } else if field_id == inner_header_field_4::END_OF_HEADER {
            break;
        }
    }

    Ok(inner)
}

/// TeeReader copies all read bytes to a sink buffer.
/// Borrows the inner reader instead of owning it.
struct TeeReader<'a, R> {
    inner: &'a mut R,
    sink: &'a mut Vec<u8>,
}

impl<'a, R: Read> TeeReader<'a, R> {
    fn new(inner: &'a mut R, sink: &'a mut Vec<u8>) -> Self {
        Self { inner, sink }
    }
}

impl<'a, R: Read> Read for TeeReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.sink.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::db::composite_key::CompositeKey;

    #[test]
    fn test_invalid_version_rejected() {
        // Write KDBX 3.1 signature
        let mut data = Vec::new();
        data.extend_from_slice(&crate::kdbx::file::header::KDBX_SIGNATURE_1.to_le_bytes());
        data.extend_from_slice(&crate::kdbx::file::header::KDBX_SIGNATURE_2.to_le_bytes());
        data.extend_from_slice(&0x00030001u32.to_le_bytes()); // v3.1

        let mut cursor = std::io::Cursor::new(data);
        let key = CompositeKey::new().with_password(b"test");
        assert!(read_kdbx4(&mut cursor, &key).is_err());
    }
}
