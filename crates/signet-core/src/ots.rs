//! Minimal reader for detached OpenTimestamps proofs (`.ots` files).
//!
//! It parses the proof, replays every commitment operation from the file
//! digest, and returns each attestation together with the message that
//! reaches it. It does **not** decide whether an attestation is true: a
//! Bitcoin attestation is only verified once the caller compares its message
//! with the Merkle root of that block, taken from a source the caller trusts
//! (see `anchor::BitcoinHeaderSource`).
//!
//! Supported operations are the ones Bitcoin calendar proofs use: `sha256`,
//! `append`, `prepend`, `reverse` and `hexlify`. A proof that needs `sha1`,
//! `ripemd160` or `keccak256` is rejected with [`OtsError::UnsupportedOp`]
//! rather than half-checked.
//!
//! Format reference: <https://github.com/opentimestamps/python-opentimestamps>
//! (`opentimestamps/core/serialize.py`, `op.py`, `notary.py`, `timestamp.py`).

use sha2::{Digest, Sha256};

const HEADER_MAGIC: &[u8; 31] =
    b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
const MAJOR_VERSION: u64 = 1;

const TAG_ATTESTATION: u8 = 0x00;
const TAG_FORK: u8 = 0xff;

const OP_SHA1: u8 = 0x02;
const OP_RIPEMD160: u8 = 0x03;
const OP_SHA256: u8 = 0x08;
const OP_KECCAK256: u8 = 0x67;
const OP_APPEND: u8 = 0xf0;
const OP_PREPEND: u8 = 0xf1;
const OP_REVERSE: u8 = 0xf2;
const OP_HEXLIFY: u8 = 0xf3;

const BITCOIN_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const PENDING_TAG: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];

/// Same limits as the reference implementation.
const MAX_RESULT_LENGTH: usize = 4096;
const MAX_PAYLOAD_SIZE: usize = 8192;
const MAX_URI_LENGTH: usize = 1000;
/// Guards the recursion on hostile input; real proofs are a few dozen deep.
const MAX_DEPTH: usize = 256;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OtsError {
    #[error("not an OpenTimestamps proof (bad magic)")]
    BadMagic,
    #[error("unsupported proof version {0}")]
    UnsupportedVersion(u64),
    #[error("unexpected end of proof")]
    Truncated,
    #[error("trailing bytes after the proof")]
    TrailingBytes,
    #[error("unsupported operation 0x{0:02x}")]
    UnsupportedOp(u8),
    #[error("unknown operation tag 0x{0:02x}")]
    UnknownTag(u8),
    #[error("operation result longer than 4096 bytes")]
    ResultTooLong,
    #[error("value out of range: {0}")]
    OutOfRange(&'static str),
    #[error("proof nested deeper than 256 levels")]
    TooDeep,
}

/// What an attestation claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    /// The message is the Merkle root of the Bitcoin block at this height.
    Bitcoin { height: u64 },
    /// A calendar promises to timestamp the message; not yet upgraded.
    Pending { uri: String },
    /// An attestation type this reader does not know (e.g. other chains).
    Unknown { tag: [u8; 8] },
}

/// One attestation and the message the proof derives for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    pub attestation: Attestation,
    pub message: Vec<u8>,
}

/// A parsed detached proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtsProof {
    /// SHA-256 of the timestamped bytes, as stated by the proof.
    pub digest: [u8; 32],
    pub attestations: Vec<Attested>,
}

impl OtsProof {
    pub fn bitcoin(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.attestations
            .iter()
            .filter_map(|a| match a.attestation {
                Attestation::Bitcoin { height } => Some((height, a.message.as_slice())),
                _ => None,
            })
    }

    pub fn has_pending(&self) -> bool {
        self.attestations
            .iter()
            .any(|a| matches!(a.attestation, Attestation::Pending { .. }))
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, OtsError> {
        let b = *self.buf.get(self.pos).ok_or(OtsError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], OtsError> {
        let end = self.pos.checked_add(n).ok_or(OtsError::Truncated)?;
        let out = self.buf.get(self.pos..end).ok_or(OtsError::Truncated)?;
        self.pos = end;
        Ok(out)
    }

    fn varuint(&mut self) -> Result<u64, OtsError> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.byte()?;
            if shift > 63 {
                return Err(OtsError::OutOfRange("varuint"));
            }
            value |= u64::from(b & 0x7f)
                .checked_shl(shift)
                .ok_or(OtsError::OutOfRange("varuint"))?;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn varbytes(&mut self, max: usize, min: usize) -> Result<&'a [u8], OtsError> {
        let len = usize::try_from(self.varuint()?).map_err(|_| OtsError::OutOfRange("length"))?;
        if len > max || len < min {
            return Err(OtsError::OutOfRange("length"));
        }
        self.bytes(len)
    }
}

/// Parse a detached `.ots` proof and derive the message at every attestation.
pub fn parse_detached(bytes: &[u8]) -> Result<OtsProof, OtsError> {
    let mut r = Reader { buf: bytes, pos: 0 };
    if r.bytes(HEADER_MAGIC.len())? != HEADER_MAGIC {
        return Err(OtsError::BadMagic);
    }
    let version = r.varuint()?;
    if version != MAJOR_VERSION {
        return Err(OtsError::UnsupportedVersion(version));
    }
    match r.byte()? {
        OP_SHA256 => {}
        tag @ (OP_SHA1 | OP_RIPEMD160 | OP_KECCAK256) => return Err(OtsError::UnsupportedOp(tag)),
        tag => return Err(OtsError::UnknownTag(tag)),
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(r.bytes(32)?);

    let mut attestations = Vec::new();
    read_timestamp(&mut r, digest.to_vec(), 0, &mut attestations)?;
    if r.pos != bytes.len() {
        return Err(OtsError::TrailingBytes);
    }
    Ok(OtsProof {
        digest,
        attestations,
    })
}

fn read_timestamp(
    r: &mut Reader<'_>,
    msg: Vec<u8>,
    depth: usize,
    out: &mut Vec<Attested>,
) -> Result<(), OtsError> {
    if depth > MAX_DEPTH {
        return Err(OtsError::TooDeep);
    }
    let mut tag = r.byte()?;
    while tag == TAG_FORK {
        let current = r.byte()?;
        read_tag(r, current, &msg, depth, out)?;
        tag = r.byte()?;
    }
    read_tag(r, tag, &msg, depth, out)
}

fn read_tag(
    r: &mut Reader<'_>,
    tag: u8,
    msg: &[u8],
    depth: usize,
    out: &mut Vec<Attested>,
) -> Result<(), OtsError> {
    if tag == TAG_ATTESTATION {
        let attestation = read_attestation(r)?;
        out.push(Attested {
            attestation,
            message: msg.to_vec(),
        });
        return Ok(());
    }
    let next = apply_op(r, tag, msg)?;
    read_timestamp(r, next, depth + 1, out)
}

fn apply_op(r: &mut Reader<'_>, tag: u8, msg: &[u8]) -> Result<Vec<u8>, OtsError> {
    let result = match tag {
        OP_SHA256 => Sha256::digest(msg).to_vec(),
        OP_APPEND => {
            let arg = r.varbytes(MAX_RESULT_LENGTH, 1)?;
            [msg, arg].concat()
        }
        OP_PREPEND => {
            let arg = r.varbytes(MAX_RESULT_LENGTH, 1)?;
            [arg, msg].concat()
        }
        OP_REVERSE => msg.iter().rev().copied().collect(),
        OP_HEXLIFY => hex::encode(msg).into_bytes(),
        OP_SHA1 | OP_RIPEMD160 | OP_KECCAK256 => return Err(OtsError::UnsupportedOp(tag)),
        other => return Err(OtsError::UnknownTag(other)),
    };
    if result.len() > MAX_RESULT_LENGTH {
        return Err(OtsError::ResultTooLong);
    }
    Ok(result)
}

fn read_attestation(r: &mut Reader<'_>) -> Result<Attestation, OtsError> {
    let mut tag = [0u8; 8];
    tag.copy_from_slice(r.bytes(8)?);
    let payload = r.varbytes(MAX_PAYLOAD_SIZE, 0)?;
    let mut p = Reader {
        buf: payload,
        pos: 0,
    };
    let attestation = if tag == BITCOIN_TAG {
        Attestation::Bitcoin {
            height: p.varuint()?,
        }
    } else if tag == PENDING_TAG {
        let uri = p.varbytes(MAX_URI_LENGTH, 0)?;
        let uri = String::from_utf8(uri.to_vec()).map_err(|_| OtsError::OutOfRange("uri"))?;
        Attestation::Pending { uri }
    } else {
        return Ok(Attestation::Unknown { tag });
    };
    if p.pos != payload.len() {
        return Err(OtsError::TrailingBytes);
    }
    Ok(attestation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(digest: &[u8; 32]) -> Vec<u8> {
        let mut v = HEADER_MAGIC.to_vec();
        v.push(0x01);
        v.push(OP_SHA256);
        v.extend_from_slice(digest);
        v
    }

    fn pending(uri: &str) -> Vec<u8> {
        let mut payload = vec![uri.len() as u8];
        payload.extend_from_slice(uri.as_bytes());
        let mut v = vec![TAG_ATTESTATION];
        v.extend_from_slice(&PENDING_TAG);
        v.push(payload.len() as u8);
        v.extend_from_slice(&payload);
        v
    }

    fn bitcoin(height: u64) -> Vec<u8> {
        let mut payload = Vec::new();
        let mut h = height;
        loop {
            let b = (h & 0x7f) as u8;
            h >>= 7;
            if h == 0 {
                payload.push(b);
                break;
            }
            payload.push(b | 0x80);
        }
        let mut v = vec![TAG_ATTESTATION];
        v.extend_from_slice(&BITCOIN_TAG);
        v.push(payload.len() as u8);
        v.extend_from_slice(&payload);
        v
    }

    #[test]
    fn replays_ops_and_forks() {
        let d = [7u8; 32];
        let mut proof = header(&d);
        // fork: branch 1 = append 0xaa, sha256, pending
        proof.push(TAG_FORK);
        proof.extend_from_slice(&[OP_APPEND, 1, 0xaa, OP_SHA256]);
        proof.extend_from_slice(&pending("https://a.example"));
        // branch 2 (last) = prepend 0xbb, sha256, bitcoin 800000
        proof.extend_from_slice(&[OP_PREPEND, 1, 0xbb, OP_SHA256]);
        proof.extend_from_slice(&bitcoin(800_000));

        let parsed = parse_detached(&proof).unwrap();
        assert_eq!(parsed.digest, d);
        assert_eq!(parsed.attestations.len(), 2);

        let m1 = Sha256::digest([&d[..], &[0xaa]].concat()).to_vec();
        let m2 = Sha256::digest([&[0xbb][..], &d[..]].concat()).to_vec();
        assert_eq!(parsed.attestations[0].message, m1);
        assert_eq!(
            parsed.attestations[0].attestation,
            Attestation::Pending {
                uri: "https://a.example".into()
            }
        );
        assert_eq!(parsed.attestations[1].message, m2);
        assert_eq!(
            parsed.bitcoin().collect::<Vec<_>>(),
            vec![(800_000, &m2[..])]
        );
        assert!(parsed.has_pending());
    }

    #[test]
    fn rejects_trailing_bytes_and_truncation() {
        let mut proof = header(&[1u8; 32]);
        proof.extend_from_slice(&pending("https://a.example"));
        let mut longer = proof.clone();
        longer.push(0);
        assert_eq!(parse_detached(&longer), Err(OtsError::TrailingBytes));
        assert_eq!(
            parse_detached(&proof[..proof.len() - 1]),
            Err(OtsError::Truncated)
        );
    }

    #[test]
    fn rejects_bad_magic_and_unsupported_ops() {
        let mut proof = header(&[1u8; 32]);
        proof[1] = b'X';
        assert_eq!(parse_detached(&proof), Err(OtsError::BadMagic));

        let mut proof = header(&[1u8; 32]);
        proof.push(OP_RIPEMD160);
        assert_eq!(
            parse_detached(&proof),
            Err(OtsError::UnsupportedOp(OP_RIPEMD160))
        );
    }

    #[test]
    fn rejects_excessive_nesting() {
        let mut proof = header(&[1u8; 32]);
        proof.extend(std::iter::repeat_n(OP_REVERSE, MAX_DEPTH + 2));
        proof.extend_from_slice(&pending("https://a.example"));
        assert_eq!(parse_detached(&proof), Err(OtsError::TooDeep));
    }
}
