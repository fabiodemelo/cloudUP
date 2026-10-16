//! Client-side keys for accounts and sync (docs/sync-api.md, "Client-side
//! keys"): Argon2id from the password, HKDF-SHA256 subkeys, XChaCha20-Poly1305
//! sealing, and the Crockford base32 form of the recovery key.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A 32-byte key, wiped from memory when dropped.
pub type Key32 = Zeroizing<[u8; 32]>;

/// Additional data bound to every sealed value.
const AAD: &[u8] = b"cloudup-v1";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

pub const INFO_AUTH: &str = "cloudup-auth-v1";
pub const INFO_ENC: &str = "cloudup-enc-v1";
pub const INFO_RECOVERY_AUTH: &str = "cloudup-recovery-auth-v1";

/// Argon2id parameters, as registered and echoed back by `prelogin`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kdf {
    pub alg: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for Kdf {
    fn default() -> Self {
        Kdf { alg: "argon2id".into(), m: 65536, t: 3, p: 1 }
    }
}

impl Kdf {
    /// Parameters this client accepts from the server: never weaker than the
    /// defaults (a server could otherwise ask for a hash that's cheap to brute
    /// force) and not so large that deriving a key would exhaust the Mac.
    pub fn acceptable(&self) -> bool {
        let d = Kdf::default();
        self.alg == "argon2id"
            && (d.m..=2 * 1024 * 1024).contains(&self.m)
            && (d.t..=20).contains(&self.t)
            && (1..=16).contains(&self.p)
    }
}

/// `master = Argon2id(password, salt, kdf)`, 32 bytes. CPU and memory heavy
/// (64 MiB): call it off the async runtime.
pub fn derive_master(password: &str, salt: &[u8], kdf: &Kdf) -> Result<Key32, String> {
    let params = argon2::Params::new(kdf.m, kdf.t, kdf.p, Some(32)).map_err(|e| e.to_string())?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(password.as_bytes(), salt, &mut *out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// HKDF-SHA256 with no salt, 32 bytes of output.
pub fn hkdf32(ikm: &[u8], info: &str) -> Key32 {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), &mut *out).expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// The two keys made from the account password.
pub struct PasswordKeys {
    /// Sent to the server, which stores only a hash of it.
    pub auth_key: Key32,
    /// Wraps the vault key; never leaves the Mac.
    pub enc_key: Key32,
}

pub fn password_keys(password: &str, salt: &[u8], kdf: &Kdf) -> Result<PasswordKeys, String> {
    let master = derive_master(password, salt, kdf)?;
    Ok(PasswordKeys { auth_key: hkdf32(&*master, INFO_AUTH), enc_key: hkdf32(&*master, INFO_ENC) })
}

/// 32 random bytes from the OS generator (vault and recovery keys).
pub fn random_key() -> Key32 {
    let mut k = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *k);
    k
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut v);
    v
}

/// `seal(k, m) = nonce(24 random) || XChaCha20-Poly1305(k, nonce, m, aad="cloudup-v1")`.
pub fn seal(key: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    seal_with_nonce(key, &nonce, msg)
}

pub fn seal_with_nonce(key: &[u8; 32], nonce: &[u8; NONCE_LEN], msg: &[u8]) -> Vec<u8> {
    let ct = seal_raw(key, nonce, msg, AAD);
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out
}

fn seal_raw(key: &[u8; 32], nonce: &[u8; NONCE_LEN], msg: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .expect("XChaCha20-Poly1305 encryption of an in-memory buffer can't fail")
}

/// Undo [`seal`]. Fails on a wrong key or any change to the data.
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, ()> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(());
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: AAD }).map_err(|_| ())
}

/// [`open`] for a sealed 32-byte key.
pub fn open_key(key: &[u8; 32], sealed: &[u8]) -> Result<Key32, ()> {
    let plain = Zeroizing::new(open(key, sealed)?);
    let arr: [u8; 32] = plain.as_slice().try_into().map_err(|_| ())?;
    Ok(Zeroizing::new(arr))
}

// ------------------------------------------------------------------ Crockford base32

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Crockford base32 (no check symbol), in groups of 4 joined by dashes:
/// 32 bytes become 52 symbols, `XXXX-XXXX-...`.
pub fn crockford_encode(bytes: &[u8]) -> String {
    let mut symbols = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            symbols.push(CROCKFORD[((buf >> bits) & 31) as usize] as char);
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        symbols.push(CROCKFORD[((buf << (5 - bits)) & 31) as usize] as char);
    }
    let chars: Vec<char> = symbols.chars().collect();
    chars.chunks(4).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join("-")
}

/// Decode Crockford base32: case-insensitive, dashes and spaces ignored,
/// O read as 0 and I/L as 1. Leftover padding bits must be zero.
pub fn crockford_decode(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for ch in text.chars() {
        if ch == '-' || ch.is_whitespace() {
            continue;
        }
        let v = match ch.to_ascii_uppercase() {
            'O' => 0,
            'I' | 'L' => 1,
            c => CROCKFORD.iter().position(|&x| x as char == c).ok_or_else(|| format!("'{ch}' isn't used in recovery keys"))?
                as u32,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    if buf != 0 {
        return Err("the last symbol doesn't fit".into());
    }
    Ok(out)
}

/// A typed recovery key: 32 bytes in Crockford base32.
pub fn parse_recovery_key(text: &str) -> Result<Key32, String> {
    let bytes = Zeroizing::new(crockford_decode(text)?);
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "it has the wrong length".to_string())?;
    Ok(Zeroizing::new(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn hkdf_matches_rfc5869_case_3() {
        // RFC 5869 A.3: IKM = 0x0b * 22, no salt, no info; the first 32 of 42 bytes.
        let okm = hkdf32(&[0x0b; 22], "");
        assert_eq!(hex::encode(&*okm), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d");
    }

    #[test]
    fn hkdf_subkeys_are_pinned() {
        let master = [7u8; 32];
        assert_eq!(hex::encode(&*hkdf32(&master, INFO_AUTH)), PINNED_AUTH);
        assert_eq!(hex::encode(&*hkdf32(&master, INFO_ENC)), PINNED_ENC);
        assert_eq!(hex::encode(&*hkdf32(&master, INFO_RECOVERY_AUTH)), PINNED_RECOVERY_AUTH);
        assert_ne!(*hkdf32(&master, INFO_AUTH), *hkdf32(&master, INFO_ENC));
    }

    #[test]
    fn xchacha_matches_draft_irtf_cfrg_xchacha_a3() {
        // draft-irtf-cfrg-xchacha-03, A.3.1 (AEAD_XChaCha20_Poly1305).
        let key: [u8; 32] = h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").try_into().unwrap();
        let nonce: [u8; 24] = h("404142434445464748494a4b4c4d4e4f5051525354555657").try_into().unwrap();
        let aad = h("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let out = seal_raw(&key, &nonce, pt, &aad);
        let expected_ct = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e";
        let expected_tag = "c0875924c1c7987947deafd8780acf49";
        assert_eq!(hex::encode(&out), format!("{expected_ct}{expected_tag}"));
    }

    #[test]
    fn argon2id_master_is_pinned() {
        let master = derive_master("correct horse battery staple", b"0123456789abcdef", &Kdf::default()).unwrap();
        assert_eq!(hex::encode(&*master), PINNED_MASTER);
        let keys = password_keys("correct horse battery staple", b"0123456789abcdef", &Kdf::default()).unwrap();
        assert_eq!(*keys.auth_key, *hkdf32(&*master, INFO_AUTH));
        assert_eq!(*keys.enc_key, *hkdf32(&*master, INFO_ENC));
        // Any change to the password or salt gives another key.
        let other = derive_master("correct horse battery stapler", b"0123456789abcdef", &Kdf::default()).unwrap();
        assert_ne!(*master, *other);
    }

    #[test]
    fn seal_is_pinned_and_round_trips() {
        let key = [1u8; 32];
        let nonce = [2u8; 24];
        let sealed = seal_with_nonce(&key, &nonce, b"vault");
        assert_eq!(hex::encode(&sealed), PINNED_SEAL);
        assert_eq!(open(&key, &sealed).unwrap(), b"vault");

        let random = seal(&key, b"vault");
        assert_ne!(random, sealed, "a fresh random nonce each time");
        assert_eq!(open(&key, &random).unwrap(), b"vault");
    }

    #[test]
    fn open_refuses_wrong_key_tampering_and_short_input() {
        let key = [1u8; 32];
        let mut sealed = seal(&key, b"secret");
        assert!(open(&[9u8; 32], &sealed).is_err());
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open(&key, &sealed).is_err());
        assert!(open(&key, &[0u8; 39]).is_err());
        // Sealed with another AAD: refused.
        let other = [&[2u8; 24][..], &seal_raw(&key, &[2u8; 24], b"x", b"other")].concat();
        assert!(open(&key, &other).is_err());
    }

    #[test]
    fn wrapped_key_round_trip() {
        let enc = random_key();
        let vault_key = random_key();
        let wrapped = seal(&enc, &*vault_key);
        assert_eq!(wrapped.len(), 24 + 32 + 16);
        assert_eq!(*open_key(&enc, &wrapped).unwrap(), *vault_key);
        assert!(open_key(&enc, &seal(&enc, b"short")).is_err());
    }

    #[test]
    fn crockford_known_values() {
        assert_eq!(crockford_encode(b""), "");
        assert_eq!(crockford_encode(b"f"), "CR");
        // RFC 4648 base32 of "foobar" is MZXW6YTBOI; the same 5-bit values in Crockford's alphabet:
        assert_eq!(crockford_encode(b"foobar"), "CSQP-YRK1-E8");
        assert_eq!(crockford_decode("CSQP-YRK1-E8").unwrap(), b"foobar");
        assert_eq!(crockford_decode("csqp yrk1 e8").unwrap(), b"foobar");
        assert_eq!(crockford_decode(" c-s-q-p-y-r-k-l-e-8 ").unwrap(), b"foobar", "l reads as 1");
        assert_eq!(crockford_decode("0O").unwrap(), crockford_decode("00").unwrap());
        assert!(crockford_decode("CSQU").is_err(), "U isn't in the alphabet");
        assert!(crockford_decode("CS").is_err(), "nonzero padding bits");
    }

    #[test]
    fn recovery_key_round_trip() {
        let key = [0xA5u8; 32];
        let text = crockford_encode(&key);
        assert_eq!(text.len(), 52 + 12, "13 groups of 4");
        assert!(text.split('-').all(|g| g.len() == 4));
        assert_eq!(*parse_recovery_key(&text).unwrap(), key);
        assert_eq!(*parse_recovery_key(&text.to_lowercase().replace('-', " ")).unwrap(), key);
        assert!(parse_recovery_key(&text[..text.len() - 5]).is_err());
        for _ in 0..50 {
            let k = random_key();
            assert_eq!(*parse_recovery_key(&crockford_encode(&*k)).unwrap(), *k);
        }
    }

    #[test]
    fn kdf_limits() {
        assert!(Kdf::default().acceptable());
        assert!(Kdf { m: 131072, t: 4, ..Kdf::default() }.acceptable());
        assert!(!Kdf { m: 1024, ..Kdf::default() }.acceptable(), "weaker than the default");
        assert!(!Kdf { t: 1, ..Kdf::default() }.acceptable());
        assert!(!Kdf { m: u32::MAX, ..Kdf::default() }.acceptable());
        assert!(!Kdf { alg: "scrypt".into(), ..Kdf::default() }.acceptable());
    }

    // HKDF pins cross-checked with Python's hmac/hashlib (RFC 5869 by hand).
    const PINNED_AUTH: &str = "d0654b63fe0d439b5e21ff1cffaabfd3b367fbf32ea1d14709265541b8fdee2e";
    const PINNED_ENC: &str = "a08e0c1d5abe5b693a1a24491dce5548a898ca13e09ecaa3c352546bdf310d18";
    const PINNED_RECOVERY_AUTH: &str = "f4e8d353c95fa15d42def8b2f153a75f880b0f9dee58fc5139df582bca790d92";
    // Argon2id(m=65536, t=3, p=1) of "correct horse battery staple", salt "0123456789abcdef".
    const PINNED_MASTER: &str = "94c86f541abdb3d9aabfea59aa03963549483e9c0b1a79336e76b54cee6c917e";
    // seal(key = 01*32, nonce = 02*24, "vault"): nonce || ciphertext || tag.
    const PINNED_SEAL: &str =
        "020202020202020202020202020202020202020202020202ba074383de09ac170399315ec5677662b8ccf5eb20";
}
