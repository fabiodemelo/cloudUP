//! MEGA's hashcash proof of work (CloudUp addition to the vendored crate).
//!
//! Some API requests (sign-in, notably) are answered with
//! `402 Payment Required` and an `X-Hashcash: 1:<easiness>:<timestamp>:<token>`
//! header. The client fills a buffer with a 4-byte prefix followed by the
//! 48-byte token repeated 262144 times (12 MiB), and bumps the prefix until
//! the SHA-256 of the buffer, read as a big-endian `u32`, is at most the
//! threshold derived from `easiness`. The request is then sent again with
//! `X-Hashcash: 1:<token>:<base64url prefix>`.

use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

const TOKEN_LEN: usize = 48;
const REPEATS: usize = 262_144;

/// The `X-Hashcash` header answering `challenge`, or `None` for a challenge
/// this code doesn't understand. CPU-bound (about a second): run it on a
/// blocking thread.
pub(crate) fn answer(challenge: &str) -> Option<String> {
    let mut parts = challenge.trim().split(':');
    let (version, easiness, _timestamp, token) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if version != "1" || parts.next().is_some() {
        return None;
    }
    let easiness: u32 = easiness.parse().ok().filter(|e| *e <= 255)?;
    let prefix = solve(token, threshold(easiness))?;
    Some(format!("1:{token}:{}", BASE64_URL_SAFE_NO_PAD.encode(prefix)))
}

fn threshold(easiness: u32) -> u32 {
    (((easiness & 63) << 1) + 1) << ((easiness >> 6) * 7 + 3)
}

fn solve(token: &str, threshold: u32) -> Option<[u8; 4]> {
    let token = BASE64_URL_SAFE_NO_PAD.decode(token).ok()?;
    if token.len() != TOKEN_LEN {
        return None;
    }
    let mut buffer = vec![0u8; 4 + TOKEN_LEN * REPEATS];
    for chunk in buffer[4..].chunks_exact_mut(TOKEN_LEN) {
        chunk.copy_from_slice(&token);
    }
    // Every prefix is tried at most once; with the thresholds MEGA uses a
    // solution comes after a few hundred hashes.
    for _ in 0..=u32::MAX {
        let hash = Sha256::digest(&buffer);
        if u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) <= threshold {
            return Some([buffer[0], buffer[1], buffer[2], buffer[3]]);
        }
        for byte in &mut buffer[..4] {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds() {
        // 192 = 3 << 6: 1 << 24, i.e. one hash in 256 on average.
        assert_eq!(threshold(192), 1 << 24);
        assert_eq!(threshold(0), 1 << 3);
        assert_eq!(threshold(255), 127 << 24);
    }

    #[test]
    fn rejects_unknown_challenges() {
        assert_eq!(answer("2:192:0:AAAA"), None);
        assert_eq!(answer("1:192:0"), None);
        assert_eq!(answer("1:999:0:AAAA"), None);
        // A token of the wrong length.
        assert_eq!(answer("1:255:0:AAAA"), None);
    }

    #[test]
    fn answer_satisfies_the_threshold() {
        // Easiest setting: most prefixes pass, so this stays quick.
        let token = BASE64_URL_SAFE_NO_PAD.encode([7u8; TOKEN_LEN]);
        let header = answer(&format!("1:255:1700000000:{token}")).unwrap();
        let prefix = header.rsplit(':').next().unwrap();
        let prefix = BASE64_URL_SAFE_NO_PAD.decode(prefix).unwrap();
        assert!(header.starts_with(&format!("1:{token}:")));
        let mut buffer = prefix.clone();
        for _ in 0..REPEATS {
            buffer.extend_from_slice(&[7u8; TOKEN_LEN]);
        }
        let hash = Sha256::digest(&buffer);
        assert!(u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) <= threshold(255));
    }
}
