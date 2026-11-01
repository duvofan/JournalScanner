use crate::data::KNOWN_CLIENTS;
use crate::util::*;
use memchr::memmem;
use std::sync::OnceLock;

static K_AVENOR_MARKER: &str = "AVENOR-SCANNER-SIGDB-9c4f1e7a";
static K_CORE_MARKER: &str = "JOURNALSCANNER-CORE-SIGDB-4b7f2ae1";

const LEGACY_OWN_SHA256: [&str; 6] = [
    "f4efc9da37c1286477ae1dda2f9bb63975e73e74bed29f1cf277e07dde5d3f7b", // avdll.exe (v20.1 / v20.2)
    "2d7419fb414fae1af171d2da393d15034d4f666ea7497c171ce76dc1a16ffa9d", // JournalScanner.exe (v20.2, tek exe)
    "e95ebd0e105809977d83492d3fc32559741457fec9821dfcf3b8e5b231186ca5", // JournalScanner.exe (v20.0)
    "d4bb960358f205b85333b1d1b7f176e4929d1a4dcc71c13333422a6b982b51fa", // jscli.exe (v20.0)
    "f0ec7bd38dfe4b4260cfd02fcb6b05f4186c1fd9355b52e84dcbb7b01cb56bb6", // JournalScanner.exe (v20.1)
    "ed12b2170663b2a139c9d0a9a06fe73e4425084b43c69b3d96bb7ae5867c24b6", // jscli.exe (v20.1)
];

struct SelfImage {
    size: usize,
    sha: String,
}

fn self_image() -> &'static SelfImage {
    static IMG: OnceLock<SelfImage> = OnceLock::new();
    IMG.get_or_init(|| {
        let mut img = SelfImage {
            size: 0,
            sha: String::new(),
        };
        let p = self_exe_path();
        if p.is_empty() {
            return img;
        }
        if let Some(d) = read_file(&p, -1, 0) {
            if !d.is_empty() {
                img.size = d.len();
                img.sha = sha256_hex(&d);
            }
        }
        img
    })
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    if hay.len() < needle.len() {
        return false;
    }
    memmem::find(hay, needle).is_some()
}

pub fn is_own_component(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    if contains_bytes(data, K_AVENOR_MARKER.as_bytes()) {
        return true;
    }
    if contains_bytes(data, K_CORE_MARKER.as_bytes()) {
        return true;
    }
    let mut h = String::new();
    let me = self_image();
    if me.size != 0 && data.len() == me.size {
        h = sha256_hex(data);
        if h == me.sha {
            return true;
        }
    }
    if h.is_empty() {
        h = sha256_hex(data);
    }
    if LEGACY_OWN_SHA256.iter().any(|p| h == *p) {
        return true;
    }
    const K_OLD_TITLE: &[u8] = b"JOURNALSCANNER v20.";
    if contains_bytes(data, K_OLD_TITLE) {
        let mut n = 0;
        for kc in KNOWN_CLIENTS.iter() {
            if contains_bytes(data, kc.0.as_bytes()) {
                n += 1;
                if n >= 200 {
                    return true;
                }
            }
        }
    }
    false
}

pub fn own_tool_markers() -> &'static str {
    if !K_AVENOR_MARKER.is_empty() {
        K_CORE_MARKER
    } else {
        K_AVENOR_MARKER
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_detected() {
        let mut d = b"xxxx".to_vec();
        d.extend_from_slice(K_CORE_MARKER.as_bytes());
        assert!(is_own_component(&d));
        assert!(!is_own_component(b""));
    }
}
