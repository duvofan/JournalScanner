use crate::pat_data::*;
use crate::patterns::{extract_strings, get_db};
use crate::pe::PeInfo;
use crate::util::*;
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

pub fn hid_strong_cat(c: u8) -> bool {
    c == C_FAMILY || c == C_CLIENT_A || c == C_MOD_STRONG || c == C_SDSTR || c == C_GUICHEAT
}

struct StackRun {
    run: [BTreeMap<i64, u8>; 2], // 0: rsp/esp tabanlı, 1: rbp/ebp tabanlı yazmalar (yer değiştirme -> bayt)
    run_start: usize,
    last_end: usize,
    active: bool,
}

fn flush_runs(st: &mut StackRun, off: usize, emit: &mut dyn FnMut(&[u8], usize)) {
    for b in 0..2 {
        let m = std::mem::take(&mut st.run[b]);
        if m.len() >= 5 {
            let mut buf: Vec<u8> = Vec::new();
            let mut prev: i64 = 0;
            let mut first = true;
            let run_start = st.run_start;
            let mut out = |buf: &mut Vec<u8>| {
                if buf.len() >= 5 {
                    extract_strings(buf, 0, buf.len(), 5, |p, _, _| emit(p, off + run_start));
                }
                buf.clear();
            };
            for (&k, &v) in &m {
                if !first && k - prev > 1 {
                    if k - prev <= 8 {
                        buf.extend(std::iter::repeat(0u8).take((k - prev - 1) as usize));
                    } else {
                        out(&mut buf);
                    }
                }
                buf.push(v);
                prev = k;
                first = false;
                if buf.len() >= 2048 {
                    out(&mut buf);
                }
            }
            out(&mut buf);
        }
    }
    st.active = false;
}

fn stack_mem(c: &[u8], i: usize, len: usize, mo: usize) -> Option<(usize, i64, usize)> {
    if i + mo + 7 > len {
        return None;
    }
    let g = |k: usize| c.get(i + k).copied().unwrap_or(0);
    let m = g(mo) & 0xC7;
    if m == 0x44 && g(mo + 1) == 0x24 {
        return Some((0, g(mo + 2) as i8 as i64, 3));
    }
    if m == 0x45 {
        return Some((1, g(mo + 1) as i8 as i64, 2));
    }
    if m == 0x84 && g(mo + 1) == 0x24 && i + mo + 10 <= len {
        return Some((0, rd32(c, i + mo + 2) as i32 as i64, 6));
    }
    if m == 0x85 && i + mo + 9 <= len {
        return Some((1, rd32(c, i + mo + 1) as i32 as i64, 5));
    }
    None
}

pub fn stack_strings(d: &[u8], pe: &PeInfo, emit: &mut dyn FnMut(&[u8], usize)) {
    let n = d.len();
    for s in &pe.secs {
        if s.chars & 0x2000_0000 == 0 && s.chars & 0x20 == 0 {
            continue;
        }
        let (off, mut len) = if pe.mem_layout {
            (s.rva as usize, s.vsize.max(s.raw_size) as usize)
        } else {
            (s.raw_ptr as usize, s.raw_size as usize)
        };
        if off >= n {
            continue;
        }
        if off + len > n {
            len = n - off;
        }
        if len < 16 {
            continue;
        }
        let c = &d[off..off + len];
        let mut st = StackRun {
            run: [BTreeMap::new(), BTreeMap::new()],
            run_start: 0,
            last_end: 0,
            active: false,
        };
        let mut rv = [0u64; 16];
        let mut rpos = [0usize; 16];
        let mut rok = [false; 16];
        let mut i = 0usize;
        while i + 4 <= len {
            let g = |k: usize| c.get(i + k).copied().unwrap_or(0);
            let mut b = 0usize;
            let mut dp = 0i64;
            let mut l = 0usize;
            let mut val = 0u64;
            let mut vsz = 0usize;
            let mut reg_load = false;
            let mut hit = false;
            if g(0) == 0xC6 && (g(1) & 0x38) == 0 {
                if let Some((bb, dd, ml)) = stack_mem(c, i, len, 1) {
                    b = bb;
                    dp = dd;
                    val = g(1 + ml) as u64;
                    vsz = 1;
                    l = 2 + ml;
                    hit = true;
                }
            }
            if !hit && g(0) == 0xC7 && (g(1) & 0x38) == 0 {
                if let Some((bb, dd, ml)) = stack_mem(c, i, len, 1) {
                    if i + 1 + ml + 4 <= len {
                        b = bb;
                        dp = dd;
                        val = rd32(c, i + 1 + ml) as u64;
                        vsz = 4;
                        l = 1 + ml + 4;
                        hit = true;
                    }
                }
            }
            if !hit && g(0) == 0x66 && g(1) == 0xC7 && (g(2) & 0x38) == 0 {
                if let Some((bb, dd, ml)) = stack_mem(c, i, len, 2) {
                    if i + 2 + ml + 2 <= len {
                        b = bb;
                        dp = dd;
                        val = rd16(c, i + 2 + ml) as u64;
                        vsz = 2;
                        l = 2 + ml + 2;
                        hit = true;
                    }
                }
            }
            if !hit && pe.is64 && (g(0) == 0x48 || g(0) == 0x49) && (0xB8..=0xBF).contains(&g(1)) && i + 10 <= len {
                let r = (g(1) - 0xB8) as usize + if g(0) == 0x49 { 8 } else { 0 };
                rv[r] = rd64(c, i + 2);
                rpos[r] = i;
                rok[r] = true;
                l = 10;
                reg_load = true;
                hit = true;
            }
            if !hit && pe.is64 && (g(0) == 0x48 || g(0) == 0x4C) && g(1) == 0x89 {
                if let Some((bb, dd, ml)) = stack_mem(c, i, len, 2) {
                    b = bb;
                    dp = dd;
                    let r = ((g(2) >> 3) & 7) as usize + if g(0) == 0x4C { 8 } else { 0 };
                    if rok[r] && i - rpos[r] <= 40 {
                        val = rv[r];
                        vsz = 8;
                    }
                    l = 2 + ml;
                }
            }
            if l == 0 {
                i += 1;
                continue;
            }
            if vsz != 0 || reg_load {
                if !st.active || i > st.last_end + 24 {
                    flush_runs(&mut st, off, emit);
                    st.active = true;
                    st.run_start = i;
                }
                if vsz != 0 {
                    let m = &mut st.run[b];
                    for k in 0..vsz {
                        m.insert(dp + k as i64, (val >> (8 * k)) as u8);
                    }
                    if m.len() > 4096 {
                        flush_runs(&mut st, off, emit);
                    }
                }
                st.last_end = i + l;
            }
            i += l;
        }
        flush_runs(&mut st, off, emit);
    }
}

pub struct XorPatIdx {
    pub bits16: Vec<u8>,
    pub by24: HashMap<u32, Vec<i32>>,
}

pub fn get_xor_idx() -> &'static XorPatIdx {
    static X: OnceLock<XorPatIdx> = OnceLock::new();
    X.get_or_init(|| {
        let mut x = XorPatIdx {
            bits16: vec![0u8; 65536 / 8],
            by24: HashMap::new(),
        };
        let db = get_db();
        for (id, pi) in db.pats.iter().enumerate() {
            let t = &pi.text;
            if !hid_strong_cat(pi.cat) || t.len() < 7 || t.len() > 64 {
                continue;
            }
            if !t.iter().all(|&ch| ch.is_ascii_lowercase() || ch.is_ascii_digit()) {
                continue;
            }
            let m0 = ((t[0] ^ t[1]) & 0xDF) as u32;
            let m1 = ((t[1] ^ t[2]) & 0xDF) as u32;
            let m2 = ((t[2] ^ t[3]) & 0xDF) as u32;
            let k16 = m0 | (m1 << 8);
            x.bits16[(k16 >> 3) as usize] |= 1u8 << (k16 & 7);
            x.by24.entry(k16 | (m2 << 16)).or_default().push(id as i32);
        }
        x
    })
}

#[derive(Debug, Clone, Copy)]
pub struct XorCand {
    pub key: u8,
    pub off: usize,
    pub len: usize,
}

pub fn xor_string_cands(d: &[u8], out: &mut Vec<XorCand>) {
    let n = d.len();
    let x = get_xor_idx();
    if x.by24.is_empty() || n < 8 {
        return;
    }
    let db = get_db();
    let mut i = 0usize;
    while i + 8 <= n && out.len() < 4096 {
        let m0 = ((d[i] ^ d[i + 1]) & 0xDF) as u32;
        let m1 = ((d[i + 1] ^ d[i + 2]) & 0xDF) as u32;
        let k16 = m0 | (m1 << 8);
        if x.bits16[(k16 >> 3) as usize] & (1u8 << (k16 & 7)) == 0 {
            i += 1;
            continue;
        }
        let m2 = ((d[i + 2] ^ d[i + 3]) & 0xDF) as u32;
        let Some(list) = x.by24.get(&(k16 | (m2 << 16))) else {
            i += 1;
            continue;
        };
        for &id in list {
            let t = &db.pats[id as usize].text;
            let l = t.len();
            if i + l > n {
                continue;
            }
            let mut ok = true;
            let mut j = 3;
            while j + 1 < l {
                if ((d[i + j] ^ d[i + j + 1]) & 0xDF) != ((t[j] ^ t[j + 1]) & 0xDF) {
                    ok = false;
                    break;
                }
                j += 1;
            }
            if !ok {
                continue;
            }
            let k1 = d[i] ^ t[0];
            let mut found = false;
            let mut key = 0u8;
            for a in 0..2 {
                if found {
                    break;
                }
                if a != 0 && !is_al(t[0]) {
                    break;
                }
                let k = if a != 0 { k1 ^ 0x20 } else { k1 };
                let mut good = true;
                for j in 0..l {
                    if low_c(d[i + j] ^ k) != t[j] {
                        good = false;
                        break;
                    }
                }
                if good {
                    key = k;
                    found = true;
                }
            }
            if !found || key == 0x00 || key == 0x20 {
                continue;
            }
            out.push(XorCand { key, off: i, len: l });
            break;
        }
        i += 1;
    }
}

pub fn is_b64c(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'-' | b'_')
}

fn b64_table() -> &'static [i32; 256] {
    static T: OnceLock<[i32; 256]> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = [-1i32; 256];
        let a = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (k, &c) in a.iter().enumerate() {
            t[c as usize] = k as i32;
        }
        t[b'-' as usize] = 62;
        t[b'_' as usize] = 63;
        t
    })
}

pub fn b64_decode(input: &[u8], out: &mut Vec<u8>, max_out: usize) -> bool {
    let t = b64_table();
    out.clear();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &ch in input {
        if ch == b'=' {
            break;
        }
        let v = t[ch as usize];
        if v < 0 {
            continue;
        }
        acc = ((acc << 6) | v as u32) & 0xFF_FFFF;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            if out.len() >= max_out {
                return false;
            }
        }
    }
    true
}

pub fn payload_magic(p: &[u8]) -> bool {
    let n = p.len();
    if n >= 10
        && p[0] == 0xCA
        && p[1] == 0xFE
        && p[2] == 0xBA
        && p[3] == 0xBE
        && p[4] == 0
        && p[5] == 0
        && p[6] == 0
        && (45..=70).contains(&p[7])
    {
        return true;
    }
    if n >= 30 && rd32(p, 0) == 0x04034B50 {
        let m = rd16(p, 8);
        let nl = rd16(p, 26);
        return (m == 0 || m == 8) && (1..=512).contains(&nl);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64() {
        let mut o = Vec::new();
        assert!(b64_decode(b"yv66vgAA", &mut o, 100));
        assert_eq!(&o[..4], &[0xCA, 0xFE, 0xBA, 0xBE]);
        assert!(!b64_decode(b"AAAAAAAAAAAA", &mut o, 3));
        assert!(b64_decode(b"aGk=", &mut o, 10));
        assert_eq!(o, b"hi");
    }

    #[test]
    fn xor_finds_killaura() {
        let mut buf = vec![0x11u8; 8];
        let key = 0x5Au8;
        buf.extend(b"killaura module".iter().map(|c| c ^ key));
        buf.extend_from_slice(&[0x11; 8]);
        let mut out = Vec::new();
        xor_string_cands(&buf, &mut out);
        assert!(out.iter().any(|c| c.key == key && c.off == 8));
    }

    #[test]
    fn stack_string_mov_bytes() {
        let mut code = Vec::new();
        for (k, ch) in b"hello".iter().enumerate() {
            code.extend_from_slice(&[0xC6, 0x44, 0x24, 0x20 + k as u8, *ch]);
        }
        code.resize(code.len() + 16, 0x90);
        let pe = PeInfo {
            is64: true,
            mem_layout: false,
            secs: vec![crate::pe::PeSec {
                raw_ptr: 0,
                raw_size: code.len() as u32,
                chars: 0x2000_0020,
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut got: Vec<String> = Vec::new();
        stack_strings(&code, &pe, &mut |s, _| got.push(String::from_utf8_lossy(s).to_string()));
        assert!(got.iter().any(|s| s == "hello"));
    }

    #[test]
    fn magic() {
        assert!(payload_magic(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 0]));
        assert!(!payload_magic(&[0u8; 40]));
    }
}
