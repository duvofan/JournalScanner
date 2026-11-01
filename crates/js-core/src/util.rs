use std::ffi::{c_char, c_int, CString};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, DeleteFileW, FindClose, FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW,
    FindNextFileW, GetFileAttributesExW, GetFileExInfoStandard, GetFileSizeEx, GetFullPathNameW, GetTempPathW,
    ReadFile, RemoveDirectoryW, SetFileAttributesW, SetFilePointerEx, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_DEVICE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BEGIN,
    FILE_FLAG_SEQUENTIAL_SCAN, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FIND_FIRST_EX_LARGE_FETCH, OPEN_EXISTING, WIN32_FILE_ATTRIBUTE_DATA, WIN32_FIND_DATAW,
};
use windows::Win32::System::Environment::GetEnvironmentVariableW;
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::SystemInformation::{GetSystemInfo, GetSystemTimeAsFileTime, SYSTEM_INFO};
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::UI::WindowsAndMessaging::CharLowerBuffW;

pub type Bytes = Vec<u8>;
pub type StrList = Vec<String>;
pub type StrProgress<'a> = &'a (dyn Fn(&str) + Sync);
pub type ProgressFn<'a> = &'a (dyn Fn(i32, i32, &str) + Sync);

pub const WS_CHARS: &str = " \t\r\n\x0b\x0c";

pub fn unmask(p: &[u8]) -> String {
    let o: Vec<u8> = p
        .iter()
        .enumerate()
        .map(|(i, &c)| c ^ (((0x5Au32).wrapping_add(13u32.wrapping_mul(i as u32))) & 0xFF) as u8)
        .collect();
    match String::from_utf8(o) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}
pub fn kw_jni_vms() -> &'static str {
    static S: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        unmask(&[
            0x10, 0x29, 0x3d, 0xde, 0xc9, 0xfe, 0xdc, 0xf6, 0xb0, 0xaa, 0xbd, 0x9d, 0x93, 0x67, 0x5a, 0x7c, 0x5c, 0x56,
            0x12, 0x1c, 0x2d,
        ])
    })
}
pub fn kw_jvm_dll() -> &'static str {
    static S: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    S.get_or_init(|| unmask(&[0x30, 0x11, 0x19, 0xaf, 0xea, 0xf7, 0xc4]))
}

pub fn starts(s: &str, p: &str) -> bool {
    s.starts_with(p)
}
pub fn ends(s: &str, p: &str) -> bool {
    s.ends_with(p)
}
pub fn has(s: &str, p: &str) -> bool {
    s.contains(p)
}
pub fn starts_any<S: AsRef<str>>(s: &str, ps: &[S]) -> bool {
    ps.iter().any(|p| s.starts_with(p.as_ref()))
}
pub fn ends_any<S: AsRef<str>>(s: &str, ps: &[S]) -> bool {
    ps.iter().any(|p| s.ends_with(p.as_ref()))
}
pub fn has_any<S: AsRef<str>>(s: &str, ps: &[S]) -> bool {
    ps.iter().any(|p| s.contains(p.as_ref()))
}

pub fn lower_ascii(s: &str) -> String {
    s.to_ascii_lowercase()
}
pub fn upper_ascii(s: &str) -> String {
    s.to_ascii_uppercase()
}

fn lower_cp(c: u32) -> u32 {
    if c < 0x80 {
        return if (0x41..=0x5A).contains(&c) { c + 32 } else { c };
    }
    if (0xC0..=0xDE).contains(&c) && c != 0xD7 {
        return c + 32;
    }
    if (0x100..=0x137).contains(&c) && c != 0x130 {
        return if c & 1 == 0 { c + 1 } else { c };
    }
    if (0x139..=0x148).contains(&c) {
        return if c & 1 == 1 { c + 1 } else { c };
    }
    if (0x14A..=0x177).contains(&c) {
        return if c & 1 == 0 { c + 1 } else { c };
    }
    if c == 0x178 {
        return 0xFF;
    }
    if (0x179..=0x17E).contains(&c) {
        return if c & 1 == 1 { c + 1 } else { c };
    }
    if (0x391..=0x3AB).contains(&c) && c != 0x3A2 {
        return c + 32;
    }
    if (0x410..=0x42F).contains(&c) {
        return c + 32;
    }
    if (0x400..=0x40F).contains(&c) {
        return c + 80;
    }
    if c == 0x212A {
        return 'k' as u32;
    }
    if c == 0x212B {
        return 0xE5;
    }
    if (0xFF21..=0xFF3A).contains(&c) {
        return c + 32;
    }
    c
}
fn upper_cp(c: u32) -> u32 {
    if c < 0x80 {
        return if (0x61..=0x7A).contains(&c) { c - 32 } else { c };
    }
    if (0xE0..=0xFE).contains(&c) && c != 0xF7 {
        return c - 32;
    }
    if (0x101..=0x137).contains(&c) && c != 0x131 {
        return if c & 1 == 1 { c - 1 } else { c };
    }
    if (0x13A..=0x148).contains(&c) {
        return if c & 1 == 0 { c - 1 } else { c };
    }
    if (0x14B..=0x177).contains(&c) {
        return if c & 1 == 1 { c - 1 } else { c };
    }
    if (0x3B1..=0x3CB).contains(&c) && c != 0x3C2 {
        return c - 32;
    }
    if (0x430..=0x44F).contains(&c) {
        return c - 32;
    }
    if (0x450..=0x45F).contains(&c) {
        return c - 80;
    }
    c
}

pub fn py_lower(s: &str) -> String {
    if s.is_ascii() {
        return lower_ascii(s);
    }
    let mut o = String::with_capacity(s.len());
    for ch in s.chars() {
        let c = ch as u32;
        if c == 0x130 {
            o.push('i');
            o.push('\u{307}');
            continue;
        }
        append_cp(&mut o, lower_cp(c));
    }
    o
}
pub fn py_upper(s: &str) -> String {
    if s.is_ascii() {
        return upper_ascii(s);
    }
    let mut o = String::with_capacity(s.len());
    for ch in s.chars() {
        append_cp(&mut o, upper_cp(ch as u32));
    }
    o
}
pub fn katla(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'ç' => 'c',
            'ğ' => 'g',
            'ı' => 'i',
            'ö' => 'o',
            'ş' => 's',
            'ü' => 'u',
            'Ç' => 'C',
            'Ğ' => 'G',
            'İ' => 'I',
            'Ö' => 'O',
            'Ş' => 'S',
            'Ü' => 'U',
            'â' => 'a',
            'î' => 'i',
            'û' => 'u',
            'Â' => 'A',
            'Î' => 'I',
            'Û' => 'U',
            _ => c,
        })
        .collect()
}
pub fn goster_buyuk(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    let mut word = String::new();
    let flush = |w: &mut String, o: &mut String| {
        match w.as_str() {
            "KESIN" => o.push_str("KESİN"),
            "HILE" => o.push_str("HİLE"),
            "SUPHELI" => o.push_str("ŞÜPHELİ"),
            "ISLEV" => o.push_str("İŞLEV"),
            "TEMIZ" => o.push_str("TEMİZ"),
            "BILGI" => o.push_str("BİLGİ"),
            other => o.push_str(other),
        }
        w.clear();
    };
    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            word.push(c);
        } else {
            flush(&mut word, &mut o);
            o.push(c);
        }
    }
    flush(&mut word, &mut o);
    o.replace("resmi Fabric modulu", "resmi Fabric modülü")
        .replace("kanit yetersiz", "kanıt yetersiz")
}
pub fn ulen(s: &str) -> usize {
    s.chars().count()
}
pub fn uslice(s: &str, n: usize) -> String {
    match s.char_indices().nth(n) {
        Some((i, _)) => s[..i].to_string(),
        None => s.to_string(),
    }
}
pub fn utail(s: &str, n: usize) -> String {
    let total = ulen(s);
    if total <= n {
        return s.to_string();
    }
    let skip = total - n;
    match s.char_indices().nth(skip) {
        Some((i, _)) => s[i..].to_string(),
        None => String::new(),
    }
}

pub fn split(s: &str, sep: &str, maxsplit: i32) -> StrList {
    let mut out = StrList::new();
    if sep.is_empty() {
        out.push(s.to_string());
        return out;
    }
    let mut pos = 0usize;
    let mut n = 0i32;
    loop {
        if maxsplit >= 0 && n >= maxsplit {
            break;
        }
        let k = match s[pos..].find(sep) {
            Some(k) => pos + k,
            None => break,
        };
        out.push(s[pos..k].to_string());
        pos = k + sep.len();
        n += 1;
    }
    out.push(s[pos..].to_string());
    out
}

pub fn rsplit(s: &str, sep: &str, maxsplit: i32) -> StrList {
    if maxsplit < 0 {
        return split(s, sep, -1);
    }
    let mut rev = StrList::new();
    let mut end = s.len();
    let mut n = 0i32;
    while n < maxsplit {
        if end < sep.len() {
            break;
        }
        let k = match s[..end].rfind(sep) {
            Some(k) => k,
            None => break,
        };
        rev.push(s[k + sep.len()..end].to_string());
        end = k;
        n += 1;
    }
    rev.push(s[..end].to_string());
    rev.reverse();
    rev
}

fn is_ws_byte(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) || (0x1c..=0x1f).contains(&c)
}

pub fn split_ws(s: &str) -> StrList {
    let b = s.as_bytes();
    let n = b.len();
    let mut out = StrList::new();
    let mut i = 0usize;
    while i < n {
        while i < n && is_ws_byte(b[i]) {
            i += 1;
        }
        if i >= n {
            break;
        }
        let mut j = i;
        while j < n && !is_ws_byte(b[j]) {
            j += 1;
        }
        out.push(s[i..j].to_string());
        i = j;
    }
    out
}

pub fn splitlines(s: &str) -> StrList {
    let p = s.as_bytes();
    let n = p.len();
    let mut out = StrList::new();
    let (mut i, mut start) = (0usize, 0usize);
    while i < n {
        let c = p[i];
        let mut brk = 0usize;
        if c == b'\n' || c == 0x0b || c == 0x0c || c == 0x1c || c == 0x1d || c == 0x1e {
            brk = 1;
        } else if c == b'\r' {
            brk = if i + 1 < n && p[i + 1] == b'\n' { 2 } else { 1 };
        } else if c == 0xC2 && i + 1 < n && p[i + 1] == 0x85 {
            brk = 2;
        } else if c == 0xE2 && i + 2 < n && p[i + 1] == 0x80 && (p[i + 2] == 0xA8 || p[i + 2] == 0xA9) {
            brk = 3;
        }
        if brk != 0 {
            out.push(s[start..i].to_string());
            i += brk;
            start = i;
        } else {
            i += 1;
        }
    }
    if start < n {
        out.push(s[start..].to_string());
    }
    out
}

pub fn join<S: AsRef<str>>(v: &[S], sep: &str) -> String {
    let tot: usize = v.iter().map(|x| x.as_ref().len() + sep.len()).sum();
    let mut o = String::with_capacity(tot);
    for (i, x) in v.iter().enumerate() {
        if i != 0 {
            o.push_str(sep);
        }
        o.push_str(x.as_ref());
    }
    o
}

fn bytes_to_string(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(b).into_owned(),
    }
}

pub fn strip(s: &str, chars: &str) -> String {
    let b = s.as_bytes();
    let c = chars.as_bytes();
    let a = match b.iter().position(|x| !c.contains(x)) {
        Some(a) => a,
        None => return String::new(),
    };
    let e = b.iter().rposition(|x| !c.contains(x)).unwrap_or(a);
    bytes_to_string(&b[a..=e])
}
pub fn lstrip(s: &str, chars: &str) -> String {
    let b = s.as_bytes();
    let c = chars.as_bytes();
    match b.iter().position(|x| !c.contains(x)) {
        Some(a) => bytes_to_string(&b[a..]),
        None => String::new(),
    }
}
pub fn rstrip(s: &str, chars: &str) -> String {
    let b = s.as_bytes();
    let c = chars.as_bytes();
    match b.iter().rposition(|x| !c.contains(x)) {
        Some(e) => bytes_to_string(&b[..=e]),
        None => String::new(),
    }
}

fn is_uspace(c: u32) -> bool {
    (9..=13).contains(&c)
        || c == 32
        || (0x1c..=0x1f).contains(&c)
        || c == 0x85
        || c == 0xA0
        || c == 0x1680
        || (0x2000..=0x200A).contains(&c)
        || c == 0x2028
        || c == 0x2029
        || c == 0x202F
        || c == 0x205F
        || c == 0x3000
}
pub fn pystrip(s: &str) -> String {
    s.trim_matches(|c: char| is_uspace(c as u32)).to_string()
}
pub fn replace_all(s: &str, a: &str, b: &str) -> String {
    if a.is_empty() {
        return s.to_string();
    }
    s.replace(a, b)
}
pub fn rpartition_tail(s: &str, sep: &str) -> String {
    match s.rfind(sep) {
        Some(k) => s[k + sep.len()..].to_string(),
        None => s.to_string(),
    }
}
pub fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}
pub fn itos(v: i64) -> String {
    v.to_string()
}
pub fn dtos1(v: f64) -> String {
    format!("{:.1}", v)
}
pub fn is_hex40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

pub fn latin1_to_utf8(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

const CP1252_HI: [u16; 32] = [
    0x20AC, 0, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0, 0x017D, 0, 0,
    0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0, 0x017E, 0x0178,
];

pub fn cp1252_to_utf8(b: &[u8], replace: bool) -> String {
    let mut o = String::with_capacity(b.len());
    for &c in b {
        if (0x80..0xA0).contains(&c) {
            let u = CP1252_HI[(c - 0x80) as usize];
            if u != 0 {
                append_cp(&mut o, u as u32);
            } else if replace {
                o.push('\u{FFFD}');
            }
        } else {
            o.push(c as char);
        }
    }
    o
}

pub fn cp1254_to_utf8(b: &[u8]) -> String {
    let mut o = String::with_capacity(b.len());
    for &c in b {
        let mut u = c as u32;
        if (0x80..0xA0).contains(&c) {
            u = CP1252_HI[(c - 0x80) as usize] as u32;
            if c == 0x8E || c == 0x9E {
                u = 0;
            }
            if u == 0 {
                u = 0xFFFD;
            }
        } else if c == 0xD0 {
            u = 0x011E;
        } else if c == 0xDD {
            u = 0x0130;
        } else if c == 0xDE {
            u = 0x015E;
        } else if c == 0xF0 {
            u = 0x011F;
        } else if c == 0xFD {
            u = 0x0131;
        } else if c == 0xFE {
            u = 0x015F;
        }
        append_cp(&mut o, u);
    }
    o
}

const CP437_HI: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC,
    0x00C4, 0x00C5, 0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, 0x00FF, 0x00D6, 0x00DC, 0x00A2,
    0x00A3, 0x00A5, 0x20A7, 0x0192, 0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310,
    0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, 0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, 0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C,
    0x255E, 0x255F, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559,
    0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, 0x03B1, 0x00DF,
    0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, 0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2,
    0x25A0, 0x00A0,
];

pub fn cp437_to_utf8(b: &[u8]) -> String {
    let mut o = String::with_capacity(b.len());
    for &c in b {
        if c < 0x80 {
            o.push(c as char);
        } else {
            append_cp(&mut o, CP437_HI[(c - 0x80) as usize] as u32);
        }
    }
    o
}

fn decode_one(p: &[u8]) -> (u32, usize, bool) {
    let n = p.len();
    let c = match p.first() {
        Some(&c) => c as u32,
        None => return (0xFFFD, 1, true),
    };
    if c < 0x80 {
        return (c, 1, false);
    }
    let (need, mut v, minv): (usize, u32, u32) = if (0xC2..=0xDF).contains(&c) {
        (1, c & 0x1F, 0x80)
    } else if (0xE0..=0xEF).contains(&c) {
        (2, c & 0x0F, 0x800)
    } else if (0xF0..=0xF4).contains(&c) {
        (3, c & 0x07, 0x10000)
    } else {
        return (0xFFFD, 1, true);
    };
    if need >= n {
        return (0xFFFD, 1, true);
    }
    for &x in &p[1..=need] {
        if (x & 0xC0) != 0x80 {
            return (0xFFFD, 1, true);
        }
        v = (v << 6) | (x as u32 & 0x3F);
    }
    if v < minv || v > 0x10FFFF {
        return (0xFFFD, 1, true);
    }
    (v, need + 1, false)
}

pub fn utf8_valid(b: &[u8], surrogatepass: bool) -> bool {
    let n = b.len();
    let mut i = 0usize;
    while i < n {
        if b[i] < 0x80 {
            i += 1;
            continue;
        }
        let (cp, k, bad) = decode_one(&b[i..]);
        if bad {
            return false;
        }
        if (0xD800..=0xDFFF).contains(&cp) && !surrogatepass {
            return false;
        }
        i += k;
    }
    true
}

pub fn utf8_decode(b: &[u8], mode: i32) -> String {
    let n = b.len();
    let mut o = String::with_capacity(n);
    let mut i = 0usize;
    while i < n {
        if b[i] < 0x80 {
            o.push(b[i] as char);
            i += 1;
            continue;
        }
        let (cp, k, mut bad) = decode_one(&b[i..]);
        if !bad && (0xD800..=0xDFFF).contains(&cp) {
            bad = true;
        }
        if bad {
            if mode == 0 {
                o.push('\u{FFFD}');
            }
            i += 1;
            while i < n && (b[i] & 0xC0) == 0x80 && mode == 0 {
                i += 1;
            }
            continue;
        }
        append_cp(&mut o, cp);
        i += k;
    }
    o
}

fn u16_at(p: &[u8], i: usize, le: bool) -> u32 {
    let a = p.get(2 * i).copied().unwrap_or(0) as u32;
    let b = p.get(2 * i + 1).copied().unwrap_or(0) as u32;
    if le {
        a | (b << 8)
    } else {
        (a << 8) | b
    }
}

pub fn utf16_decode(b: &[u8], le: bool, mode: i32) -> String {
    let n = b.len() / 2;
    let mut o = String::with_capacity(b.len());
    let mut i = 0usize;
    while i < n {
        let u = u16_at(b, i, le);
        if (0xD800..=0xDBFF).contains(&u) {
            if i + 1 < n {
                let u2 = u16_at(b, i + 1, le);
                if (0xDC00..=0xDFFF).contains(&u2) {
                    append_cp(&mut o, 0x10000 + ((u - 0xD800) << 10) + (u2 - 0xDC00));
                    i += 2;
                    continue;
                }
            }
            if mode == 0 {
                o.push('\u{FFFD}');
            }
            i += 1;
            continue;
        }
        if (0xDC00..=0xDFFF).contains(&u) {
            if mode == 0 {
                o.push('\u{FFFD}');
            }
            i += 1;
            continue;
        }
        append_cp(&mut o, u);
        i += 1;
    }
    if (b.len() & 1) != 0 && mode == 0 {
        o.push('\u{FFFD}');
    }
    o
}

pub fn utf16_auto(b: &[u8], mode: i32) -> String {
    if b.len() >= 2 {
        let (a, c) = (b[0], b[1]);
        if a == 0xFF && c == 0xFE {
            return utf16_decode(&b[2..], true, mode);
        }
        if a == 0xFE && c == 0xFF {
            return utf16_decode(&b[2..], false, mode);
        }
    }
    utf16_decode(b, true, mode)
}

pub fn utf16_strict(b: &[u8], le: bool, out: &mut String) -> bool {
    out.clear();
    if b.len() & 1 != 0 {
        return false;
    }
    let n = b.len() / 2;
    out.reserve(b.len());
    let mut i = 0usize;
    while i < n {
        let u = u16_at(b, i, le);
        if (0xD800..=0xDBFF).contains(&u) {
            if i + 1 >= n {
                return false;
            }
            let u2 = u16_at(b, i + 1, le);
            if !(0xDC00..=0xDFFF).contains(&u2) {
                return false;
            }
            append_cp(out, 0x10000 + ((u - 0xD800) << 10) + (u2 - 0xDC00));
            i += 2;
            continue;
        }
        if (0xDC00..=0xDFFF).contains(&u) {
            return false;
        }
        append_cp(out, u);
        i += 1;
    }
    true
}

pub fn widen(u8s: &str) -> Vec<u16> {
    u8s.encode_utf16().collect()
}
pub fn narrow(w: &[u16]) -> String {
    String::from_utf16_lossy(w)
}
pub fn codepoints(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}
pub fn from_codepoints(cps: &[u32]) -> String {
    let mut o = String::with_capacity(cps.len());
    for &c in cps {
        append_cp(&mut o, c);
    }
    o
}
pub fn append_cp(out: &mut String, cp: u32) {
    out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
}
pub fn chars_to_bytes(text_utf8: &str, out: &mut Vec<u8>) -> bool {
    out.clear();
    out.reserve(text_utf8.len());
    for ch in text_utf8.chars() {
        let cp = ch as u32;
        if cp < 256 {
            out.push(cp as u8);
            continue;
        }
        match CP1252_HI.iter().position(|&x| x as u32 == cp) {
            Some(j) => out.push(0x80 + j as u8),
            None => return false,
        }
    }
    true
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex_lower(&Sha256::digest(data))
}
pub fn sha1_hex(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    hex_lower(&Sha1::digest(data))
}
pub fn crc32_of(data: &[u8], start: u32) -> u32 {
    let mut h = crc32fast::Hasher::new_with_initial(start);
    h.update(data);
    h.finalize()
}
pub fn hex_lower(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut o = String::with_capacity(b.len() * 2);
    for &c in b {
        o.push(H[(c >> 4) as usize] as char);
        o.push(H[(c & 15) as usize] as char);
    }
    o
}
pub fn rd16(p: &[u8]) -> u16 {
    match p.get(..2) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]),
        None => 0,
    }
}
pub fn rd32(p: &[u8]) -> u32 {
    match p.get(..4) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}
pub fn rd64(p: &[u8]) -> u64 {
    match p.get(..8) {
        Some(b) => u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        None => 0,
    }
}
pub fn rb16(p: &[u8]) -> u16 {
    match p.get(..2) {
        Some(b) => u16::from_be_bytes([b[0], b[1]]),
        None => 0,
    }
}
pub fn rb32(p: &[u8]) -> u32 {
    match p.get(..4) {
        Some(b) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

#[cfg(windows)]
pub const SEP: char = '\\';
#[cfg(not(windows))]
pub const SEP: char = '/';

fn isseps(c: u8) -> bool {
    c == b'\\' || c == b'/'
}

fn splitdrive(p: &str) -> (&str, &str) {
    let b = p.as_bytes();
    if b.len() >= 2 && isseps(b[0]) && isseps(b[1]) {
        let mut i = 2usize;
        while i < b.len() && !isseps(b[i]) {
            i += 1;
        }
        if i >= b.len() {
            return (p, "");
        }
        let mut j = i + 1;
        while j < b.len() && !isseps(b[j]) {
            j += 1;
        }
        return (&p[..j], &p[j..]);
    }
    if b.len() >= 2 && b[1] == b':' {
        return (&p[..2], &p[2..]);
    }
    ("", p)
}

pub fn path_basename(p: &str) -> String {
    let (_, r) = splitdrive(p);
    let b = r.as_bytes();
    let mut i = b.len();
    while i > 0 && !isseps(b[i - 1]) {
        i -= 1;
    }
    r[i..].to_string()
}
pub fn path_dirname(p: &str) -> String {
    let (drive, r) = splitdrive(p);
    let b = r.as_bytes();
    let mut i = b.len();
    while i > 0 && !isseps(b[i - 1]) {
        i -= 1;
    }
    let head = &r[..i];
    let hb = head.as_bytes();
    let mut k = hb.len();
    while k > 0 && isseps(hb[k - 1]) {
        k -= 1;
    }
    let h2 = if k != 0 { &head[..k] } else { head };
    let mut o = String::with_capacity(drive.len() + h2.len());
    o.push_str(drive);
    o.push_str(h2);
    o
}
pub fn path_join(a: &str, b: &str) -> String {
    if a.is_empty() {
        return b.to_string();
    }
    if b.is_empty() {
        let mut o = a.to_string();
        if !o.as_bytes().last().is_some_and(|&c| isseps(c)) {
            o.push('\\');
        }
        return o;
    }
    let (db, _) = splitdrive(b);
    if !db.is_empty() {
        return b.to_string();
    }
    if isseps(b.as_bytes()[0]) {
        let (da, _) = splitdrive(a);
        return format!("{}{}", da, b);
    }
    let mut o = a.to_string();
    let ob = o.as_bytes();
    if !isseps(ob[ob.len() - 1]) && !(ob.len() == 2 && ob[1] == b':') {
        o.push('\\');
    }
    o.push_str(b);
    o
}
pub fn path_join_all(parts: &[&str]) -> String {
    let mut o = String::new();
    for (i, p) in parts.iter().enumerate() {
        if i == 0 {
            o = p.to_string();
        } else {
            o = path_join(&o, p);
        }
    }
    o
}
pub fn path_splitext(p: &str) -> (String, String) {
    let b = p.as_bytes();
    let mut sep: Option<usize> = None;
    for (i, &c) in b.iter().enumerate() {
        if isseps(c) {
            sep = Some(i);
        }
    }
    if let Some(dot) = p.rfind('.') {
        let sepi: i64 = sep.map(|x| x as i64).unwrap_or(-1);
        if dot as i64 > sepi {
            let mut fi = (sepi + 1) as usize;
            while fi < dot {
                if b[fi] != b'.' {
                    return (p[..dot].to_string(), p[dot..].to_string());
                }
                fi += 1;
            }
        }
    }
    (p.to_string(), String::new())
}
pub fn path_ext_lower(p: &str) -> String {
    py_lower(&path_splitext(&path_basename(p)).1)
}
pub fn path_normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let p = replace_all(path, "/", "\\");
    let (drive, rest) = splitdrive(&p);
    let mut prefix = drive.to_string();
    if p.starts_with("\\\\?\\") || p.starts_with("\\\\.\\") {
        return p;
    }
    let root = rest.starts_with('\\');
    if root {
        prefix.push('\\');
    }
    let mut comps: Vec<&str> = Vec::new();
    for c in rest.split('\\') {
        if c.is_empty() || c == "." {
            continue;
        }
        if c == ".." {
            if comps.last().is_some_and(|&l| l != "..") {
                comps.pop();
            } else if !root {
                comps.push("..");
            }
            continue;
        }
        comps.push(c);
    }
    let out = format!("{}{}", prefix, comps.join("\\"));
    if out.is_empty() {
        return ".".to_string();
    }
    out
}
pub fn path_abspath(p: &str) -> String {
    let p = if p.is_empty() { "." } else { p };
    let w = wz(p);
    // SAFETY: `w` NUL ile biten geçerli bir UTF-16 dizisidir.
    let n = unsafe { GetFullPathNameW(PCWSTR(w.as_ptr()), None, None) };
    if n == 0 {
        return path_normpath(p);
    }
    let mut out = vec![0u16; n as usize];
    // SAFETY: `out` n birimlik yazılabilir tampondur.
    let k = unsafe { GetFullPathNameW(PCWSTR(w.as_ptr()), Some(&mut out), None) };
    out.truncate((k as usize).min(out.len()));
    narrow(&out)
}
pub fn path_normcase(p: &str) -> String {
    let mut w = widen(&replace_all(p, "/", "\\"));
    if !w.is_empty() {
        // SAFETY: `w` yazılabilir geçerli bir dilimdir.
        unsafe {
            CharLowerBuffW(&mut w);
        }
    }
    narrow(&w)
}
pub fn path_norm(p: &str) -> String {
    path_normcase(&path_abspath(p))
}
pub fn path_isabs(p: &str) -> bool {
    let (drive, rest) = splitdrive(p);
    if drive.len() > 2 {
        return true; // UNC
    }
    !drive.is_empty() && rest.as_bytes().first().is_some_and(|&c| isseps(c))
}
pub fn path_relpath(p: &str, base: &str) -> String {
    let a = path_abspath(p);
    let b = path_abspath(base);
    let an = path_normcase(&a);
    let mut bn = path_normcase(&b);
    if !bn.as_bytes().last().is_some_and(|&c| isseps(c)) && !bn.is_empty() {
        bn.push('\\');
    }
    if an.starts_with(&bn) {
        return match a.get(bn.len()..) {
            Some(r) => r.to_string(),
            None => a,
        };
    }
    a
}

fn wz(s: &str) -> Vec<u16> {
    let mut w: Vec<u16> = s.encode_utf16().collect();
    w.push(0);
    w
}

fn longw_raw(p: &str) -> Vec<u16> {
    let mut w = widen(p);
    for c in w.iter_mut() {
        if *c == b'/' as u16 {
            *c = b'\\' as u16;
        }
    }
    let pre = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    if w.len() >= 240 && !(w.len() >= 4 && w[..4] == pre) {
        if w.len() >= 2 && w[1] == b':' as u16 {
            let mut o: Vec<u16> = pre.to_vec();
            o.extend_from_slice(&w);
            return o;
        }
        if w.len() >= 2 && w[0] == b'\\' as u16 && w[1] == b'\\' as u16 {
            let mut o: Vec<u16> = "\\\\?\\UNC\\".encode_utf16().collect();
            o.extend_from_slice(&w[2..]);
            return o;
        }
    }
    w
}
fn longw(p: &str) -> Vec<u16> {
    let mut w = longw_raw(p);
    w.push(0);
    w
}

const FT_UNIX_DIFF: i64 = 116_444_736_000_000_000;

fn ft_epoch(low: u32, high: u32) -> f64 {
    let v = ((high as u64) << 32) | low as u64;
    ((v as i64).wrapping_sub(FT_UNIX_DIFF)) as f64 / 1e7
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: tutamak CreateFileW'den geldi ve yalnızca burada kapatılır.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FileStat {
    pub ok: bool,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_link: bool,
    pub size: u64,
    pub mtime: f64,
    pub attrs: u32,
}
pub fn stat_path(p: &str, follow: bool) -> FileStat {
    let _ = follow;
    let mut st = FileStat::default();
    let w = longw(p);
    let mut d = WIN32_FILE_ATTRIBUTE_DATA::default();
    // SAFETY: `w` NUL'lu, `d` doğru boyutlu çıktı yapısı.
    let r = unsafe {
        GetFileAttributesExW(
            PCWSTR(w.as_ptr()),
            GetFileExInfoStandard,
            &mut d as *mut WIN32_FILE_ATTRIBUTE_DATA as *mut core::ffi::c_void,
        )
    };
    if r.is_err() {
        return st;
    }
    st.ok = true;
    st.attrs = d.dwFileAttributes;
    st.is_dir = (d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0;
    st.is_file = !st.is_dir && (d.dwFileAttributes & FILE_ATTRIBUTE_DEVICE.0) == 0;
    st.size = ((d.nFileSizeHigh as u64) << 32) | d.nFileSizeLow as u64;
    st.mtime = ft_epoch(d.ftLastWriteTime.dwLowDateTime, d.ftLastWriteTime.dwHighDateTime);
    st.is_link = false;
    st
}
pub fn is_file(p: &str) -> bool {
    !p.is_empty() && stat_path(p, true).is_file
}
pub fn is_dir(p: &str) -> bool {
    !p.is_empty() && stat_path(p, true).is_dir
}
pub fn exists(p: &str) -> bool {
    !p.is_empty() && stat_path(p, true).ok
}
pub fn file_size(p: &str) -> Option<u64> {
    let s = stat_path(p, true);
    if !s.ok {
        return None;
    }
    Some(s.size)
}
pub fn file_mtime(p: &str) -> Option<f64> {
    let s = stat_path(p, true);
    if !s.ok {
        return None;
    }
    Some(s.mtime)
}

fn open_read(p: &str) -> Option<Handle> {
    let w = longw(p);
    // SAFETY: `w` NUL ile biten geçerli yol.
    let h = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            0x8000_0000, // GENERIC_READ
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN,
            None,
        )
    };
    match h {
        Ok(h) if h != INVALID_HANDLE_VALUE => Some(Handle(h)),
        _ => None,
    }
}
fn read_some(h: &Handle, buf: &mut [u8]) -> Option<usize> {
    let mut r = 0u32;
    // SAFETY: `buf` yazılabilir; `r` geçerli çıktı değişkeni.
    let ok = unsafe { ReadFile(h.0, Some(buf), Some(&mut r), None) };
    if ok.is_err() {
        None
    } else {
        Some(r as usize)
    }
}
fn file_size_of(h: &Handle) -> i64 {
    let mut sz = 0i64;
    // SAFETY: `sz` geçerli çıktı değişkeni.
    if unsafe { GetFileSizeEx(h.0, &mut sz) }.is_err() {
        sz = 0;
    }
    sz
}

pub fn read_file(p: &str, limit: i64, offset: i64) -> Option<Bytes> {
    let h = open_read(p)?;
    let sz = file_size_of(&h);
    if offset > 0 {
        // SAFETY: tutamak geçerli.
        unsafe {
            let _ = SetFilePointerEx(h.0, offset, None, FILE_BEGIN);
        }
    }
    let mut want: i64 = sz - if offset > 0 { offset } else { 0 };
    if want < 0 {
        want = 0;
    }
    if limit >= 0 && want > limit {
        want = limit;
    }
    let want = want as usize;
    let mut out: Bytes = Vec::new();
    if out.try_reserve_exact(want).is_err() {
        return None;
    }
    out.resize(want, 0);
    let mut got = 0usize;
    while got < want {
        let chunk = (want - got).min(1 << 24);
        match read_some(&h, &mut out[got..got + chunk]) {
            None => {
                if got == 0 {
                    return None;
                }
                break;
            }
            Some(0) => break,
            Some(r) => got += r,
        }
    }
    if got == want && (limit < 0 || (got as i64) < limit) && sz == 0 {
        let mut tmp = vec![0u8; 65536];
        while let Some(r) = read_some(&h, &mut tmp) {
            if r == 0 {
                break;
            }
            out.extend_from_slice(&tmp[..r]);
            got += r;
            if limit >= 0 && got as i64 >= limit {
                break;
            }
        }
    } else {
        out.truncate(got);
    }
    if limit >= 0 && out.len() as i64 > limit {
        out.truncate(limit as usize);
    }
    Some(out)
}

pub fn read_head_tail(p: &str, head_len: usize, tail_len: usize, head: &mut Bytes, tail: &mut Bytes) -> bool {
    head.clear();
    tail.clear();
    let h = match open_read(p) {
        Some(h) => h,
        None => return false,
    };
    let fsz = file_size_of(&h) as u64;
    let rd = |want: usize, out: &mut Bytes| {
        out.clear();
        if out.try_reserve_exact(want).is_err() {
            return;
        }
        out.resize(want, 0);
        let mut got = 0usize;
        while got < want {
            let chunk = (want - got).min(u32::MAX as usize);
            match read_some(&h, &mut out[got..got + chunk]) {
                Some(r) if r > 0 => got += r,
                _ => break,
            }
        }
        out.truncate(got);
    };
    if fsz <= (head_len as u64).saturating_add(tail_len as u64) {
        rd(fsz as usize, head);
        *tail = head.clone();
        return true;
    }
    rd(head_len, head);
    if tail_len != 0 {
        let off = (fsz - tail_len as u64) as i64;
        // SAFETY: tutamak geçerli.
        if unsafe { SetFilePointerEx(h.0, off, None, FILE_BEGIN) }.is_ok() {
            rd(tail_len, tail);
        }
    }
    !head.is_empty() || fsz == 0
}

pub fn read_head_tail_streams(
    p: &str,
    head_len: usize,
    tail_len: usize,
    head: &mut Bytes,
    tail: &mut Bytes,
    streams: &mut Vec<(String, i64)>,
) -> bool {
    streams.clear();
    head.clear();
    tail.clear();
    let h = match open_read(p) {
        Some(h) => h,
        None => return false,
    };
    #[cfg(windows)]
    {
        use windows::Win32::Storage::FileSystem::{FileStreamInfo, GetFileInformationByHandleEx};
        let mut buf = vec![0u64; 512]; // 4 KB, 8 bayt hizalı
                                       // SAFETY: tutamak geçerli; tampon boyutu doğru verilir.
        let ok = unsafe {
            GetFileInformationByHandleEx(h.0, FileStreamInfo, buf.as_mut_ptr() as *mut core::ffi::c_void, 4096)
        };
        if ok.is_ok() {
            // SAFETY: u64 tamponunun bayt görünümü; uzunluk aynı bellek bölgesi.
            let b = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, 4096) };
            let mut off = 0usize;
            while off + 24 <= b.len() && streams.len() < 16 {
                let next = rd32(&b[off..]) as usize;
                let nlen = rd32(&b[off + 4..]) as usize;
                let size = rd64(&b[off + 8..]) as i64;
                let nb = &b[(off + 24).min(b.len())..(off + 24 + nlen).min(b.len())];
                let w: Vec<u16> = nb.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                let nm = narrow(&w);
                let parts = split(&nm, ":", -1);
                if parts.len() >= 2 && !parts[1].is_empty() {
                    streams.push((parts[1].clone(), size));
                }
                if next == 0 {
                    break;
                }
                off += next;
            }
        }
    }
    let fsz = file_size_of(&h) as u64;
    let rd = |want: usize, out: &mut Bytes| {
        out.clear();
        if out.try_reserve_exact(want).is_err() {
            return;
        }
        out.resize(want, 0);
        let mut got = 0usize;
        while got < want {
            let chunk = (want - got).min(u32::MAX as usize);
            match read_some(&h, &mut out[got..got + chunk]) {
                Some(r) if r > 0 => got += r,
                _ => break,
            }
        }
        out.truncate(got);
    };
    if fsz <= (head_len as u64).saturating_add(tail_len as u64) {
        rd(fsz as usize, head);
        *tail = head.clone();
        return true;
    }
    rd(head_len, head);
    if tail_len != 0 {
        let off = (fsz - tail_len as u64) as i64;
        // SAFETY: tutamak geçerli.
        if unsafe { SetFilePointerEx(h.0, off, None, FILE_BEGIN) }.is_ok() {
            rd(tail_len, tail);
        }
    }
    !head.is_empty() || fsz == 0
}

pub fn write_file(p: &str, data: &[u8]) -> bool {
    let w = longw(p);
    // SAFETY: `w` NUL ile biten geçerli yol.
    let h = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            0x4000_0000, // GENERIC_WRITE
            FILE_SHARE_MODE(0),
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };
    let h = match h {
        Ok(h) if h != INVALID_HANDLE_VALUE => Handle(h),
        _ => return false,
    };
    let mut off = 0usize;
    while off < data.len() {
        let chunk = (data.len() - off).min(1 << 24);
        let mut wr = 0u32;
        // SAFETY: dilim geçerli, `wr` geçerli çıktı değişkeni.
        let ok = unsafe { WriteFile(h.0, Some(&data[off..off + chunk]), Some(&mut wr), None) };
        if ok.is_err() || wr == 0 {
            return false;
        }
        off += wr as usize;
    }
    true
}

#[derive(Debug, Clone, Default)]
pub struct DirEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_link: bool,
    pub reparse: bool,
    pub size: u64,
    pub attrs: u32,
    pub mtime: f64,
}

struct FindHandle(HANDLE);
impl Drop for FindHandle {
    fn drop(&mut self) {
        // SAFETY: tutamak FindFirstFileExW'den geldi.
        unsafe {
            let _ = FindClose(self.0);
        }
    }
}

const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

pub fn list_dir(dir: &str, out: &mut Vec<DirEntry>) -> bool {
    out.clear();
    let mut pat = longw_raw(dir);
    if !pat.is_empty() && pat[pat.len() - 1] != b'\\' as u16 {
        pat.push(b'\\' as u16);
    }
    pat.push(b'*' as u16);
    pat.push(0);
    let mut fd = WIN32_FIND_DATAW::default();
    // SAFETY: `pat` NUL'lu, `fd` doğru boyutlu çıktı yapısı.
    let r = unsafe {
        FindFirstFileExW(
            PCWSTR(pat.as_ptr()),
            FindExInfoBasic,
            &mut fd as *mut WIN32_FIND_DATAW as *mut core::ffi::c_void,
            FindExSearchNameMatch,
            None,
            FIND_FIRST_EX_LARGE_FETCH,
        )
    };
    let h = match r {
        Ok(h) if h != INVALID_HANDLE_VALUE => FindHandle(h),
        Ok(_) => return false,
        Err(e) => {
            return e.code().0 as u32 == 0x8007_0002;
        }
    };
    loop {
        let len = fd.cFileName.iter().position(|&c| c == 0).unwrap_or(fd.cFileName.len());
        let name_w = &fd.cFileName[..len];
        let skip = name_w == [b'.' as u16] || name_w == [b'.' as u16, b'.' as u16];
        if !skip {
            let name = narrow(name_w);
            let mut e = DirEntry {
                path: path_join(dir, &name),
                name,
                ..Default::default()
            };
            e.attrs = fd.dwFileAttributes;
            e.reparse = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0;
            e.is_link = e.reparse && fd.dwReserved0 == IO_REPARSE_TAG_SYMLINK;
            e.is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0;
            e.is_file = !e.is_dir;
            e.size = ((fd.nFileSizeHigh as u64) << 32) | fd.nFileSizeLow as u64;
            e.mtime = ft_epoch(fd.ftLastWriteTime.dwLowDateTime, fd.ftLastWriteTime.dwHighDateTime);
            out.push(e);
        }
        // SAFETY: tutamak geçerli, `fd` geçerli çıktı yapısı.
        if unsafe { FindNextFileW(h.0, &mut fd) }.is_err() {
            break;
        }
    }
    true
}
pub fn listdir_names(dir: &str) -> StrList {
    let mut v = Vec::new();
    if list_dir(dir, &mut v) {
        v.into_iter().map(|e| e.name).collect()
    } else {
        StrList::new()
    }
}
pub fn walk_files(root: &str, cb: &mut dyn FnMut(&str), max_files: i32) {
    let mut stack: Vec<String> = vec![root.to_string()];
    let mut n = 0i32;
    while let Some(d) = stack.pop() {
        let mut ents = Vec::new();
        if !list_dir(&d, &mut ents) {
            continue;
        }
        for e in ents {
            if e.is_dir {
                if !e.reparse && !e.is_link {
                    stack.push(e.path);
                }
                continue;
            }
            if e.is_link {
                continue;
            }
            cb(&e.path);
            n = n.wrapping_add(1);
            if n >= max_files {
                return;
            }
        }
    }
}
pub fn temp_dir() -> String {
    const MAX_PATH: usize = 260;
    let mut buf = vec![0u16; MAX_PATH + 2];
    // SAFETY: tampon MAX_PATH+1 birimlik dilimle verilir.
    let n = unsafe { GetTempPathW(Some(&mut buf[..MAX_PATH + 1])) } as usize;
    let mut t = narrow(&buf[..n.min(MAX_PATH + 1)]);
    while t.len() > 3 && (t.ends_with('\\') || t.ends_with('/')) {
        t.pop();
    }
    t
}
pub fn make_temp_dir(prefix: &str) -> String {
    static CTR: AtomicU32 = AtomicU32::new(0);
    for _ in 0..100 {
        let c = CTR.fetch_add(1, Ordering::Relaxed);
        let mut r: u32 = ((now_epoch() * 1000.0) as i64 as u32) ^ c.wrapping_mul(2654435761);
        // SAFETY: yan etkisiz Win32 çağrısı.
        r ^= unsafe { GetCurrentProcessId() };
        let p = path_join(&temp_dir(), &format!("{}{:08x}", prefix, r));
        let w = longw(&p);
        // SAFETY: `w` NUL ile biten geçerli yol.
        if unsafe { CreateDirectoryW(PCWSTR(w.as_ptr()), None) }.is_ok() {
            return p;
        }
    }
    String::new()
}
pub fn remove_tree(p: &str) {
    let mut ents = Vec::new();
    if list_dir(p, &mut ents) {
        for e in &ents {
            if e.is_dir && !e.reparse && !e.is_link {
                remove_tree(&e.path);
            } else {
                let w = longw(&e.path);
                // SAFETY: `w` NUL ile biten geçerli yol.
                unsafe {
                    let _ = SetFileAttributesW(PCWSTR(w.as_ptr()), FILE_ATTRIBUTE_NORMAL);
                    if e.is_dir {
                        let _ = RemoveDirectoryW(PCWSTR(w.as_ptr()));
                    } else {
                        let _ = DeleteFileW(PCWSTR(w.as_ptr()));
                    }
                }
            }
        }
    }
    let w = longw(p);
    // SAFETY: `w` NUL ile biten geçerli yol.
    unsafe {
        let _ = RemoveDirectoryW(PCWSTR(w.as_ptr()));
    }
}
pub fn env(name: &str) -> String {
    let w = wz(name);
    // SAFETY: `w` NUL ile biten geçerli ad.
    let n = unsafe { GetEnvironmentVariableW(PCWSTR(w.as_ptr()), None) };
    if n == 0 {
        return String::new();
    }
    let mut v = vec![0u16; n as usize];
    // SAFETY: `v` n birimlik yazılabilir tampon.
    let k = unsafe { GetEnvironmentVariableW(PCWSTR(w.as_ptr()), Some(&mut v)) };
    v.truncate((k as usize).min(v.len()));
    narrow(&v)
}
pub fn home_dir() -> String {
    let u = env("USERPROFILE");
    if !u.is_empty() {
        return u;
    }
    env("HOMEDRIVE") + &env("HOMEPATH")
}
pub fn self_exe_path() -> String {
    let mut buf = vec![0u16; 32768];
    // SAFETY: tampon yazılabilir.
    let n = unsafe { GetModuleFileNameW(None, &mut buf) } as usize;
    narrow(&buf[..n.min(buf.len())])
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Tm {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
}
extern "C" {
    fn _localtime64_s(tm: *mut Tm, t: *const i64) -> c_int;
    fn _mktime64(tm: *mut Tm) -> i64;
    fn _mkgmtime64(tm: *mut Tm) -> i64;
    fn strftime(buf: *mut c_char, max: usize, fmt: *const c_char, tm: *const Tm) -> usize;
}

pub fn now_epoch() -> f64 {
    // SAFETY: yan etkisiz Win32 çağrısı.
    let f = unsafe { GetSystemTimeAsFileTime() };
    ft_epoch(f.dwLowDateTime, f.dwHighDateTime)
}
pub fn filetime_to_epoch(ft: u64) -> Option<f64> {
    const D: u64 = 116_444_736_000_000_000;
    if ft <= D {
        return None;
    }
    let t = (ft - D) as f64 / 1e7;
    if t > 32503680000.0 {
        return None; // 3000 yılı sonrası: geçersiz
    }
    Some(t)
}

fn local_tm(t: f64) -> Option<Tm> {
    let tt = (if t < 0.0 { t - 1.0 } else { t }) as i64;
    if !(0..=0x7_9340_6FFF).contains(&tt) {
        return None;
    }
    let mut out = Tm::default();
    // SAFETY: `out` ve `tt` geçerli işaretçiler.
    let r = unsafe { _localtime64_s(&mut out, &tt) };
    if r == 0 {
        Some(out)
    } else {
        None
    }
}
pub fn fmt_local(t: f64, fmt: &str) -> String {
    let tmv = match local_tm(t) {
        Some(x) => x,
        None => return "?".to_string(),
    };
    let f = fmt.split('\0').next().unwrap_or("");
    let cf = match CString::new(f) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    let mut buf = [0u8; 128];
    // SAFETY: tampon 128 bayt, biçim NUL'lu, `tmv` geçerli.
    let n = unsafe { strftime(buf.as_mut_ptr() as *mut c_char, buf.len(), cf.as_ptr(), &tmv) };
    String::from_utf8_lossy(&buf[..n.min(buf.len())]).into_owned()
}
pub fn fmt_dt(t: Option<f64>) -> String {
    match t {
        None => "-".to_string(),
        Some(t) => fmt_local(t, "%d.%m.%Y %H:%M:%S"),
    }
}
pub fn local_mktime(y: i32, mo: i32, d: i32, h: i32, mi: i32, s: i32) -> f64 {
    let mut tmv = Tm {
        tm_year: y.wrapping_sub(1900),
        tm_mon: mo.wrapping_sub(1),
        tm_mday: d,
        tm_hour: h,
        tm_min: mi,
        tm_sec: s,
        tm_isdst: -1,
        ..Default::default()
    };
    // SAFETY: `tmv` geçerli işaretçi.
    unsafe { _mktime64(&mut tmv) as f64 }
}

fn scan_int(b: &[u8], pos: &mut usize, width: usize) -> Option<i32> {
    let mut i = *pos;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut used = 0usize;
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') && width > 0 {
        neg = b[i] == b'-';
        i += 1;
        used += 1;
    }
    let mut v: i64 = 0;
    let mut nd = 0usize;
    while i < b.len() && b[i].is_ascii_digit() && used < width {
        v = v * 10 + (b[i] - b'0') as i64;
        i += 1;
        used += 1;
        nd += 1;
    }
    if nd == 0 {
        return None;
    }
    *pos = i;
    Some(if neg { -v } else { v } as i32)
}

pub fn parse_utc_iso(s: &str) -> Option<f64> {
    let t = strip(s, WS_CHARS);
    let b = t.as_bytes();
    let mut pos = 0usize;
    let mut vals = [0i32; 6];
    let fmt: [(usize, Option<u8>); 6] = [
        (4, Some(b'-')),
        (2, Some(b'-')),
        (2, Some(b'T')),
        (2, Some(b':')),
        (2, Some(b':')),
        (2, None),
    ];
    for (k, (w, lit)) in fmt.iter().enumerate() {
        vals[k] = scan_int(b, &mut pos, *w)?;
        if let Some(l) = lit {
            if b.get(pos) == Some(l) {
                pos += 1;
            } else {
                return None;
            }
        }
    }
    let mut tmv = Tm {
        tm_year: vals[0].wrapping_sub(1900),
        tm_mon: vals[1].wrapping_sub(1),
        tm_mday: vals[2],
        tm_hour: vals[3],
        tm_min: vals[4],
        tm_sec: vals[5],
        ..Default::default()
    };
    // SAFETY: `tmv` geçerli işaretçi.
    let tt = unsafe { _mkgmtime64(&mut tmv) };
    if tt == -1 {
        return None;
    }
    let mut frac = 0f64;
    if let Some(dot) = t.find('.') {
        let mut j = dot + 1;
        let mut sc = 0.1f64;
        while j < b.len() && b[j].is_ascii_digit() {
            frac += (b[j] - b'0') as f64 * sc;
            sc /= 10.0;
            j += 1;
        }
    }
    Some(tt as f64 + frac)
}

pub fn cpu_count() -> u32 {
    let mut si = SYSTEM_INFO::default();
    // SAFETY: `si` geçerli çıktı yapısı.
    unsafe { GetSystemInfo(&mut si) };
    if si.dwNumberOfProcessors != 0 {
        si.dwNumberOfProcessors
    } else {
        2
    }
}

#[derive(Debug, Default)]
pub struct StopFlag {
    pub v: AtomicBool,
}
impl StopFlag {
    pub fn new() -> Self {
        StopFlag {
            v: AtomicBool::new(false),
        }
    }
    pub fn is_set(&self) -> bool {
        self.v.load(Ordering::Relaxed)
    }
    pub fn set(&self) {
        self.v.store(true, Ordering::SeqCst);
    }
    pub fn clear(&self) {
        self.v.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sl(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn kw() {
        assert_eq!(kw_jni_vms(), "JNI_GetCreatedJavaVMs");
        assert_eq!(kw_jvm_dll(), "jvm.dll");
    }

    #[test]
    fn lower_upper() {
        assert_eq!(py_lower("HeLLo"), "hello");
        assert_eq!(py_lower("ÇĞİŞÖÜ"), "çği\u{307}şöü");
        assert_eq!(py_lower("İ"), "i\u{307}");
        assert_eq!(py_lower("ΑΒΓ"), "αβγ");
        assert_eq!(py_lower("ПРИВЕТ Ѐ"), "привет ѐ");
        assert_eq!(py_lower("\u{212A}"), "k");
        assert_eq!(py_lower("Ａ"), "ａ");
        assert_eq!(py_upper("çğıöşü"), "ÇĞıÖŞÜ"); // önceki sürüm upper_cp ı (U+0131) harfini değiştirmez
        assert_eq!(py_upper("abc"), "ABC");
        assert_eq!(py_upper("привет"), "ПРИВЕТ");
        assert_eq!(py_upper("ß÷"), "ß÷");
        assert_eq!(py_lower("×"), "×");
    }

    #[test]
    fn ulen_slice() {
        assert_eq!(ulen("aç😀"), 3);
        assert_eq!(uslice("aç😀b", 2), "aç");
        assert_eq!(uslice("ab", 5), "ab");
        assert_eq!(uslice("ab", 0), "");
        assert_eq!(utail("aç😀b", 2), "😀b");
        assert_eq!(utail("ab", 5), "ab");
        assert_eq!(utail("ab", 0), "");
    }

    #[test]
    fn split_basic() {
        assert_eq!(split("a,b,c", ",", -1), sl(&["a", "b", "c"]));
        assert_eq!(split("a,b,c", ",", 1), sl(&["a", "b,c"]));
        assert_eq!(split("a,b,c", ",", 0), sl(&["a,b,c"]));
        assert_eq!(split("", ",", -1), sl(&[""]));
        assert_eq!(split("abc", "", -1), sl(&["abc"]));
        assert_eq!(split(",a,", ",", -1), sl(&["", "a", ""]));
        assert_eq!(split("a--b--c", "--", -1), sl(&["a", "b", "c"]));
    }

    #[test]
    fn rsplit_basic() {
        assert_eq!(rsplit("a,b,c", ",", -1), sl(&["a", "b", "c"]));
        assert_eq!(rsplit("a,b,c", ",", 1), sl(&["a,b", "c"]));
        assert_eq!(rsplit("a,b,c", ",", 5), sl(&["a", "b", "c"]));
        assert_eq!(rsplit("abc", ",", 1), sl(&["abc"]));
        assert_eq!(rsplit("a--b--c", "--", 1), sl(&["a--b", "c"]));
        assert_eq!(rsplit("", ",", 1), sl(&[""]));
    }

    #[test]
    fn split_ws_cases() {
        assert_eq!(split_ws("  a  b\tc\n"), sl(&["a", "b", "c"]));
        assert_eq!(split_ws(""), Vec::<String>::new());
        assert_eq!(split_ws("   "), Vec::<String>::new());
        assert_eq!(split_ws("a\x1cb\x1fc"), sl(&["a", "b", "c"]));
        assert_eq!(split_ws("aç  ğ"), sl(&["aç", "ğ"]));
    }

    #[test]
    fn splitlines_cases() {
        assert_eq!(splitlines("a\nb\r\nc\rd"), sl(&["a", "b", "c", "d"]));
        assert_eq!(splitlines("a\n"), sl(&["a"]));
        assert_eq!(splitlines("a\n\nb"), sl(&["a", "", "b"]));
        assert_eq!(splitlines(""), Vec::<String>::new());
        assert_eq!(splitlines("a\u{85}b\u{2028}c\u{2029}d"), sl(&["a", "b", "c", "d"]));
        assert_eq!(
            splitlines("a\x0bb\x0cc\x1cd\x1de\x1ef"),
            sl(&["a", "b", "c", "d", "e", "f"])
        );
        assert_eq!(splitlines("\r\n"), sl(&[""]));
    }

    #[test]
    fn strip_variants() {
        assert_eq!(strip("  a b \t\n", WS_CHARS), "a b");
        assert_eq!(strip("   ", WS_CHARS), "");
        assert_eq!(lstrip("  a ", WS_CHARS), "a ");
        assert_eq!(rstrip("  a ", WS_CHARS), "  a");
        assert_eq!(strip("xxaxx", "x"), "a");
        assert_eq!(lstrip("", WS_CHARS), "");
        assert_eq!(rstrip("\x0b\x0c", WS_CHARS), "");
        assert_eq!(pystrip("\u{a0} a b\u{3000}\x1f"), "a b");
        assert_eq!(pystrip("  x  "), "x");
        assert_eq!(pystrip("\u{200b}x"), "\u{200b}x");
        assert_eq!(pystrip(""), "");
    }

    #[test]
    fn misc_text() {
        assert_eq!(join(&["a", "b"], "-"), "a-b");
        assert_eq!(join::<&str>(&[], "-"), "");
        assert_eq!(replace_all("aaa", "a", "bb"), "bbbbbb");
        assert_eq!(replace_all("abc", "", "x"), "abc");
        assert_eq!(rpartition_tail("a.b.c", "."), "c");
        assert_eq!(rpartition_tail("abc", "."), "abc");
        assert!(is_digits("0123"));
        assert!(!is_digits(""));
        assert!(!is_digits("12a"));
        assert_eq!(itos(-5), "-5");
        assert_eq!(dtos1(1.25), "1.2");
        assert_eq!(dtos1(2.0), "2.0");
        assert!(is_hex40(&"aF".repeat(20)));
        assert!(!is_hex40("abc"));
        assert!(!is_hex40(&"g".repeat(40)));
        assert!(starts_any("abc", &["x", "ab"]));
        assert!(!ends_any("abc", &["x"]));
        assert!(has_any("abc", &["b"]));
    }

    #[test]
    fn encodings_8bit() {
        assert_eq!(latin1_to_utf8(&[0x41, 0xE9, 0xFF]), "Aéÿ");
        assert_eq!(cp1252_to_utf8(&[0x80, 0x81, 0x41, 0x9F], true), "€\u{FFFD}AŸ");
        assert_eq!(cp1252_to_utf8(&[0x80, 0x81, 0x41], false), "€A");
        assert_eq!(
            cp1254_to_utf8(&[0xD0, 0xDD, 0xDE, 0xF0, 0xFD, 0xFE, 0x8E, 0x9E, 0x80]),
            "ĞİŞğış\u{FFFD}\u{FFFD}€"
        );
        assert_eq!(cp437_to_utf8(&[0x41, 0x80, 0xB0, 0xFF]), "AÇ░\u{a0}");
    }

    #[test]
    fn utf8_modes() {
        assert!(utf8_valid("aç😀".as_bytes(), false));
        assert!(!utf8_valid(&[0xFF], false));
        assert!(!utf8_valid(&[0xC3], false));
        assert!(!utf8_valid(&[0xC0, 0x80], false));
        assert!(!utf8_valid(&[0xED, 0xA0, 0x80], false));
        assert!(utf8_valid(&[0xED, 0xA0, 0x80], true));
        assert!(!utf8_valid(&[0xF4, 0x90, 0x80, 0x80], true));
        assert_eq!(utf8_decode(b"ab", 0), "ab");
        assert_eq!(utf8_decode(&[b'a', 0xFF, b'b'], 0), "a\u{FFFD}b");
        assert_eq!(utf8_decode(&[b'a', 0xFF, b'b'], 1), "ab");
        assert_eq!(utf8_decode(&[0xE2, 0x82], 0), "\u{FFFD}");
        assert_eq!(utf8_decode(&[0xE2, 0x82], 1), "");
        assert_eq!(utf8_decode(&[0xED, 0xA0, 0x80, b'x'], 0), "\u{FFFD}x");
        assert_eq!(utf8_decode(&[0x80, 0x80, b'x'], 0), "\u{FFFD}x");
        assert_eq!(utf8_decode(&[0x80, 0x80, b'x'], 1), "x");
        assert_eq!(utf8_decode(&[0xC3, 0xA7], 0), "ç");
    }

    #[test]
    fn utf16_modes() {
        let le = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect() };
        assert_eq!(utf16_decode(&le("aç😀"), true, 0), "aç😀");
        assert_eq!(utf16_decode(&[0x00, 0x61], false, 0), "a");
        assert_eq!(utf16_decode(&[0x61, 0x00, 0x62], true, 0), "a\u{FFFD}");
        assert_eq!(utf16_decode(&[0x61, 0x00, 0x62], true, 1), "a");
        assert_eq!(utf16_decode(&[0x00, 0xD8, 0x61, 0x00], true, 0), "\u{FFFD}a");
        assert_eq!(utf16_decode(&[0x00, 0xD8, 0x61, 0x00], true, 1), "a");
        assert_eq!(utf16_decode(&[0x00, 0xDC], true, 0), "\u{FFFD}");
        let mut b = vec![0xFF, 0xFE];
        b.extend(le("hi"));
        assert_eq!(utf16_auto(&b, 0), "hi");
        assert_eq!(utf16_auto(&[0xFE, 0xFF, 0x00, 0x68], 0), "h");
        assert_eq!(utf16_auto(&le("x"), 0), "x");
        let mut out = String::new();
        assert!(utf16_strict(&le("aç😀"), true, &mut out));
        assert_eq!(out, "aç😀");
        assert!(!utf16_strict(&[0x61], true, &mut out));
        assert!(!utf16_strict(&[0x00, 0xD8], true, &mut out));
        assert!(!utf16_strict(&[0x00, 0xDC], true, &mut out));
        assert!(!utf16_strict(&[0x00, 0xD8, 0x61, 0x00], true, &mut out));
        assert!(utf16_strict(&[], true, &mut out));
        assert_eq!(out, "");
    }

    #[test]
    fn cps_and_widen() {
        assert_eq!(codepoints("aç😀"), vec![0x61, 0xE7, 0x1F600]);
        assert_eq!(from_codepoints(&[0x61, 0xE7, 0x1F600]), "aç😀");
        assert_eq!(widen("a😀"), vec![0x61, 0xD83D, 0xDE00]);
        assert_eq!(narrow(&[0x61, 0xD83D, 0xDE00]), "a😀");
        assert_eq!(narrow(&[0xD83D]), "\u{FFFD}");
        let mut o = Vec::new();
        assert!(chars_to_bytes("aé€", &mut o));
        assert_eq!(o, vec![0x61, 0xE9, 0x80]);
        assert!(!chars_to_bytes("ğ", &mut o));
        assert!(chars_to_bytes("Ÿ", &mut o));
        assert_eq!(o, vec![0x9F]);
    }

    #[test]
    fn digests() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(crc32_of(b"123456789", 0), 0xCBF43926);
        let part = crc32_of(b"1234", 0);
        assert_eq!(crc32_of(b"56789", part), 0xCBF43926);
        assert_eq!(hex_lower(&[0x00, 0xAB, 0xFF]), "00abff");
        assert_eq!(rd16(&[1, 2]), 0x0201);
        assert_eq!(rd32(&[1, 2, 3, 4]), 0x04030201);
        assert_eq!(rb32(&[1, 2, 3, 4]), 0x01020304);
        assert_eq!(rb16(&[1, 2]), 0x0102);
        assert_eq!(rd64(&[1, 0, 0, 0, 0, 0, 0, 0]), 1);
        assert_eq!(rd32(&[1]), 0);
    }

    #[test]
    fn paths_basic() {
        assert_eq!(path_basename("C:\\a\\b.txt"), "b.txt");
        assert_eq!(path_basename("C:b.txt"), "b.txt");
        assert_eq!(path_basename("a/b/"), "");
        assert_eq!(path_basename("\\\\srv\\share\\f"), "f");
        assert_eq!(path_basename("\\\\srv\\share"), "");
        assert_eq!(path_dirname("C:\\a\\b.txt"), "C:\\a");
        assert_eq!(path_dirname("C:\\b.txt"), "C:\\");
        assert_eq!(path_dirname("b.txt"), "");
        assert_eq!(path_dirname("a/b/c"), "a/b");
        assert_eq!(path_dirname("\\\\srv\\share\\f"), "\\\\srv\\share\\");
        assert!(path_isabs("C:\\x"));
        assert!(path_isabs("C:/x"));
        assert!(!path_isabs("C:x"));
        assert!(!path_isabs("\\x"));
        assert!(path_isabs("\\\\srv\\share\\x"));
        assert!(!path_isabs("a\\b"));
    }

    #[test]
    fn paths_join() {
        assert_eq!(path_join("", "b"), "b");
        assert_eq!(path_join("a", ""), "a\\");
        assert_eq!(path_join("a\\", ""), "a\\");
        assert_eq!(path_join("a", "b"), "a\\b");
        assert_eq!(path_join("a\\", "b"), "a\\b");
        assert_eq!(path_join("a/", "b"), "a/b");
        assert_eq!(path_join("C:", "b"), "C:b");
        assert_eq!(path_join("a", "D:\\x"), "D:\\x");
        assert_eq!(path_join("C:\\a", "\\x"), "C:\\x");
        assert_eq!(path_join("a", "\\x"), "\\x");
        assert_eq!(path_join_all(&["a", "b", "c"]), "a\\b\\c");
        assert_eq!(path_join_all(&[]), "");
    }

    #[test]
    fn paths_splitext() {
        let t = |a: &str, b: &str| (a.to_string(), b.to_string());
        assert_eq!(path_splitext("a\\b.txt"), t("a\\b", ".txt"));
        assert_eq!(path_splitext("a.b\\c"), t("a.b\\c", ""));
        assert_eq!(path_splitext(".bashrc"), t(".bashrc", ""));
        assert_eq!(path_splitext("..x"), t("..x", ""));
        assert_eq!(path_splitext("a..x"), t("a.", ".x"));
        assert_eq!(path_splitext("a.tar.gz"), t("a.tar", ".gz"));
        assert_eq!(path_splitext("noext"), t("noext", ""));
        assert_eq!(path_ext_lower("C:\\X\\Foo.JAR"), ".jar");
        assert_eq!(path_ext_lower("C:\\X\\Foo"), "");
    }

    #[test]
    fn paths_normpath() {
        assert_eq!(path_normpath(""), ".");
        assert_eq!(path_normpath("a/b/../c"), "a\\c");
        assert_eq!(path_normpath("a/./b//c"), "a\\b\\c");
        assert_eq!(path_normpath("C:\\a\\..\\.."), "C:\\");
        assert_eq!(path_normpath("..\\a"), "..\\a");
        assert_eq!(path_normpath("a\\..\\.."), "..");
        assert_eq!(path_normpath("."), ".");
        assert_eq!(path_normpath("C:"), "C:");
        assert_eq!(path_normpath("\\\\srv\\share\\a\\..\\b"), "\\\\srv\\share\\b");
        assert_eq!(path_normpath("//?/C:/a/../b"), "\\\\?\\C:\\a\\..\\b");
        assert_eq!(path_normpath("\\a\\..\\.."), "\\");
    }

    #[test]
    fn paths_win32() {
        assert_eq!(path_normcase("C:/Foo/BAR"), "c:\\foo\\bar");
        assert_eq!(path_normcase("ÇAĞ"), "çağ");
        let a = path_abspath("C:\\x\\..\\y");
        assert_eq!(a, "C:\\y");
        assert!(path_isabs(&path_abspath("rel")));
        assert_eq!(path_relpath("C:\\A\\b\\c.txt", "c:\\a"), "b\\c.txt");
        assert_eq!(path_relpath("C:\\A\\b", "D:\\a"), "C:\\A\\b");
        assert_eq!(path_norm("C:/X/../Y"), "c:\\y");
    }

    #[test]
    fn time_utils() {
        assert_eq!(parse_utc_iso("2026-10-20T11:02:03Z"), Some(1792494123.0));
        let v = parse_utc_iso(" 2026-10-20T11:02:03.5Z ").unwrap();
        assert!((v - 1792494123.5).abs() < 1e-9);
        let v = parse_utc_iso("2000-01-01T00:00:00.1234567Z").unwrap();
        assert!((v - 946684800.1234567).abs() < 1e-6);
        assert_eq!(parse_utc_iso("2000-01-01"), None);
        assert_eq!(parse_utc_iso("garbage"), None);
        assert_eq!(parse_utc_iso("2000-01-01X00:00:00"), None);
        assert_eq!(parse_utc_iso("2000-01-01T00:00"), None);
        assert_eq!(parse_utc_iso("1960-01-01T00:00:00"), None);
        assert_eq!(filetime_to_epoch(0), None);
        assert_eq!(filetime_to_epoch(116_444_736_000_000_000), None);
        assert_eq!(filetime_to_epoch(116_444_736_000_000_000 + 10_000_000), Some(1.0));
        assert_eq!(filetime_to_epoch(u64::MAX), None);
    }

    #[test]
    fn time_local() {
        assert_eq!(fmt_dt(None), "-");
        let s = fmt_dt(Some(1792494123.0));
        assert_eq!(s.len(), 19);
        assert_eq!(&s[2..3], ".");
        assert_eq!(&s[5..6], ".");
        assert!(s.contains("2026"));
        assert_eq!(fmt_local(-100.0, "%Y"), "?");
        let t = local_mktime(2026, 10, 20, 11, 2, 3);
        assert_eq!(fmt_local(t, "%Y-%m-%d %H:%M:%S"), "2026-10-20 11:02:03");
        assert!(now_epoch() > 1.7e9);
    }

    #[test]
    fn fs_roundtrip() {
        let d = make_temp_dir("jsutiltest_");
        assert!(!d.is_empty());
        assert!(is_dir(&d));
        let f = path_join(&d, "a.bin");
        let data: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        assert!(write_file(&f, &data));
        assert!(is_file(&f));
        assert_eq!(file_size(&f), Some(200));
        assert!(file_mtime(&f).is_some());
        assert_eq!(read_file(&f, -1, 0).unwrap(), data);
        assert_eq!(read_file(&f, 10, 5).unwrap(), data[5..15].to_vec());
        assert_eq!(read_file(&f, -1, 190).unwrap(), data[190..].to_vec());
        assert_eq!(read_file(&f, -1, 500).unwrap(), Vec::<u8>::new());
        assert!(read_file(&path_join(&d, "yok"), -1, 0).is_none());
        let (mut h, mut t) = (Vec::new(), Vec::new());
        assert!(read_head_tail(&f, 20, 30, &mut h, &mut t));
        assert_eq!(h, data[..20].to_vec());
        assert_eq!(t, data[170..].to_vec());
        assert!(read_head_tail(&f, 150, 100, &mut h, &mut t));
        assert_eq!(h, data);
        assert_eq!(t, data);
        let sub = path_join(&d, "sub");
        let w = longw(&sub);
        unsafe {
            CreateDirectoryW(PCWSTR(w.as_ptr()), None).unwrap();
        }
        assert!(write_file(&path_join(&sub, "b.txt"), b"x"));
        let mut ents = Vec::new();
        assert!(list_dir(&d, &mut ents));
        assert_eq!(ents.len(), 2);
        assert!(ents.iter().any(|e| e.name == "sub" && e.is_dir && !e.reparse));
        assert!(ents.iter().any(|e| e.name == "a.bin" && e.is_file && e.size == 200));
        let mut names = listdir_names(&d);
        names.sort();
        assert_eq!(names, sl(&["a.bin", "sub"]));
        let mut seen = Vec::new();
        walk_files(&d, &mut |p| seen.push(p.to_string()), 100);
        assert_eq!(seen.len(), 2);
        let mut n = 0;
        walk_files(&d, &mut |_| n += 1, 1);
        assert_eq!(n, 1);
        assert!(!list_dir(&path_join(&d, "yok"), &mut ents));
        remove_tree(&d);
        assert!(!exists(&d));
        assert!(!exists(""));
    }

    #[test]
    fn env_and_misc() {
        assert!(!env("PATH").is_empty() || !env("Path").is_empty());
        assert_eq!(env("JS_BU_DEGISKEN_YOK_123"), "");
        assert!(!home_dir().is_empty());
        assert!(self_exe_path().to_lowercase().ends_with(".exe"));
        assert!(!temp_dir().is_empty());
        assert!(cpu_count() >= 1);
        let f = StopFlag::new();
        assert!(!f.is_set());
        f.set();
        assert!(f.is_set());
        f.clear();
        assert!(!f.is_set());
    }
}
