use crate::util::*;
use std::collections::BTreeMap;

fn recycle_info_parse(b: &[u8]) -> String {
    if b.len() < 24 {
        return String::new();
    }
    let ver = rd64(b);
    let raw: &[u8] = if ver == 2 {
        if b.len() < 28 {
            return String::new();
        }
        let n = rd32(&b[24..]) as usize;
        let end = 28usize.saturating_add(n.saturating_mul(2)).min(b.len());
        &b[28..end]
    } else {
        let end = (24 + 520).min(b.len());
        &b[24..end]
    };
    let mut s = utf16_decode(raw, true, 1);
    if let Some(z) = s.find('\0') {
        s.truncate(z);
    }
    s
}

fn recycle_original(path: &str) -> String {
    let outer = split(path, " !/ ", -1).into_iter().next().unwrap_or_default();
    let d = path_dirname(&outer);
    let f = path_basename(&outer);
    if !starts(&upper_ascii(&f), "$R") {
        return String::new();
    }
    let info = path_join(&d, &format!("$I{}", f.get(2..).unwrap_or("")));
    match read_file(&info, 4096, 0) {
        Some(b) => recycle_info_parse(&b),
        None => String::new(),
    }
}

fn recycle_info_original(info_path: &str) -> String {
    match read_file(info_path, 4096, 0) {
        Some(b) => recycle_info_parse(&b),
        None => String::new(),
    }
}

fn index_recycle_dir(dir: &str, out: &mut BTreeMap<String, String>, depth: i32) {
    let mut ents: Vec<DirEntry> = Vec::new();
    if !list_dir(dir, &mut ents) {
        return;
    }
    for e in &ents {
        let up = upper_ascii(&e.name);
        if e.is_dir && depth == 0 && !starts(&up, "$R") && !starts(&up, "$I") {
            index_recycle_dir(&path_join(dir, &e.name), out, 1); // kullanıcı SID klasörü
            continue;
        }
        if !starts(&up, "$I") || e.is_dir {
            continue;
        }
        let orig = recycle_info_original(&path_join(dir, &e.name));
        if orig.is_empty() {
            continue;
        }
        let rpath = path_join(dir, &format!("$R{}", e.name.get(2..).unwrap_or("")));
        if is_file(&rpath) || is_dir(&rpath) {
            out.insert(py_lower(&replace_all(&orig, "/", "\\")), rpath);
        }
    }
}

pub fn recycle_bin_index() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut roots: StrList = Vec::new();
    for r in split(&env("JS_RECYCLE_ROOTS"), ";", -1) {
        let s = strip(&r, WS_CHARS);
        if !s.is_empty() {
            roots.push(s);
        }
    }
    #[cfg(windows)]
    {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
        const DRIVE_FIXED: u32 = 3;
        // SAFETY: parametresiz Win32 çağrısı.
        let mask = unsafe { GetLogicalDrives() };
        for i in 0..26u32 {
            if mask & (1u32 << i) == 0 {
                continue;
            }
            let root: [u16; 4] = [(b'A' as u16) + i as u16, b':' as u16, b'\\' as u16, 0];
            // SAFETY: root NUL ile biten geçerli bir UTF-16 dizisidir.
            let t = unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) };
            if t != DRIVE_FIXED {
                continue;
            }
            roots.push(format!("{}:\\$Recycle.Bin", (b'A' + i as u8) as char));
        }
    }
    for r in &roots {
        index_recycle_dir(r, &mut out, 0);
    }
    out
}

pub fn recycle_lookup(idx: &BTreeMap<String, String>, original_path: &str) -> String {
    if idx.is_empty() || original_path.is_empty() {
        return String::new();
    }
    let key = py_lower(&replace_all(original_path, "/", "\\"));
    if let Some(v) = idx.get(&key) {
        return if is_file(v) { v.clone() } else { String::new() };
    }
    let kb = key.as_bytes();
    let mut best: Option<&String> = None;
    let mut rest = String::new();
    for k in idx.keys() {
        let kl = k.len();
        let best_len = best.map_or(0, |b| b.len());
        if kb.len() > kl + 1 && kb.starts_with(k.as_bytes()) && kb[kl] == b'\\' && kl > best_len {
            best = Some(k);
            rest = String::from_utf8_lossy(original_path.as_bytes().get(kl + 1..).unwrap_or(&[])).into_owned();
        }
    }
    let Some(best) = best else {
        return String::new();
    };
    let Some(base) = idx.get(best) else {
        return String::new();
    };
    let cand = path_join(base, &rest);
    if is_file(&cand) {
        cand
    } else {
        String::new()
    }
}

pub fn location_note(path: &str) -> String {
    const LOCS: &[(&str, &str, &str)] = &[
        (
            "/google/chrome/user data/",
            "/cache",
            "Google Chrome tarayıcı ÖNBELLEĞİ: bu dosya tarayıcıdan indirilmiş / açılmış bir dosyanın kopyasıdır \
             (Chrome indirdiği dosyaların kopyasını burada tutar)",
        ),
        (
            "/microsoft/edge/user data/",
            "/cache",
            "Microsoft Edge tarayıcı ÖNBELLEĞİ (indirilen dosyanın kopyası)",
        ),
        (
            "/bravesoftware/",
            "/cache",
            "Brave tarayıcı ÖNBELLEĞİ (indirilen dosyanın kopyası)",
        ),
        (
            "/opera software/",
            "/cache",
            "Opera tarayıcı ÖNBELLEĞİ (indirilen dosyanın kopyası)",
        ),
        (
            "/mozilla/firefox/profiles/",
            "/cache2",
            "Firefox tarayıcı ÖNBELLEĞİ (indirilen dosyanın kopyası)",
        ),
        (
            "/discord/",
            "/cache",
            "Discord ÖNBELLEĞİ: Discord'dan indirilen / açılan bir dosyanın kopyası",
        ),
        (
            "/$recycle.bin/",
            "",
            "GERİ DÖNÜŞÜM KUTUSU: silinmiş ama kalıcı olarak yok edilmemiş dosya",
        ),
        ("/appdata/local/temp/", "", "Geçici dosyalar klasörü (Temp)"),
        ("/windows/temp/", "", "Windows geçici dosyalar klasörü"),
        ("/downloads/", "", "İndirilenler klasörü"),
        ("/.minecraft/mods/", "", "Minecraft mod klasörü"),
        ("/mods/", "", "Bir Minecraft kurulumunun mod klasörü"),
    ];
    let first = split(path, " !/ ", -1).into_iter().next().unwrap_or_default();
    let lp = py_lower(&replace_all(&first, "\\", "/"));
    for &(a, b, text) in LOCS {
        let Some(k) = lp.find(a) else {
            continue;
        };
        if !b.is_empty() && !lp.get(k..).is_some_and(|t| t.contains(b)) {
            continue;
        }
        let mut extra = String::new();
        if a == "/$recycle.bin/" {
            let orig = recycle_original(path);
            if !orig.is_empty() {
                extra = format!(" - silinmeden önceki yolu: {}", orig);
            }
        }
        return format!("Konum: {}{}.", text, extra);
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_parse_v1() {
        let mut b = vec![0u8; 24];
        b[0] = 1;
        for c in "C:\\a\\b.jar".encode_utf16() {
            b.extend_from_slice(&c.to_le_bytes());
        }
        b.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(recycle_info_parse(&b), "C:\\a\\b.jar");
        assert_eq!(recycle_info_parse(&b[..10]), "");
    }

    #[test]
    fn info_parse_v2_bozuk() {
        let mut b = vec![0u8; 28];
        b[0] = 2;
        b[24] = 0xFF; // uzunluk gerçek veriden büyük: panic olmamalı
        let _ = recycle_info_parse(&b);
    }
}
