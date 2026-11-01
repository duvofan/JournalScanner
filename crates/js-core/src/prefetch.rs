use crate::disk::{DiskScanner, ResultP};
use crate::events::EventResult;
use crate::rx::*;
use crate::util::*;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use windows::core::{s, w, PCWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::Storage::FileSystem::{GetVolumeInformationW, QueryDosDeviceW};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Registry::*;

#[derive(Debug, Clone, Default)]
pub struct PfVolume {
    pub device: String,
    pub serial: String,
    pub created: Option<f64>,
    pub dirs: StrList,
}

#[derive(Debug, Clone, Default)]
pub struct Prefetch {
    pub name: String,
    pub path: String,
    pub exe: String,
    pub hash: String,
    pub version: u32,
    pub file_size: u32,
    pub run_count: i32,
    pub run_times: Vec<f64>,
    pub filenames: StrList,
    pub volumes: Vec<PfVolume>,
}

#[derive(Debug, Clone, Default)]
pub struct PfFinding {
    pub category: String,
    pub label: String,
    pub explain: String,
    pub pf: String,
    pub pf_path: String,
    pub exe: String,
    pub run_count: i32,
    pub run_times: StrList,
    pub files: StrList,
    pub scan_result: Option<ResultP>,
    pub version: u32,
}

#[derive(Debug, Clone, Default)]
pub struct PrefetchResult {
    pub available: bool,
    pub error: String,
    pub enabled: Option<i32>,
    pub pf_count: i32,
    pub parsed: i32,
    pub failed: i32,
    pub java_pf: i32,
    pub checked_files: i32,
    pub self_skipped: i32,
    pub findings: Vec<PfFinding>,
}

const MAX_DECOMPRESSED: u32 = 64 * 1024 * 1024;

struct Layout {
    fi_size: u32,
    lr_off: u32,
    lr_cnt: u32,
    rc_off: u32,
    rc_move: bool,
    vol_size: u32,
}

fn layout_of(v: u32) -> Option<Layout> {
    let l = |fi_size, lr_off, lr_cnt, rc_off, rc_move, vol_size| Layout {
        fi_size,
        lr_off,
        lr_cnt,
        rc_off,
        rc_move,
        vol_size,
    };
    match v {
        17 => Some(l(68, 36, 1, 60, false, 40)),
        23 => Some(l(156, 44, 1, 68, false, 104)),
        26 => Some(l(224, 44, 8, 124, false, 104)),
        30 => Some(l(224, 44, 8, 124, true, 96)),
        31 => Some(l(224, 44, 8, 124, true, 96)),
        _ => None,
    }
}

fn decompress_ntdll(data: &[u8], size: u32, out: &mut Bytes) -> bool {
    type GetWs = unsafe extern "system" fn(u16, *mut u32, *mut u32) -> i32;
    type DecEx = unsafe extern "system" fn(u16, *mut u8, u32, *mut u8, u32, *mut u32, *mut c_void) -> i32;
    if data.is_empty() || size == 0 {
        return false;
    }
    // SAFETY: ntdll her işlemde yüklüdür; dönen modül tanıtıcısı yalnızca sorgulanır.
    let Ok(nt) = (unsafe { GetModuleHandleW(w!("ntdll.dll")) }) else {
        return false;
    };
    // SAFETY: nt geçerli bir modül tanıtıcısı; adlar NUL sonlu.
    let (gw, de) = unsafe {
        (
            GetProcAddress(nt, s!("RtlGetCompressionWorkSpaceSize")),
            GetProcAddress(nt, s!("RtlDecompressBufferEx")),
        )
    };
    let (Some(gw), Some(de)) = (gw, de) else {
        return false;
    };
    // SAFETY: bu iki ntdll işlevinin imzaları belgelidir ve yukarıdaki türlerle birebir uyuşur.
    let (gw, de) = unsafe {
        (
            std::mem::transmute::<unsafe extern "system" fn() -> isize, GetWs>(gw),
            std::mem::transmute::<unsafe extern "system" fn() -> isize, DecEx>(de),
        )
    };
    let mut wss = 0u32;
    let mut frag = 0u32;
    // SAFETY: wss / frag geçerli çıktı işaretçileri.
    if unsafe { gw(4, &mut wss, &mut frag) } != 0 {
        return false;
    }
    let mut ws = vec![0u8; wss as usize + 16];
    out.clear();
    out.resize(size as usize, 0);
    let mut fin = 0u32;
    let mut src = data.to_vec();
    // SAFETY: tamponlar bildirilen uzunluklarda; ws çalışma alanı istenen boyuttan büyük.
    let st = unsafe {
        de(
            4,
            out.as_mut_ptr(),
            size,
            src.as_mut_ptr(),
            src.len() as u32,
            &mut fin,
            ws.as_mut_ptr() as *mut c_void,
        )
    };
    if st != 0 {
        return false;
    }
    out.truncate(fin as usize);
    true
}

fn decompress_xpress(src: &[u8], out_size: u32, out: &mut Bytes, err: &mut String) -> bool {
    let n = src.len();
    let mut pos = 0usize;
    let out_size = out_size as usize;
    out.clear();
    out.reserve(out_size);
    let mut table = vec![-1i32; 1 << 15];
    let rd16s = |p: usize| -> u32 {
        if p + 2 <= n {
            rd16(&src[p..]) as u32
        } else {
            0
        }
    };
    while out.len() < out_size {
        if pos + 256 > n {
            *err = "beklenmeyen veri sonu (tablo)".to_string();
            return false;
        }
        let mut lengths = [0i32; 512];
        for i in 0..256 {
            lengths[2 * i] = (src[pos + i] & 0x0F) as i32;
            lengths[2 * i + 1] = (src[pos + i] >> 4) as i32;
        }
        pos += 256;
        table.iter_mut().for_each(|t| *t = -1);
        let mut code: u32 = 0;
        for l in 1..16i32 {
            for sym in 0..512i32 {
                if lengths[sym as usize] != l {
                    continue;
                }
                let start = code << (15 - l);
                let end = start + (1u32 << (15 - l));
                if end > (1u32 << 15) {
                    *err = "bozuk Huffman tablosu".to_string();
                    return false;
                }
                for i in start..end {
                    table[i as usize] = (sym << 4) | l;
                }
                code += 1;
            }
            code <<= 1;
        }
        if pos + 4 > n {
            *err = "beklenmeyen veri sonu".to_string();
            return false;
        }
        let mut next_bits: u32 = ((rd16(&src[pos..]) as u32) << 16) | rd16(&src[pos + 2..]) as u32;
        pos += 4;
        let mut extra: i32 = 16;
        let block_end = (out.len() + 65536).min(out_size);
        while out.len() < block_end {
            let e = table[((next_bits >> 17) & 0x7FFF) as usize];
            if e < 0 {
                *err = "geçersiz Huffman kodu".to_string();
                return false;
            }
            let mut sym = e >> 4;
            let bl = e & 15;
            next_bits <<= bl;
            extra -= bl;
            if extra < 0 {
                next_bits |= rd16s(pos) << (-extra);
                pos += 2;
                extra += 16;
            }
            if sym < 256 {
                out.push(sym as u8);
                continue;
            }
            sym -= 256;
            let mut length: u32 = (sym & 15) as u32;
            let dbits = sym >> 4;
            if length == 15 {
                if pos >= n {
                    *err = "veri sonu".to_string();
                    return false;
                }
                length = src[pos] as u32;
                pos += 1;
                if length == 255 {
                    if pos + 2 > n {
                        *err = "veri sonu".to_string();
                        return false;
                    }
                    length = rd16(&src[pos..]) as u32;
                    pos += 2;
                    if length == 0 {
                        if pos + 4 > n {
                            *err = "veri sonu".to_string();
                            return false;
                        }
                        length = rd32(&src[pos..]);
                        pos += 4;
                    }
                    if length < 15 {
                        *err = "geçersiz uzunluk".to_string();
                        return false;
                    }
                    length -= 15;
                }
                length = length.wrapping_add(15);
            }
            length = length.wrapping_add(3);
            let dist: u32;
            if dbits != 0 {
                dist = (((next_bits as u64) >> (32 - dbits)) as u32).wrapping_add(1u32 << dbits);
                next_bits <<= dbits;
                extra -= dbits;
                if extra < 0 {
                    next_bits |= rd16s(pos) << (-extra);
                    pos += 2;
                    extra += 16;
                }
            } else {
                dist = 1;
            }
            if dist as usize > out.len() {
                *err = "geçersiz uzaklık".to_string();
                return false;
            }
            let start = out.len() - dist as usize;
            let room = out_size.saturating_sub(out.len());
            let cnt = (length as usize).min(room);
            for i in 0..cnt {
                let b = out[start + i];
                out.push(b);
            }
        }
    }
    out.truncate(out_size);
    true
}

pub fn decompress_mam(raw: &[u8], out: &mut Bytes, err: &mut String) -> bool {
    if raw.len() < 8 {
        *err = "kısa".to_string();
        return false;
    }
    let fmt = (raw[3] & 0x0F) as u32;
    let has_crc = (raw[3] & 0x80) != 0;
    if fmt != 4 {
        *err = format!("desteklenmeyen MAM biçimi {}", fmt);
        return false;
    }
    let size = rd32(&raw[4..]);
    if size > MAX_DECOMPRESSED {
        *err = "çok büyük".to_string();
        return false;
    }
    let data = raw.get(if has_crc { 12 } else { 8 }..).unwrap_or(&[]);
    if decompress_ntdll(data, size, out) {
        return true;
    }
    decompress_xpress(data, size, out, err)
}

fn pf_filetime(v: u64) -> Option<f64> {
    if v == 0 {
        return None;
    }
    Some(v as f64 / 1e7 - 11644473600.0)
}

fn sub(raw: &[u8], pos: usize, count: usize) -> &[u8] {
    match raw.get(pos..) {
        Some(r) => &r[..count.min(r.len())],
        None => &[],
    }
}
fn r32(raw: &[u8], pos: usize) -> u32 {
    rd32(raw.get(pos..).unwrap_or(&[]))
}
fn r64(raw: &[u8], pos: usize) -> u64 {
    rd64(raw.get(pos..).unwrap_or(&[]))
}
fn r16(raw: &[u8], pos: usize) -> u16 {
    rd16(raw.get(pos..).unwrap_or(&[]))
}

pub fn parse_prefetch_bytes(raw_in: &[u8], name: &str, pf: &mut Prefetch, err: &mut String) -> bool {
    let mut dec: Bytes = Vec::new();
    let mut raw: &[u8] = raw_in;
    if raw.len() >= 3 && &raw[..3] == b"MAM" {
        if !decompress_mam(raw, &mut dec, err) {
            return false;
        }
        raw = &dec;
    }
    if raw.len() < 84 || &raw[4..8] != b"SCCA" {
        *err = "SCCA imzası yok".to_string();
        return false;
    }
    let version = r32(raw, 0);
    let Some(l) = layout_of(version) else {
        *err = format!("bilinmeyen sürüm {}", version);
        return false;
    };
    pf.name = name.to_string();
    pf.version = version;
    pf.file_size = r32(raw, 12);
    let mut exe = utf16_decode(sub(raw, 16, 60), true, 1);
    if let Some(z) = exe.find('\0') {
        exe.truncate(z);
    }
    pf.exe = exe;
    pf.hash = format!("{:X}", r32(raw, 76));
    if raw.len() < 84 + l.fi_size as usize {
        *err = "kısa dosya bilgisi".to_string();
        return false;
    }
    let info = 84usize;
    let fn_off = r32(raw, info + 16) as usize;
    let fn_size = r32(raw, info + 20) as usize;
    let vol_off = r32(raw, info + 24) as usize;
    let vol_cnt = r32(raw, info + 28);
    let vol_sz = r32(raw, info + 32) as usize;
    for i in 0..l.lr_cnt {
        if l.lr_off + i * 8 + 8 > l.fi_size {
            break;
        }
        let v = r64(raw, info + (l.lr_off + i * 8) as usize);
        if v == 0 && l.lr_cnt > 1 {
            continue;
        }
        if let Some(t) = pf_filetime(v) {
            pf.run_times.push(t);
        }
    }
    let rc = info + l.rc_off as usize;
    pf.run_count = r32(raw, rc) as i32;
    if l.rc_move && r32(raw, rc - 4) as i32 != 0 {
        pf.run_count = r32(raw, rc - 8) as i32;
    }
    if fn_off > 0 && fn_off < raw.len() && fn_size != 0 {
        let s = utf16_decode(sub(raw, fn_off, fn_size), true, 1);
        for x in s.split('\0') {
            if !x.is_empty() {
                pf.filenames.push(x.to_string());
            }
        }
    }
    let vols: &[u8] = if vol_off < raw.len() {
        sub(raw, vol_off, vol_sz)
    } else {
        &[]
    };
    for j in 0..vol_cnt as usize {
        let a = j * l.vol_size as usize;
        if a + 36 > vols.len() {
            break;
        }
        let e = &vols[a..];
        let elen = (l.vol_size as usize).min(vols.len() - a);
        if elen < 36 {
            break;
        }
        let mut v = PfVolume::default();
        let dev_off = rd32(e) as usize;
        let dev_chars = rd32(&e[4..]) as usize;
        v.created = pf_filetime(rd64(&e[8..]));
        v.serial = format!("{:X}", rd32(&e[16..]));
        if dev_off < vols.len() {
            v.device = utf16_decode(sub(vols, dev_off, dev_chars.saturating_mul(2)), true, 1);
        }
        let d_off = rd32(&e[28..]) as usize;
        let d_cnt = rd32(&e[32..]);
        let mut p = vol_off + d_off;
        let mut k = 0u32;
        while k < d_cnt && k < 100000 {
            if p + 2 > raw.len() {
                break;
            }
            let nch = r16(raw, p) as usize;
            p += 2;
            let mut d = if p < raw.len() {
                utf16_decode(sub(raw, p, nch * 2 + 2), true, 1)
            } else {
                String::new()
            };
            while d.ends_with('\0') {
                d.pop();
            }
            v.dirs.push(d);
            p += nch * 2 + 2;
            k += 1;
        }
        pf.volumes.push(v);
    }
    true
}

pub fn prefetch_dir() -> String {
    let mut sr = env("SystemRoot");
    if sr.is_empty() {
        sr = "C:\\Windows".to_string();
    }
    path_join(&sr, "Prefetch")
}

fn prefetch_enabled() -> Option<i32> {
    let mut k = HKEY::default();
    // SAFETY: yol NUL sonlu sabit; k geçerli çıktı işaretçisi.
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            w!("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters"),
            None,
            REG_SAM_FLAGS(KEY_READ.0 | KEY_WOW64_64KEY.0),
            &mut k,
        )
    } != ERROR_SUCCESS
    {
        return None;
    }
    let mut v = 0u32;
    let mut sz = std::mem::size_of::<u32>() as u32;
    let mut t = REG_VALUE_TYPE(0);
    // SAFETY: v, sz bayt boyutunda geçerli tamponlardır.
    let r = unsafe {
        RegQueryValueExW(
            k,
            w!("EnablePrefetcher"),
            None,
            Some(&mut t),
            Some(&mut v as *mut u32 as *mut u8),
            Some(&mut sz),
        )
    };
    // SAFETY: k açık bir anahtardır.
    let _ = unsafe { RegCloseKey(k) };
    if r != ERROR_SUCCESS {
        return None;
    }
    Some(v as i32)
}

struct VolMap {
    serials: BTreeMap<String, String>,
    devices: BTreeMap<String, String>,
}

impl VolMap {
    fn new() -> VolMap {
        let mut serials = BTreeMap::new();
        let mut devices = BTreeMap::new();
        for c in 'A'..='Z' {
            let root = format!("{}:\\", c);
            if !exists(&root) {
                continue;
            }
            let mut wroot = widen(&root);
            wroot.push(0);
            let mut ser = 0u32;
            // SAFETY: wroot NUL sonlu; yalnızca seri numarası isteniyor.
            if unsafe { GetVolumeInformationW(PCWSTR(wroot.as_ptr()), None, Some(&mut ser), None, None, None) }.is_ok()
            {
                serials.insert(format!("{:X}", ser), root.clone());
            }
            let mut wdev = widen(&format!("{}:", c));
            wdev.push(0);
            let mut buf = [0u16; 1024];
            // SAFETY: wdev NUL sonlu; buf 1024 öğelik yazılabilir tampon.
            let n = unsafe { QueryDosDeviceW(PCWSTR(wdev.as_ptr()), Some(&mut buf)) };
            if n != 0 {
                let len = buf.iter().position(|&x| x == 0).unwrap_or(buf.len());
                devices.insert(py_upper(&narrow(&buf[..len])), root);
            }
        }
        VolMap { serials, devices }
    }
}

fn vm() -> &'static VolMap {
    static V: OnceLock<VolMap> = OnceLock::new();
    V.get_or_init(VolMap::new)
}

pub fn resolve_nt_path(p: &str) -> String {
    static RVOL: OnceLock<Rx> = OnceLock::new();
    static RDEV: OnceLock<Rx> = OnceLock::new();
    let rvol = RVOL.get_or_init(|| Rx::new(r"^\\VOLUME\{[0-9a-fA-F]+-([0-9a-fA-F]+)\}", Rx::I));
    let rdev = RDEV.get_or_init(|| Rx::new(r"^(\\DEVICE\\HARDDISKVOLUME\d+)", Rx::I));
    let vm = vm();
    let rest_of = |end: usize| -> String { lstrip(p.get(end..).unwrap_or(""), "\\") };
    if let Some(m) = rvol.match_(p.as_bytes(), 0) {
        let g = upper_ascii(&m.group(1));
        let mut l = lstrip(&g, "0");
        if l.is_empty() {
            l = "0".to_string();
        }
        let it = vm.serials.get(&l).or_else(|| vm.serials.get(&g));
        if let Some(root) = it {
            return path_join(root, &rest_of(m.end(0)));
        }
        return String::new();
    }
    if let Some(m) = rdev.match_(p.as_bytes(), 0) {
        if let Some(root) = vm.devices.get(&upper_ascii(&m.group(1))) {
            return path_join(root, &rest_of(m.end(0)));
        }
    }
    String::new()
}

pub fn is_java_prefetch(pf: &Prefetch) -> bool {
    let exe = py_upper(&pf.exe);
    if exe == "JAVAW.EXE" || exe == "JAVA.EXE" {
        return true;
    }
    pf.filenames.iter().any(|f| ends(&py_upper(f), "\\JVM.DLL"))
}

pub fn parse_prefetch_dir(dir: &str) -> Vec<Prefetch> {
    let mut out: Vec<Prefetch> = Vec::new();
    let mut ents: Vec<DirEntry> = Vec::new();
    if !list_dir(dir, &mut ents) {
        return out;
    }
    for e in &ents {
        if !ends(&py_lower(&e.name), ".pf") {
            continue;
        }
        let Some(raw) = read_file(&e.path, -1, 0) else {
            continue;
        };
        let mut pf = Prefetch::default();
        let mut err = String::new();
        if parse_prefetch_bytes(&raw, &e.name, &mut pf, &mut err) {
            pf.path = e.path.clone();
            out.push(pf);
        }
    }
    out
}

fn ext_lower_nt(up: &str) -> String {
    let sep = up.rfind(['\\', '/']);
    let Some(dot) = up.rfind('.') else {
        return String::new();
    };
    if matches!(sep, Some(s) if dot < s) {
        return String::new();
    }
    let ub = up.as_bytes();
    let mut fi = match sep {
        None => 0,
        Some(s) => s + 1,
    };
    while fi < dot {
        if ub[fi] != b'.' {
            return py_lower(&up[dot..]);
        }
        fi += 1;
    }
    String::new()
}

fn mk(cat: &str, label: &str, explain: &str, pf: &Prefetch, files: &[String], sr: Option<ResultP>) -> PfFinding {
    let mut rt = pf.run_times.clone();
    rt.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    PfFinding {
        category: cat.to_string(),
        label: label.to_string(),
        explain: explain.to_string(),
        pf: pf.name.clone(),
        pf_path: pf.path.clone(),
        exe: pf.exe.clone(),
        run_count: pf.run_count,
        run_times: rt.iter().map(|t| fmt_local(*t, "%Y-%m-%d %H:%M:%S")).collect(),
        files: files.to_vec(),
        scan_result: sr,
        version: pf.version,
    }
}

pub fn scan_prefetch(ev: Option<&EventResult>, stop: Option<&StopFlag>) -> PrefetchResult {
    let mut out = PrefetchResult {
        enabled: prefetch_enabled(),
        ..Default::default()
    };
    let d = prefetch_dir();
    if !is_dir(&d) {
        out.error = format!("Prefetch klasörü bulunamadı ({}).", d);
        return out;
    }
    let mut ents: Vec<DirEntry> = Vec::new();
    if !list_dir(&d, &mut ents) {
        out.error = "Prefetch klasörüne erişim reddedildi - programı yönetici olarak çalıştırın.".to_string();
        return out;
    }
    let mut files: StrList = Vec::new();
    for e in &ents {
        if ends(&py_lower(&e.name), ".pf") {
            files.push(e.path.clone());
        }
    }
    files.sort();
    out.pf_count = files.len() as i32;
    if files.is_empty() {
        out.error = format!(
            "Prefetch klasörü boş.{}",
            if out.enabled == Some(0) {
                " (Prefetch Windows'ta KAPALI)"
            } else {
                ""
            }
        );
        return out;
    }
    out.available = true;
    let mut pfs: Vec<Prefetch> = Vec::new();
    for f in &files {
        let raw = read_file(f, -1, 0);
        let mut pf = Prefetch::default();
        let mut err = String::new();
        match raw {
            Some(raw) if parse_prefetch_bytes(&raw, &path_basename(f), &mut pf, &mut err) => {
                pf.path = f.clone();
                pfs.push(pf);
                out.parsed += 1;
            }
            _ => out.failed += 1,
        }
    }
    const SKIP_EXT: [&str; 15] = [
        ".dll",
        ".exe",
        ".sys",
        ".mui",
        ".nls",
        ".ttf",
        ".ttc",
        ".fon",
        ".drv",
        ".cpl",
        ".ocx",
        ".winmd",
        ".pdb",
        ".manifest",
        ".etl",
    ];
    let self_pf = py_upper(&path_basename(&self_exe_path()));
    let mut cand: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (idx, pf) in pfs.iter().enumerate() {
        if !self_pf.is_empty() && py_upper(&pf.exe) == self_pf {
            out.self_skipped += 1;
            continue;
        }
        let java = is_java_prefetch(pf);
        if java {
            out.java_pf += 1;
        }
        for rawp in &pf.filenames {
            let up = py_upper(rawp);
            let ext = ext_lower_nt(&up);
            if has(&up, "\\WINDOWS\\") {
                continue;
            }
            if SKIP_EXT.contains(&ext.as_str()) {
                continue;
            }
            if !java && ext != ".jar" {
                continue;
            }
            let local = resolve_nt_path(rawp);
            if !local.is_empty() && is_file(&local) {
                cand.entry(local).or_default().push(idx);
            }
        }
    }
    if !cand.is_empty() {
        let paths: StrList = cand.keys().cloned().collect();
        let local_stop = Arc::new(StopFlag::new());
        let done = AtomicBool::new(false);
        let r = std::thread::scope(|sc| {
            if let Some(st) = stop {
                let ls = local_stop.clone();
                let done = &done;
                sc.spawn(move || {
                    while !done.load(Ordering::Relaxed) {
                        if st.is_set() {
                            ls.set();
                        }
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                });
            }
            let mut ds = DiskScanner::new(Vec::new(), None, Some(local_stop.clone()), 4, Vec::new());
            let r = ds.scan_paths(&paths, "");
            done.store(true, Ordering::Relaxed);
            r
        });
        out.checked_files = cand.len() as i32;
        for res in &r.results {
            let first = res.file.split(" !/ ").next().unwrap_or("");
            let base = first.split("  (jar'a").next().unwrap_or("");
            let mut owners: Vec<usize> = Vec::new();
            if let Some(v) = cand.get(base) {
                owners = v.clone();
            } else {
                for (k, v) in &cand {
                    if starts(base, &path_dirname(k)) {
                        for p in v {
                            if owners.len() >= 3 {
                                break;
                            }
                            owners.push(*p);
                        }
                    }
                }
            }
            let cat = if res.rank == 3 {
                "KESIN_HILE"
            } else if res.rank == 2 {
                "YASAKLI_ISLEV"
            } else {
                "SUPHELI"
            };
            let mut uq: Vec<usize> = Vec::new();
            for p in &owners {
                if !uq.contains(p) {
                    uq.push(*p);
                }
            }
            for &i in uq.iter().take(3) {
                let pf = &pfs[i];
                out.findings.push(mk(
                    cat,
                    &format!("Prefetch kaydıyla doğrulanmış: {}", goster_buyuk(&res.verdict)),
                    &format!(
                        "{} bu dosyayı açmış/yüklemiş ve dosyanın KODU analiz edildiğinde {} bulundu.",
                        pf.exe, res.verdict
                    ),
                    pf,
                    std::slice::from_ref(&res.file),
                    Some(res.clone()),
                ));
            }
        }
    }
    let mut fs = 0;
    if let Some(ev) = ev {
        for e in &ev.findings {
            if e.process == "fsutil.exe" {
                fs += 1;
            }
        }
    }
    if fs != 0 {
        for pf in &pfs {
            if py_upper(&pf.exe) == "FSUTIL.EXE" {
                out.findings.push(mk(
                    "SUPHELI",
                    "fsutil.exe çalışma kaydı (Olay Görüntüleyicisi 500/501 ile eşleşiyor)",
                    &format!(
                        "Olay Görüntüleyicisi'nde fsutil.exe ile {} adet 500/501 NTFS olayı var; \
                         prefetch fsutil'in çalıştırıldığını ve zamanlarını doğruluyor (USN \
                         günlüğü ile iz silme ile ilişkili olabilir).",
                        fs
                    ),
                    pf,
                    &[],
                    None,
                ));
            }
        }
    }
    let ord = |c: &str| -> i32 {
        if c == "KESIN_HILE" {
            0
        } else if c == "YASAKLI_ISLEV" {
            1
        } else {
            2
        }
    };
    out.findings
        .sort_by(|a, b| ord(&a.category).cmp(&ord(&b.category)).then_with(|| a.exe.cmp(&b.exe)));
    out
}

pub fn prefetch_rank(pr: &PrefetchResult) -> i32 {
    let mut r = 0;
    for f in &pr.findings {
        let v = if f.category == "KESIN_HILE" {
            3
        } else if f.category == "YASAKLI_ISLEV" {
            2
        } else {
            1
        };
        r = r.max(v);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|c| c.to_le_bytes())
            .collect()
    }

    fn build_v30() -> Vec<u8> {
        let mut b = vec![0u8; 84 + 224];
        put32(&mut b, 0, 30);
        b[4..8].copy_from_slice(b"SCCA");
        put32(&mut b, 12, 12345);
        let exe = utf16z("JAVAW.EXE");
        b[16..16 + exe.len()].copy_from_slice(&exe);
        put32(&mut b, 76, 0xABCDEF);
        let info = 84;
        let fnames = utf16z("\\VOLUME{01d0-1a2b3c4d}\\GAME\\A.JAR");
        let fn_off = b.len();
        b.extend_from_slice(&fnames);
        let vol_off = b.len();
        let mut vol = vec![0u8; 96];
        let dev = utf16z("\\DEVICE\\HARDDISKVOLUME3");
        let dev_off = 96u32;
        let mut tail = dev.clone();
        let dirs_off = 96 + tail.len() as u32;
        let dname: Vec<u8> = "\\VOLUME{x}\\GAME"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        tail.extend_from_slice(&((dname.len() / 2) as u16).to_le_bytes());
        tail.extend_from_slice(&dname);
        tail.extend_from_slice(&[0, 0]);
        put32(&mut vol, 0, dev_off);
        put32(&mut vol, 4, (dev.len() / 2) as u32);
        vol[8..16].copy_from_slice(&132_000_000_000_000_000u64.to_le_bytes());
        put32(&mut vol, 16, 0x1A2B3C4D);
        put32(&mut vol, 28, dirs_off);
        put32(&mut vol, 32, 1);
        let mut vols = vol;
        vols.extend_from_slice(&tail);
        let vol_sz = vols.len() as u32;
        b.extend_from_slice(&vols);
        put32(&mut b, info + 16, fn_off as u32);
        put32(&mut b, info + 20, fnames.len() as u32);
        put32(&mut b, info + 24, vol_off as u32);
        put32(&mut b, info + 28, 1);
        put32(&mut b, info + 32, vol_sz);
        b[info + 44..info + 52].copy_from_slice(&132_000_000_000_000_000u64.to_le_bytes());
        b[info + 52..info + 60].copy_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        put32(&mut b, info + 124, 7);
        put32(&mut b, info + 120, 1);
        put32(&mut b, info + 116, 9);
        b
    }

    #[test]
    fn parse_v30() {
        let raw = build_v30();
        let mut pf = Prefetch::default();
        let mut err = String::new();
        assert!(parse_prefetch_bytes(&raw, "JAVAW.EXE-1.pf", &mut pf, &mut err), "{err}");
        assert_eq!(pf.exe, "JAVAW.EXE");
        assert_eq!(pf.hash, "ABCDEF");
        assert_eq!(pf.version, 30);
        assert_eq!(pf.file_size, 12345);
        assert_eq!(pf.run_count, 9);
        assert_eq!(pf.run_times.len(), 2);
        assert_eq!(pf.filenames, vec!["\\VOLUME{01d0-1a2b3c4d}\\GAME\\A.JAR".to_string()]);
        assert_eq!(pf.volumes.len(), 1);
        assert_eq!(pf.volumes[0].serial, "1A2B3C4D");
        assert_eq!(pf.volumes[0].device, "\\DEVICE\\HARDDISKVOLUME3\0");
        assert_eq!(pf.volumes[0].dirs, vec!["\\VOLUME{x}\\GAME".to_string()]);
        assert!(pf.volumes[0].created.is_some());
        assert!(is_java_prefetch(&pf));
    }

    #[test]
    fn parse_bad_inputs() {
        let mut pf = Prefetch::default();
        let mut err = String::new();
        assert!(!parse_prefetch_bytes(&[], "x", &mut pf, &mut err));
        assert!(!parse_prefetch_bytes(&[0u8; 100], "x", &mut pf, &mut err));
        let mut raw = build_v30();
        raw.truncate(200);
        assert!(!parse_prefetch_bytes(&raw, "x", &mut pf, &mut err));
        assert_eq!(err, "kısa dosya bilgisi");
        let mut raw = build_v30();
        put32(&mut raw, 84 + 24, 0xFFFF_FFF0);
        put32(&mut raw, 84 + 16, 0xFFFF_FFF0);
        let mut pf2 = Prefetch::default();
        let _ = parse_prefetch_bytes(&raw, "x", &mut pf2, &mut err);
        assert!(!parse_prefetch_bytes(b"MAM\x04", "x", &mut pf, &mut err));
        assert!(!decompress_mam(b"MAM\x03\x10\0\0\0", &mut Vec::new(), &mut err));
        assert_eq!(err, "desteklenmeyen MAM biçimi 3");
    }

    #[test]
    fn xpress_literals() {
        let mut s = vec![0u8; 256];
        for b in s.iter_mut().take(128) {
            *b = 0x88;
        }
        s.extend_from_slice(&[0x42, 0x41, 0x00, 0x43]);
        let mut out = Vec::new();
        let mut err = String::new();
        assert!(decompress_xpress(&s, 3, &mut out, &mut err), "{err}");
        assert_eq!(out, b"ABC");
        assert!(!decompress_xpress(&s[..100], 3, &mut out, &mut err));
    }

    #[test]
    fn ext_and_rank() {
        assert_eq!(ext_lower_nt("C:\\A\\B.JAR"), ".jar");
        assert_eq!(ext_lower_nt("C:\\A.B\\C"), "");
        assert_eq!(ext_lower_nt("C:\\A\\.JAR"), "");
        let mut pr = PrefetchResult::default();
        assert_eq!(prefetch_rank(&pr), 0);
        pr.findings.push(PfFinding {
            category: "YASAKLI_ISLEV".into(),
            ..Default::default()
        });
        assert_eq!(prefetch_rank(&pr), 2);
    }

    #[test]
    fn filetime_conv() {
        assert_eq!(pf_filetime(0), None);
        assert_eq!(pf_filetime(116_444_736_000_000_000), Some(0.0));
    }

    #[test]
    #[ignore]
    fn real_prefetch_dir() {
        let v = parse_prefetch_dir(&prefetch_dir());
        println!("{} pf ayrıştırıldı", v.len());
    }
}
