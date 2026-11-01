use crate::classfile::parse_class;
use crate::data::LEGIT_AGENT_HINTS;
use crate::jar::*;
use crate::rx::Rx;
use crate::util::*;
use crate::zipr::*;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{Cursor, Read, Seek, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

pub use crate::locations::{location_note, recycle_bin_index, recycle_lookup};

pub type ResultP = Arc<ScanResult>;

#[derive(Debug, Clone, Default)]
pub struct TextHit {
    pub file: String,
    pub reason: String,
    pub line: String,
    pub category: String,
    pub line_no: i32,
}

#[derive(Debug, Clone, Default)]
pub struct DiskStats {
    pub files: i64,
    pub dirs: i64,
    pub archives: i64,
    pub texts: i64,
    pub denied: i64,
    pub flagged: i64,
    pub cloud: i64,
    pub containers: i64,
    pub loose_groups: i64,
    pub unopened: i64,
    pub skipped_sys_dirs: i64,
    pub skipped_mem: i64,
    pub skipped_loose: i64,
    pub est_total: i64,
    pub eta_secs: f64,
}

const MAX_FILE: u64 = 400 * 1024 * 1024;
const MAX_PE: u64 = 16 * 1024 * 1024;
const MAX_TEXT: u64 = 2 * 1024 * 1024;
const MAX_DEPTH: i32 = 5;
const MAX_LOOSE_FILES: u64 = 3_000_000;
const MAX_ENCODED: u64 = 24 * 1024 * 1024;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const CLOUD_ONLY_ATTRS: u32 = 0x1000 | 0x40000 | 0x400000;

const ARCHIVE_EXT: &[&str] = &[".jar", ".zip", ".litemod", ".disabled", ".mrpack", ".jarx", ".mod"];
const SCRIPT_EXT: &[&str] = &[".bat", ".cmd", ".ps1", ".vbs", ".txt"];
const CONFIG_EXT: &[&str] = &[
    ".json",
    ".cfg",
    ".ini",
    ".properties",
    ".toml",
    ".yml",
    ".yaml",
    ".conf",
];
const MC_PATH_HINTS: &[&str] = &[
    ".minecraft",
    "tlauncher",
    "minecraft",
    "prismlauncher",
    "multimc",
    "curseforge",
    "modrinth",
    "lunarclient",
    "feather",
    "badlion",
    "atlauncher",
    "gdlauncher",
    "sklauncher",
    ".fabric",
    "polymc",
    "technic",
    "salwyrr",
    "labymod",
];
const MC_CONTENT_HINTS: &[&str] = &[
    "minecraft",
    "net.fabricmc",
    "fabric-loader",
    "fabricloader",
    "tlauncher",
    "lunarclient",
    "forge-",
    "neoforge",
    "optifine",
];
const LAUNCHER_FILE_HINTS: &[&str] = &[
    "launcher",
    "profile",
    "instance",
    "mmc-pack",
    "tlauncher",
    "options.json",
];
const WEAK_KEYS_ALWAYS: &[&str] = &["crosshair_value_mod", "anti_push"];

fn in_l(s: &str, l: &[&str]) -> bool {
    l.contains(&s)
}

fn lk<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

const HEAVY_BYTES: u64 = 32 * 1024 * 1024;

const MB: u64 = 1 << 20;
static CAP_INNER: AtomicU64 = AtomicU64::new(300 * MB);
static CAP_LOOSE: AtomicU64 = AtomicU64::new(400 * MB);
static CAP_CHUNK: AtomicU64 = AtomicU64::new(96 * MB);
static CAP_SLURP: AtomicU64 = AtomicU64::new(1 << 30);

fn inner_cap() -> u64 {
    CAP_INNER.load(Ordering::Relaxed)
}
fn loose_cap() -> u64 {
    CAP_LOOSE.load(Ordering::Relaxed)
}
fn chunk_cap() -> u64 {
    CAP_CHUNK.load(Ordering::Relaxed)
}
fn slurp_cap() -> u64 {
    CAP_SLURP.load(Ordering::Relaxed)
}

thread_local! {
    static MEM_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Clone, Copy, Debug)]
struct MemPlan {
    budget: u64,
    max_heavy: i32,
    total: u64,
}

fn mem_status() -> (u64, u64) {
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        let mut ms = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        // SAFETY: ms geçerli ve dwLength doğru ayarlı.
        if unsafe { GlobalMemoryStatusEx(&mut ms) }.is_ok() {
            return (ms.ullTotalPhys, ms.ullAvailPhys);
        }
    }
    (0, 0)
}

fn plan_for(total: u64, avail: u64) -> MemPlan {
    let (total_k, avail_k) = if total == 0 { (8 << 30, 4 << 30) } else { (total, avail) };
    let budget = (avail_k / 3).min(total_k / 4).clamp(256 * MB, 1024 * MB);
    MemPlan {
        budget,
        max_heavy: if budget < 768 * MB { 1 } else { 2 },
        total: total_k,
    }
}

fn apply_mem_plan() -> MemPlan {
    let (t, a) = mem_status();
    let p = plan_for(t, a);
    CAP_INNER.store((p.budget / 3).clamp(64 * MB, 300 * MB), Ordering::Relaxed);
    CAP_LOOSE.store((p.budget * 2 / 5).clamp(64 * MB, 400 * MB), Ordering::Relaxed);
    CAP_CHUNK.store((p.budget / 8).clamp(24 * MB, 96 * MB), Ordering::Relaxed);
    CAP_SLURP.store(p.budget.clamp(128 * MB, 1 << 30), Ordering::Relaxed);
    p
}

fn volume_letter(root: &str) -> Option<char> {
    let b = root.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && root[2..].chars().all(|c| c == '\\' || c == '/') {
        Some(b[0].to_ascii_uppercase() as char)
    } else {
        None
    }
}

#[cfg(windows)]
struct VolHandle(windows::Win32::Foundation::HANDLE);
#[cfg(windows)]
impl Drop for VolHandle {
    fn drop(&mut self) {
        // SAFETY: tanıtıcı bu sarmalayıcıya aittir ve yalnızca bir kez kapatılır.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn open_volume(letter: char) -> Option<VolHandle> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let w: Vec<u16> = format!("\\\\.\\{}:", letter)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: w NUL ile biten geçerli geniş dizgi.
    let h = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };
    match h {
        Ok(h) if h != INVALID_HANDLE_VALUE => Some(VolHandle(h)),
        _ => None,
    }
}

#[cfg(windows)]
fn ioctl(h: &VolHandle, code: u32, inp: Option<&[u8]>, out: &mut [u8]) -> bool {
    use windows::Win32::System::IO::DeviceIoControl;
    let mut br: u32 = 0;
    // SAFETY: tamponlar geçerli ve uzunlukları doğru verilir.
    unsafe {
        DeviceIoControl(
            h.0,
            code,
            inp.map(|b| b.as_ptr().cast()),
            inp.map_or(0, |b| b.len() as u32),
            Some(out.as_mut_ptr().cast()),
            out.len() as u32,
            Some(&mut br),
            None,
        )
        .is_ok()
    }
}

fn mft_records(letter: char) -> Option<u64> {
    #[cfg(windows)]
    {
        const FSCTL_GET_NTFS_VOLUME_DATA: u32 = 0x0009_0064;
        let h = open_volume(letter)?;
        let mut b = [0u8; 256];
        if !ioctl(&h, FSCTL_GET_NTFS_VOLUME_DATA, None, &mut b) {
            return None;
        }
        let per = u32::from_le_bytes(b[48..52].try_into().ok()?) as u64;
        let valid = i64::from_le_bytes(b[56..64].try_into().ok()?);
        if per == 0 || valid <= 0 {
            return None;
        }
        Some(valid as u64 / per)
    }
    #[cfg(not(windows))]
    {
        let _ = letter;
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Media {
    Unknown,
    Hdd,
    Ssd,
}

fn media_type(letter: char) -> Media {
    #[cfg(windows)]
    {
        const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
        let Some(h) = open_volume(letter) else {
            return Media::Unknown;
        };
        let mut q = [0u8; 12];
        q[0..4].copy_from_slice(&7u32.to_le_bytes());
        let mut o = [0u8; 16];
        if !ioctl(&h, IOCTL_STORAGE_QUERY_PROPERTY, Some(&q), &mut o) {
            return Media::Unknown;
        }
        if u32::from_le_bytes([o[4], o[5], o[6], o[7]]) < 9 {
            return Media::Unknown;
        }
        if o[8] != 0 {
            Media::Hdd
        } else {
            Media::Ssd
        }
    }
    #[cfg(not(windows))]
    {
        let _ = letter;
        Media::Unknown
    }
}

fn auto_workers(roots: &[String], plan: &MemPlan) -> i32 {
    let cores = cpu_count().max(1) as i32;
    let mut w = cores.clamp(2, 8);
    let mut any_hdd = false;
    let mut all_ssd = !roots.is_empty();
    for r in roots {
        let letter = r
            .chars()
            .next()
            .filter(|c| c.is_ascii_alphabetic() && r.as_bytes().get(1) == Some(&b':'));
        match letter.map(|l| media_type(l.to_ascii_uppercase())) {
            Some(Media::Hdd) => {
                any_hdd = true;
                all_ssd = false;
            }
            Some(Media::Ssd) => {}
            _ => all_ssd = false,
        }
    }
    if any_hdd {
        w = w.min(3);
    } else if all_ssd {
        w = cores.clamp(2, 12);
    }
    if cores <= 2 {
        w = 2;
    }
    if plan.total < 6 * (1 << 30) {
        w = w.min(3);
    }
    w.max(1)
}

fn path_hash(s: &str) -> u64 {
    let mut h: u64 = 1469598103934665603;
    for &c in s.as_bytes() {
        h ^= c as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

fn avail_phys() -> u64 {
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        let mut ms = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        // SAFETY: ms geçerli ve dwLength doğru ayarlı.
        if unsafe { GlobalMemoryStatusEx(&mut ms) }.is_ok() {
            return ms.ullAvailPhys;
        }
    }
    u64::MAX
}

struct SkipRules {
    prefixes: Vec<String>,
    keep: Vec<String>,
    segments: Vec<String>,
    browser_roots: Vec<String>,
    cache_names: Vec<String>,
}

fn lowpath(p: &str) -> String {
    #[cfg(windows)]
    {
        path_normcase(p) // Unicode-duyarlı küçük harf + '/' -> '\'
    }
    #[cfg(not(windows))]
    {
        replace_all(&py_lower(p), "/", "\\")
    }
}

fn skip_rules() -> &'static SkipRules {
    static R: OnceLock<SkipRules> = OnceLock::new();
    R.get_or_init(|| {
        let mut r = SkipRules {
            prefixes: Vec::new(),
            keep: Vec::new(),
            segments: Vec::new(),
            browser_roots: Vec::new(),
            cache_names: Vec::new(),
        };
        #[cfg(windows)]
        {
            let addp = |p: &str, r: &mut SkipRules| {
                if !p.is_empty() {
                    r.prefixes.push(lowpath(p));
                }
            };
            let mut sr = env("SystemRoot");
            if sr.is_empty() {
                sr = "C:\\Windows".to_string();
            }
            addp(&sr, &mut r);
            r.keep.push(lowpath(&path_join(&sr, "Temp")));
            let mut pfs: StrList = Vec::new();
            for e in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
                let v = env(e);
                if !v.is_empty() && !pfs.contains(&v) {
                    pfs.push(v);
                }
            }
            const PF_VENDOR: &[&str] = &[
                "WindowsApps",
                "ModifiableWindowsApps",
                "Windows Defender",
                "Windows Defender Advanced Threat Protection",
                "Windows Mail",
                "Windows Media Player",
                "Windows NT",
                "Windows Photo Viewer",
                "Windows Portable Devices",
                "Windows Security",
                "Windows Sidebar",
                "WindowsPowerShell",
                "Windows Kits",
                "Internet Explorer",
                "Microsoft Office",
                "Microsoft Office 15",
                "Microsoft Visual Studio",
                "Microsoft SDKs",
                "Microsoft SQL Server",
                "Microsoft.NET",
                "Microsoft Update Health Tools",
                "Microsoft OneDrive",
                "Microsoft",
                "Microsoft Analysis Services",
                "Reference Assemblies",
                "MSBuild",
                "dotnet",
                "IIS",
                "IIS Express",
                "Common Files\\microsoft shared",
                "Common Files\\Microsoft Shared",
                "Common Files\\System",
                "NVIDIA Corporation",
                "Intel",
                "AMD",
                "Realtek",
                "Google\\Chrome\\Application",
                "Mozilla Firefox",
                "Mozilla Maintenance Service",
                "Microsoft\\Edge",
                "Microsoft\\EdgeUpdate",
                "Microsoft\\EdgeWebView",
            ];
            for pf in &pfs {
                for v in PF_VENDOR {
                    addp(&path_join(pf, v), &mut r);
                }
            }
            let pd = env("ProgramData");
            if !pd.is_empty() {
                for v in [
                    "Microsoft",
                    "Package Cache",
                    "NVIDIA",
                    "NVIDIA Corporation",
                    "Intel",
                    "AMD",
                    "regid.1991-06.com.microsoft",
                    "USOShared",
                    "USOPrivate",
                    "Packages",
                ] {
                    addp(&path_join(&pd, v), &mut r);
                }
            }
            for i in 0..26u8 {
                let d = format!("{}:\\", (b'A' + i) as char);
                for v in [
                    "System Volume Information",
                    "$WinREAgent",
                    "$Windows.~BT",
                    "$Windows.~WS",
                    "$SysReset",
                    "$GetCurrent",
                    "Recovery",
                    "PerfLogs",
                    "Config.Msi",
                    "MSOCache",
                    "Windows.old\\Windows",
                    "Windows.old\\Program Files",
                    "Windows.old\\Program Files (x86)",
                    "Windows.old\\ProgramData",
                ] {
                    addp(&format!("{}{}", d, v), &mut r);
                }
            }
        }
        for s in [
            "\\appdata\\local\\packages\\",
            "\\appdata\\local\\microsoft\\windowsapps\\",
            "\\appdata\\local\\microsoft\\windows\\inetcache\\",
            "\\appdata\\local\\microsoft\\windows\\webcache\\",
            "\\appdata\\local\\microsoft\\windows\\explorer\\",
            "\\appdata\\local\\microsoft\\windows\\notifications\\",
            "\\appdata\\local\\microsoft\\windows\\actioncenter\\",
            "\\appdata\\local\\microsoft\\onedrive\\",
            "\\appdata\\local\\microsoft\\teams\\",
            "\\appdata\\local\\nvidia\\dxcache\\",
            "\\appdata\\local\\nvidia\\glcache\\",
            "\\appdata\\local\\amd\\dxcache\\",
            "\\appdata\\local\\d3dscache\\",
        ] {
            r.segments.push(s.to_string());
        }
        for s in [
            "\\google\\chrome\\user data\\",
            "\\microsoft\\edge\\user data\\",
            "\\bravesoftware\\",
            "\\opera software\\",
            "\\vivaldi\\user data\\",
            "\\mozilla\\firefox\\profiles\\",
            "\\appdata\\roaming\\discord\\",
            "\\appdata\\roaming\\spotify\\",
            "\\yandex\\yandexbrowser\\user data\\",
        ] {
            r.browser_roots.push(s.to_string());
        }
        for s in [
            "cache",
            "cache_data",
            "code cache",
            "gpucache",
            "shadercache",
            "grshadercache",
            "dawncache",
            "dawngraphitecache",
            "dawnwebgpucache",
            "cache2",
            "service worker",
            "cachestorage",
            "scriptcache",
        ] {
            r.cache_names.push(s.to_string());
        }
        r
    })
}

fn under(lp: &str, pre: &str) -> bool {
    let (a, b) = (lp.as_bytes(), pre.as_bytes());
    a.len() >= b.len() && a.starts_with(b) && (a.len() == b.len() || a[b.len()] == b'\\' || a[b.len()] == b'/')
}

fn trim_seps(mut lp: String) -> String {
    while lp.len() > 3 && (lp.ends_with('\\') || lp.ends_with('/')) {
        lp.pop();
    }
    lp
}

fn disk_skip_keep_under(dir: &str) -> StrList {
    let mut out = Vec::new();
    let lp = trim_seps(lowpath(dir));
    for k in &skip_rules().keep {
        if k.len() > lp.len() && under(k, &lp) && is_dir(k) {
            out.push(k.clone());
        }
    }
    out
}

pub fn disk_skip_dir(dir: &str) -> bool {
    let r = skip_rules();
    let lp = trim_seps(lowpath(dir));
    for k in &r.keep {
        if under(&lp, k) {
            return false;
        }
    }
    for p in &r.prefixes {
        if under(&lp, p) {
            return true;
        }
    }
    let lps = format!("{}\\", replace_all(&lp, "/", "\\"));
    for s in &r.segments {
        if lps.contains(s.as_str()) {
            return true;
        }
    }
    for b in &r.browser_roots {
        if lps.contains(b.as_str()) {
            let base = match lp.rfind(['\\', '/']) {
                Some(cut) => &lp[cut + 1..],
                None => lp.as_str(),
            };
            for c in &r.cache_names {
                if base == c {
                    return true;
                }
            }
        }
    }
    false
}

#[derive(Debug, Clone, Default)]
pub struct DiskResult {
    pub roots: StrList,
    pub stats: DiskStats,
    pub duration: f64,
    pub stopped: bool,
    pub results: Vec<ResultP>,
    pub text_hits: Vec<TextHit>,
    pub error: String,
}

fn expected_ext(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        "7z" => Some(&[".7z"]),
        "tar" => Some(&[".tar"]),
        "gz" => Some(&[".gz", ".tgz"]),
        "xz" => Some(&[".xz", ".txz"]),
        "bz2" => Some(&[".bz2", ".tbz", ".tbz2"]),
        "libarch" => Some(&[".cab", ".lz", ".zst", ".tzst", ".lz4", ".lha", ".lzh", ".wim"]),
        _ => None,
    }
}

pub fn is_mc_path(p: &str) -> bool {
    has_any(&py_lower(p), MC_PATH_HINTS)
}
pub fn is_log_path(p: &str) -> bool {
    let lp = py_lower(&replace_all(p, "\\", "/"));
    ends(&lp, ".log") || ends(&lp, ".log.gz") || has(&lp, "/logs/") || has(&lp, "/crash-reports/")
}

fn is_java_class(h: &[u8]) -> bool {
    if h.len() < 8 || h[..4] != [0xca, 0xfe, 0xba, 0xbe] {
        return false;
    }
    let major = ((h[6] as i32) << 8) | h[7] as i32;
    (45..=90).contains(&major)
}

pub fn sniff(h: &[u8]) -> String {
    sniff_kind(h).to_string()
}

fn sniff_kind(h: &[u8]) -> &'static str {
    let at = |off: usize, m: &[u8]| h.len() >= off + m.len() && &h[off..off + m.len()] == m;
    if at(0, b"PK\x03\x04") || at(0, b"PK\x05\x06") {
        return "zip";
    }
    if at(0, b"\xef\xbb\xbf") && at(3, b"PK\x03\x04") {
        return "zip";
    }
    if (h.len() >= 2
        && (at(0, b"\xff\xfe") || at(0, b"\xfe\xff"))
        && memchr::memmem::find(&h[..h.len().min(12)], b"P\0K\0\x03\0\x04").is_some())
        || at(0, b"P\0K\0\x03\0\x04\0")
        || at(0, b"\0P\0K\0\x03\0\x04")
    {
        return "zip";
    }
    if at(0, b"\x1f\x8b") {
        return "gz";
    }
    if at(0, b"\xfd7zXZ\x00") {
        return "xz";
    }
    if at(0, b"BZh") && h.len() > 3 && (b'1'..=b'9').contains(&h[3]) {
        return "bz2";
    }
    if at(0, b"7z\xbc\xaf\x27\x1c") {
        return "7z";
    }
    if at(0, b"Rar!\x1a\x07") || at(0, b"Rar!\x1a\x07\x01\x00") {
        return "rar";
    }
    if is_java_class(h) {
        return "class";
    }
    if h.len() >= 262 && &h[257..262] == b"ustar" {
        return "tar";
    }
    if at(0, b"MSCF") {
        return "libarch";
    }
    if at(0, b"LZIP") {
        return "libarch";
    }
    if at(0, b"\x28\xb5\x2f\xfd") {
        return "libarch";
    }
    if at(0, b"\x04\x22\x4d\x18") {
        return "libarch";
    }
    if h.len() >= 7 {
        let x = &h[2..7];
        for m in [
            &b"-lh0-"[..],
            b"-lh1-",
            b"-lh4-",
            b"-lh5-",
            b"-lh6-",
            b"-lh7-",
            b"-lzs-",
        ] {
            if x == m {
                return "libarch";
            }
        }
    }
    if at(0, b"MSWI") || at(0, b"MSWIM\x00") {
        return "libarch";
    }
    ""
}

pub fn default_roots(mode: &str) -> StrList {
    let mut roots: StrList = Vec::new();
    if mode == "full" {
        #[cfg(windows)]
        {
            use windows::core::PCWSTR;
            use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
            const DRIVE_NO_ROOT_DIR: u32 = 1;
            // SAFETY: parametresiz Win32 çağrısı.
            let mask = unsafe { GetLogicalDrives() };
            for i in 0..26u32 {
                if mask & (1u32 << i) == 0 {
                    continue;
                }
                let r = format!("{}:\\", (b'A' + i as u8) as char);
                let w: Vec<u16> = widen(&r).into_iter().chain(std::iter::once(0)).collect();
                // SAFETY: w NUL ile biten geçerli UTF-16 dizisi.
                let t = unsafe { GetDriveTypeW(PCWSTR(w.as_ptr())) };
                if t == DRIVE_NO_ROOT_DIR {
                    continue;
                }
                if exists(&r) {
                    roots.push(r);
                }
            }
        }
        if roots.is_empty() {
            roots.push("/".to_string());
        }
    } else {
        for e in ["USERPROFILE", "PUBLIC", "ProgramData"] {
            let v = env(e);
            if !v.is_empty() && is_dir(&v) {
                roots.push(v);
            }
        }
        if roots.is_empty() {
            roots.push(home_dir());
        }
    }
    roots
}

pub fn apply_disk_filter(res: &mut ScanResult) {
    for s in res.nested.iter_mut() {
        apply_disk_filter(s);
    }
    let published = res.meta.id.truthy;
    let mut keep: Vec<Finding> = Vec::new();
    for f in res.findings.drain(..) {
        if in_l(&f.key, WEAK_KEYS_ALWAYS) {
            continue;
        }
        if published && f.key == "obfuscated" {
            continue;
        }
        if published && f.key == "cheat_terms" && f.category == "SUPHELI" {
            continue;
        }
        keep.push(f);
    }
    let mut rank = 0;
    for f in &keep {
        rank = rank.max(category_rank(&f.category));
    }
    res.findings = keep;
    for s in &res.nested {
        rank = rank.max(s.rank);
    }
    res.rank = rank;
    if rank == 0 {
        res.verdict = if res.official_fabric {
            "TEMIZ (resmi Fabric modulu)".to_string()
        } else if res.trusted_infra {
            format!("TEMIZ ({})", res.trust_label)
        } else if res.server_plugin {
            "TEMIZ (sunucu eklentisi)".to_string()
        } else {
            "TEMIZ".to_string()
        };
    } else {
        res.verdict = verdict_by_rank(rank);
    }
}

#[derive(Debug, Clone, Default)]
pub struct ArcInfo {
    pub opened: bool,
    pub encrypted: bool,
    pub names: StrList,
    pub no_mem: bool,
}

fn enc_msg(s: &str) -> bool {
    let el = s.to_ascii_lowercase();
    has(&el, "passphrase") || has(&el, "password") || has(&el, "encrypt")
}

struct Sink<'a> {
    info: ArcInfo,
    cb: &'a mut dyn FnMut(&str, &mut Bytes) -> bool,
    max_member: u64,
    stop: Option<&'a StopFlag>,
    total: u64,
    count: i32,
}

impl Sink<'_> {
    fn stopped(&self) -> bool {
        self.stop.is_some_and(|s| s.is_set())
    }
    fn next_header(&mut self) -> bool {
        if self.stopped() {
            return false;
        }
        self.count += 1;
        self.count <= 200000
    }
    fn member(&mut self, name: &str, encrypted: bool, size: Option<u64>, regular: bool, rd: &mut dyn Read) -> bool {
        if encrypted {
            self.info.encrypted = true;
            self.info.names.push(name.to_string());
            return true;
        }
        self.info.names.push(name.to_string());
        if !regular {
            return true;
        }
        if let Some(sz) = size {
            if sz < 30 || sz > self.max_member {
                return true;
            }
        }
        let mut data: Bytes = Vec::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut too_big = false;
        loop {
            match rd.read(&mut buf) {
                Ok(0) => break,
                Ok(k) => {
                    if data.len() as u64 + k as u64 > self.max_member {
                        too_big = true;
                        break;
                    }
                    data.extend_from_slice(&buf[..k]);
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    if enc_msg(&e.to_string()) {
                        self.info.encrypted = true;
                    }
                    break;
                }
            }
        }
        if too_big || data.len() < 30 {
            return true;
        }
        self.total += data.len() as u64;
        if !(self.cb)(name, &mut data) {
            return false;
        }
        self.total <= 8u64 * 1024 * 1024 * 1024
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Flt {
    Gz,
    Bz2,
    Xz,
    Zstd,
    Lz4,
}

fn filter_kind(h: &[u8]) -> Option<Flt> {
    if h.starts_with(&[0x1f, 0x8b, 0x08]) {
        Some(Flt::Gz)
    } else if h.len() >= 4 && &h[..3] == b"BZh" && (b'1'..=b'9').contains(&h[3]) {
        Some(Flt::Bz2)
    } else if h.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Some(Flt::Xz)
    } else if h.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some(Flt::Zstd)
    } else if h.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        Some(Flt::Lz4)
    } else {
        None
    }
}

struct CapWriter {
    v: Vec<u8>,
    cap: usize,
}
impl Write for CapWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.v.len() + b.len() > self.cap {
            MEM_FAIL.with(|f| f.set(true));
            return Err(std::io::Error::other("xz sınır"));
        }
        if self.v.try_reserve(b.len()).is_err() {
            MEM_FAIL.with(|f| f.set(true));
            return Err(std::io::Error::other("bellek yok"));
        }
        self.v.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn apply_filter<'a>(k: Flt, r: Box<dyn Read + 'a>) -> Box<dyn Read + 'a> {
    match k {
        Flt::Gz => Box::new(flate2::read::MultiGzDecoder::new(r)),
        Flt::Bz2 => Box::new(bzip2::read::BzDecoder::new(r)),
        Flt::Xz => {
            let mut br = std::io::BufReader::new(r);
            let mut w = CapWriter {
                v: Vec::new(),
                cap: slurp_cap() as usize,
            };
            let _ = lzma_rs::xz_decompress(&mut br, &mut w);
            Box::new(Cursor::new(w.v))
        }
        Flt::Zstd => match ruzstd::decoding::StreamingDecoder::new(r) {
            Ok(d) => Box::new(d),
            Err(_) => Box::new(std::io::empty()),
        },
        Flt::Lz4 => Box::new(lz4_flex::frame::FrameDecoder::new(r)),
    }
}

fn peek<'a>(mut r: Box<dyn Read + 'a>, n: usize) -> (Vec<u8>, Box<dyn Read + 'a>) {
    let mut head = vec![0u8; n];
    let mut got = 0;
    while got < n {
        match r.read(&mut head[got..]) {
            Ok(0) => break,
            Ok(k) => got += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    head.truncate(got);
    let chain: Box<dyn Read + 'a> = Box::new(Cursor::new(head.clone()).chain(r));
    (head, chain)
}

fn skip_bytes(r: &mut dyn Read, n: u64) {
    let _ = std::io::copy(&mut r.take(n), &mut std::io::sink());
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fmt {
    SevenZ,
    Rar,
    Cab,
    Lha,
    Tar,
    Cpio,
    Ar,
    Raw,
}

fn tar_header_ok(h: &[u8]) -> bool {
    if h.len() < 512 || h[0] == 0 {
        return false;
    }
    let field = &h[148..156];
    let txt: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|&c| c == b' ')
        .take_while(|&c| (b'0'..=b'7').contains(&c))
        .collect();
    if txt.is_empty() {
        return false;
    }
    let mut want: u64 = 0;
    for c in txt {
        want = want * 8 + (c - b'0') as u64;
    }
    let mut un: u64 = 0;
    let mut sg: i64 = 0;
    for (i, &c) in h[..512].iter().enumerate() {
        let c = if (148..156).contains(&i) { b' ' } else { c };
        un += c as u64;
        sg += c as i8 as i64;
    }
    want == un || (sg >= 0 && want == sg as u64)
}

fn detect_format(h: &[u8]) -> Fmt {
    if h.starts_with(b"7z\xbc\xaf\x27\x1c") {
        Fmt::SevenZ
    } else if h.starts_with(b"Rar!\x1a\x07") {
        Fmt::Rar
    } else if h.starts_with(b"MSCF") {
        Fmt::Cab
    } else if h.len() >= 7 && h[2] == b'-' && h[3] == b'l' && h[6] == b'-' && matches!(h[4], b'h' | b'z') {
        Fmt::Lha
    } else if (h.len() >= 262 && &h[257..262] == b"ustar") || tar_header_ok(h) {
        Fmt::Tar
    } else if h.starts_with(b"070701") || h.starts_with(b"070702") || h.starts_with(b"070707") {
        Fmt::Cpio
    } else if h.starts_with(b"!<arch>\n") {
        Fmt::Ar
    } else {
        Fmt::Raw
    }
}

fn slurp(r: &mut dyn Read, cap: u64) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        if v.len() as u64 >= cap {
            if matches!(r.read(&mut buf[..1]), Ok(n) if n > 0) {
                MEM_FAIL.with(|f| f.set(true));
            }
            break;
        }
        let want = buf.len().min((cap - v.len() as u64) as usize);
        match r.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => {
                if v.try_reserve(n.max(v.len() / 4)).is_err() && v.try_reserve_exact(n).is_err() {
                    MEM_FAIL.with(|f| f.set(true));
                    break;
                }
                v.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    v.shrink_to_fit();
    v
}

fn run_7z<R: Read + Seek>(src: R, sink: &mut Sink) {
    use sevenz_rust2::{Error as E, Password, SevenZReader};
    let mut rd = match SevenZReader::new(src, Password::empty()) {
        Ok(r) => r,
        Err(e) => {
            if matches!(e, E::PasswordRequired | E::MaybeBadPassword(_)) || enc_msg(&e.to_string()) {
                sink.info.encrypted = true;
            }
            return;
        }
    };
    let res = rd.for_each_entries(|entry, reader| {
        if !sink.next_header() {
            return Ok(false);
        }
        let name = entry.name().to_string();
        let regular = !entry.is_directory() && !entry.is_anti_item();
        Ok(sink.member(&name, false, Some(entry.size()), regular, reader))
    });
    if let Err(e) = res {
        if matches!(e, E::PasswordRequired | E::MaybeBadPassword(_)) || enc_msg(&e.to_string()) {
            sink.info.encrypted = true;
        }
    }
}

fn run_cab<R: Read + Seek>(src: R, sink: &mut Sink) {
    let Ok(mut cabinet) = cab::Cabinet::new(src) else {
        return;
    };
    let mut files: Vec<(String, u32)> = Vec::new();
    for folder in cabinet.folder_entries() {
        for f in folder.file_entries() {
            files.push((f.name().to_string(), f.uncompressed_size()));
        }
    }
    for (name, size) in files {
        if !sink.next_header() {
            break;
        }
        match cabinet.read_file(&name) {
            Ok(mut fr) => {
                if !sink.member(&name, false, Some(size as u64), true, &mut fr) {
                    break;
                }
            }
            Err(_) => {
                sink.info.names.push(name);
            }
        }
    }
}

fn run_lha(src: Box<dyn Read + '_>, sink: &mut Sink) {
    let Ok(mut rd) = delharc::LhaDecodeReader::new(src) else {
        return;
    };
    loop {
        if !sink.next_header() {
            break;
        }
        let h = rd.header();
        let name = h.parse_pathname_to_str();
        let is_dir = h.is_directory();
        let size = rd.len();
        if !sink.member(&name, false, Some(size), !is_dir, &mut rd) {
            break;
        }
        match rd.next_file() {
            Ok(true) => {}
            _ => break,
        }
    }
}

fn run_tar(src: Box<dyn Read + '_>, sink: &mut Sink) {
    let mut ar = tar::Archive::new(src);
    let Ok(entries) = ar.entries() else {
        return;
    };
    for ent in entries {
        if !sink.next_header() {
            break;
        }
        let Ok(mut e) = ent else {
            break;
        };
        let name = String::from_utf8_lossy(&e.path_bytes()).into_owned();
        let name = if name.is_empty() { "data".to_string() } else { name };
        let regular = e.header().entry_type().is_file();
        let size = e.size();
        if !sink.member(&name, false, Some(size), regular, &mut e) {
            break;
        }
    }
}

fn parse_radix(b: &[u8], radix: u32) -> Option<u64> {
    let s = std::str::from_utf8(b).ok()?;
    u64::from_str_radix(s.trim_matches(|c| c == ' ' || c == '\0'), radix).ok()
}

fn run_cpio(mut src: Box<dyn Read + '_>, sink: &mut Sink) {
    loop {
        if !sink.next_header() {
            break;
        }
        let mut m = [0u8; 6];
        if src.read_exact(&mut m).is_err() {
            break;
        }
        let (namesize, filesize, mode, pad_hdr) = if &m == b"070701" || &m == b"070702" {
            let mut h = [0u8; 104];
            if src.read_exact(&mut h).is_err() {
                break;
            }
            let f = |i: usize| parse_radix(&h[i * 8..i * 8 + 8], 16);
            let (Some(mode), Some(fsz), Some(nsz)) = (f(1), f(6), f(11)) else {
                break;
            };
            (nsz, fsz, mode, true)
        } else if &m == b"070707" {
            let mut h = [0u8; 70];
            if src.read_exact(&mut h).is_err() {
                break;
            }
            let (Some(mode), Some(nsz), Some(fsz)) = (
                parse_radix(&h[12..18], 8),
                parse_radix(&h[53..59], 8),
                parse_radix(&h[59..70], 8),
            ) else {
                break;
            };
            (nsz, fsz, mode, false)
        } else {
            break;
        };
        if namesize == 0 || namesize > 65536 {
            break;
        }
        let mut nb = vec![0u8; namesize as usize];
        if src.read_exact(&mut nb).is_err() {
            break;
        }
        if pad_hdr {
            let pad = (4 - (110 + namesize as usize) % 4) % 4;
            skip_bytes(&mut src, pad as u64);
        }
        if let Some(z) = nb.iter().position(|&c| c == 0) {
            nb.truncate(z);
        }
        let name = String::from_utf8_lossy(&nb).into_owned();
        if name == "TRAILER!!!" {
            break;
        }
        let regular = mode & 0o170000 == 0o100000;
        let mut lim = (&mut src).take(filesize);
        let cont = sink.member(&name, false, Some(filesize), regular, &mut lim);
        let left = lim.limit();
        skip_bytes(&mut src, left);
        if pad_hdr {
            skip_bytes(&mut src, (4 - filesize % 4) % 4);
        }
        if !cont {
            break;
        }
    }
}

fn run_ar(mut src: Box<dyn Read + '_>, sink: &mut Sink) {
    let mut magic = [0u8; 8];
    if src.read_exact(&mut magic).is_err() {
        return;
    }
    let mut longnames: Vec<u8> = Vec::new();
    loop {
        if !sink.next_header() {
            break;
        }
        let mut h = [0u8; 60];
        if src.read_exact(&mut h).is_err() || &h[58..60] != b"`\n" {
            break;
        }
        let Some(mut size) = parse_radix(&h[48..58], 10) else {
            break;
        };
        let padded = size + (size & 1);
        let raw = String::from_utf8_lossy(&h[..16]).trim_end().to_string();
        let mut name = raw.clone();
        let mut bsd_len = 0u64;
        if raw == "//" {
            longnames = slurp(&mut (&mut src).take(size), size);
            skip_bytes(&mut src, padded - size);
            continue;
        }
        if raw == "/" || raw == "/SYM64/" {
            skip_bytes(&mut src, padded);
            continue;
        }
        if let Some(n) = raw.strip_prefix('/').and_then(|r| r.parse::<usize>().ok()) {
            let tail = longnames.get(n..).unwrap_or(&[]);
            let end = tail.iter().position(|&c| c == b'\n').unwrap_or(tail.len());
            name = String::from_utf8_lossy(&tail[..end]).into_owned();
        } else if let Some(n) = raw.strip_prefix("#1/").and_then(|r| r.parse::<u64>().ok()) {
            bsd_len = n.min(size);
            let nb = slurp(&mut (&mut src).take(bsd_len), bsd_len);
            let z = nb.iter().position(|&c| c == 0).unwrap_or(nb.len());
            name = String::from_utf8_lossy(&nb[..z]).into_owned();
            size -= bsd_len;
        }
        let name = name.trim_end_matches('/').to_string();
        let mut lim = (&mut src).take(size);
        let cont = sink.member(&name, false, Some(size), true, &mut lim);
        let left = lim.limit();
        skip_bytes(&mut src, left + (padded - size - bsd_len));
        if !cont {
            break;
        }
    }
}

fn run_rar(path: &str, sink: &mut Sink) {
    use unrar::error::Code;
    let ar = match unrar::Archive::new(path).open_for_processing() {
        Ok(a) => a,
        Err(e) => {
            sink.info.opened = true;
            if matches!(e.code, Code::MissingPassword | Code::BadPassword) {
                sink.info.encrypted = true;
            }
            return;
        }
    };
    let mut cur = ar;
    loop {
        if !sink.next_header() {
            break;
        }
        let hdr = match cur.read_header() {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                if matches!(e.code, Code::MissingPassword | Code::BadPassword) {
                    sink.info.encrypted = true;
                }
                break;
            }
        };
        let e = hdr.entry();
        let name = e.filename.to_string_lossy().into_owned();
        let encrypted = e.is_encrypted();
        let regular = e.is_file();
        let size = e.unpacked_size;
        if encrypted {
            sink.info.encrypted = true;
            sink.info.names.push(name);
            cur = match hdr.skip() {
                Ok(c) => c,
                Err(_) => break,
            };
            continue;
        }
        sink.info.names.push(name.clone());
        if !regular || size < 30 || size > sink.max_member {
            cur = match hdr.skip() {
                Ok(c) => c,
                Err(_) => break,
            };
            continue;
        }
        match hdr.read() {
            Ok((data, next)) => {
                cur = next;
                if (data.len() as u64) > sink.max_member || data.len() < 30 {
                    continue;
                }
                let mut data = data;
                sink.total += data.len() as u64;
                if !(sink.cb)(&name, &mut data) || sink.total > 8u64 * 1024 * 1024 * 1024 {
                    break;
                }
            }
            Err(e) => {
                if matches!(e.code, Code::MissingPassword | Code::BadPassword) {
                    sink.info.encrypted = true;
                }
                break;
            }
        }
    }
}

fn run_rar_bytes(data: &[u8], sink: &mut Sink) {
    let dir = make_temp_dir("jsrar");
    if dir.is_empty() {
        return;
    }
    let p = path_join(&dir, "a.rar");
    if write_file(&p, data) {
        run_rar(&p, sink);
    }
    remove_tree(&dir);
}

pub fn archive_iterate(
    mem: &[u8],
    disk_path: &str,
    cb: &mut dyn FnMut(&str, &mut Bytes) -> bool,
    max_member: u64,
    stop: Option<&StopFlag>,
) -> ArcInfo {
    MEM_FAIL.with(|f| f.set(false));
    let mut file: Option<std::fs::File> = None;
    if !disk_path.is_empty() {
        match std::fs::File::open(disk_path) {
            Ok(f) => file = Some(f),
            Err(_) => return ArcInfo::default(),
        }
    }
    let mut sink = Sink {
        info: ArcInfo {
            opened: true,
            ..Default::default()
        },
        cb,
        max_member,
        stop,
        total: 0,
        count: 0,
    };
    let mut head = vec![0u8; 8192];
    let got = if let Some(f) = file.as_mut() {
        let mut g = 0;
        while g < head.len() {
            match f.read(&mut head[g..]) {
                Ok(0) | Err(_) => break,
                Ok(k) => g += k,
            }
        }
        let _ = f.seek(std::io::SeekFrom::Start(0));
        g
    } else {
        let g = mem.len().min(head.len());
        head[..g].copy_from_slice(&mem[..g]);
        g
    };
    head.truncate(got);
    if let Some(k0) = filter_kind(&head) {
        let base: Box<dyn Read + '_> = match file.take() {
            Some(f) => Box::new(std::io::BufReader::with_capacity(1 << 16, f)),
            None => Box::new(Cursor::new(mem)),
        };
        let mut stream = apply_filter(k0, base);
        let mut nfilt = 1usize;
        loop {
            let (h, s) = peek(stream, 8192);
            stream = s;
            match filter_kind(&h) {
                Some(k) if nfilt < 8 => {
                    stream = apply_filter(k, stream);
                    nfilt += 1;
                }
                _ => {
                    head = h;
                    break;
                }
            }
        }
        match detect_format(&head) {
            Fmt::SevenZ => {
                let v = slurp(&mut stream, slurp_cap());
                run_7z(Cursor::new(v), &mut sink);
            }
            Fmt::Cab => {
                let v = slurp(&mut stream, slurp_cap());
                run_cab(Cursor::new(v), &mut sink);
            }
            Fmt::Rar => {
                let v = slurp(&mut stream, slurp_cap());
                run_rar_bytes(&v, &mut sink);
            }
            Fmt::Lha => run_lha(stream, &mut sink),
            Fmt::Tar => run_tar(stream, &mut sink),
            Fmt::Cpio => run_cpio(stream, &mut sink),
            Fmt::Ar => run_ar(stream, &mut sink),
            Fmt::Raw => run_raw(stream, nfilt, &mut sink),
        }
        return finish(sink);
    }
    let fmt = detect_format(&head);
    match (fmt, file) {
        (Fmt::SevenZ, Some(f)) => run_7z(std::io::BufReader::new(f), &mut sink),
        (Fmt::SevenZ, None) => run_7z(Cursor::new(mem), &mut sink),
        (Fmt::Cab, Some(f)) => run_cab(std::io::BufReader::new(f), &mut sink),
        (Fmt::Cab, None) => run_cab(Cursor::new(mem), &mut sink),
        (Fmt::Rar, Some(_)) => run_rar(disk_path, &mut sink),
        (Fmt::Rar, None) => run_rar_bytes(mem, &mut sink),
        (f, file) => {
            let stream: Box<dyn Read + '_> = match file {
                Some(fl) => Box::new(std::io::BufReader::with_capacity(1 << 16, fl)),
                None => Box::new(Cursor::new(mem)),
            };
            match f {
                Fmt::Lha => run_lha(stream, &mut sink),
                Fmt::Tar => run_tar(stream, &mut sink),
                Fmt::Cpio => run_cpio(stream, &mut sink),
                Fmt::Ar => run_ar(stream, &mut sink),
                _ => run_raw(stream, 0, &mut sink),
            }
        }
    }
    finish(sink)
}

fn finish(sink: Sink) -> ArcInfo {
    let mut info = sink.info;
    info.no_mem = MEM_FAIL.with(|f| f.replace(false));
    info
}

fn run_raw(mut stream: Box<dyn Read + '_>, nfilt: usize, sink: &mut Sink) {
    if sink.stopped() {
        return;
    }
    let (h, s) = peek(stream, 1);
    if h.is_empty() {
        return;
    }
    stream = s;
    if !sink.next_header() {
        return;
    }
    if nfilt == 0 {
        sink.info.names.push("data".to_string());
        return;
    }
    sink.member("data", false, None, true, &mut stream);
}

fn looks_encoded(head: &[u8]) -> bool {
    let seg = &head[..head.len().min(512)];
    if seg.len() < 200 {
        return false;
    }
    let core: Vec<u8> = seg
        .iter()
        .copied()
        .filter(|&c| c != b' ' && c != b'\t' && c != b'\r' && c != b'\n')
        .collect();
    if core.len() < 180 {
        return false;
    }
    let (mut b64, mut hx) = (0usize, 0usize);
    for &c in &core {
        if c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=' || c == b'\r' || c == b'\n' {
            b64 += 1;
        }
        if c.is_ascii_hexdigit() {
            hx += 1;
        }
    }
    if b64 as f64 >= core.len() as f64 * 0.97 {
        return true;
    }
    hx as f64 >= core.len() as f64 * 0.99
}

fn peek_decompress(kind: &str, data: &[u8], out: &mut Bytes) -> bool {
    out.clear();
    let ok = match kind {
        "gz" => gunzip(data, out, 1024, None),
        "xz" => unxz(data, out, 1024),
        "bz2" => unbz2(data, out, 1024),
        _ => true,
    };
    if !ok {
        out.clear();
    }
    !out.is_empty()
}

fn bounded_decompress(kind: &str, data: &[u8], out: &mut Bytes) -> bool {
    out.clear();
    match kind {
        "gz" => gunzip(data, out, inner_cap() + 1, None),
        "xz" => unxz(data, out, inner_cap() + 1),
        "bz2" => unbz2(data, out, inner_cap() + 1),
        _ => false,
    }
}

fn embedded_java_zip(data: &[u8]) -> bool {
    let mut names: Vec<String> = Vec::new();
    if !zip_opens(data, Some(&mut names)) {
        return false;
    }
    for (k, n) in names.iter().enumerate() {
        if k >= 50000 {
            break;
        }
        if ends(n, ".class") || ends(n, ".jar") {
            return true;
        }
    }
    false
}

fn b64v(c: u8, url: bool) -> i32 {
    match c {
        b'A'..=b'Z' => (c - b'A') as i32,
        b'a'..=b'z' => (c - b'a') as i32 + 26,
        b'0'..=b'9' => (c - b'0') as i32 + 52,
        b'+' if !url => 62,
        b'/' if !url => 63,
        b'-' if url => 62,
        b'_' if url => 63,
        _ => -1,
    }
}

fn b64dec(inp: &[u8], url: bool, out: &mut Bytes) -> bool {
    out.clear();
    let mut acc: u32 = 0;
    let (mut bits, mut n, mut pad) = (0i32, 0i32, 0i32);
    for &c in inp {
        if c == b'=' {
            pad += 1;
            continue;
        }
        let v = b64v(c, url);
        if v < 0 {
            continue;
        }
        if pad != 0 {
            return false;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        n += 1;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    let rem = n % 4;
    if rem == 1 {
        return false;
    }
    if rem != 0 && (rem + pad) % 4 != 0 && pad != 0 {
        return false;
    }
    if rem != 0 && pad == 0 {
        return false; // Incorrect padding
    }
    true
}

fn hexv(c: u8) -> i32 {
    match c {
        b'0'..=b'9' => (c - b'0') as i32,
        b'a'..=b'f' => (c - b'a') as i32 + 10,
        b'A'..=b'F' => (c - b'A') as i32 + 10,
        _ => -1,
    }
}

fn fromhex(h: &[u8]) -> Bytes {
    let mut o = Vec::with_capacity(h.len() / 2);
    let mut i = 0;
    while i + 1 < h.len() {
        o.push((((hexv(h[i]) << 4) | hexv(h[i + 1])) & 0xFF) as u8);
        i += 2;
    }
    o
}

fn decode_payload(kind: &str, blob: &[u8], out: &mut Bytes) -> bool {
    out.clear();
    if kind == "hex" {
        let h: Vec<u8> = blob.iter().copied().filter(|&c| hexv(c) >= 0).collect();
        for t in 0..2usize {
            if t > h.len() {
                break;
            }
            let mut core = &h[t..];
            core = &core[..core.len() / 2 * 2];
            if core.len() < 16 {
                continue;
            }
            if !sniff(&fromhex(&core[..16])).is_empty() || lower_ascii_bytes(&core[..4]) == b"4d5a" {
                *out = fromhex(core);
                return true;
            }
        }
        return false;
    }
    let url = kind == "b64url";
    let mut core: Vec<u8> = blob
        .iter()
        .copied()
        .filter(|&c| c != b'\r' && c != b'\n' && c != b' ')
        .collect();
    if let Some(eq) = core.iter().position(|&c| c == b'=') {
        core.truncate(eq);
    }
    for t in 0..80usize {
        if t > core.len() {
            break;
        }
        let seg = &core[t..];
        let seg = &seg[..seg.len() / 4 * 4];
        if seg.len() < 16 {
            break;
        }
        let mut headb: Bytes = Vec::new();
        if !b64dec(&seg[..seg.len().min(24)], url, &mut headb) {
            continue;
        }
        if !sniff(&headb).is_empty() || headb.starts_with(b"MZ") {
            let mut body: Vec<u8> = core[t..].to_vec();
            if body.len() % 4 == 1 {
                body.pop();
            }
            let padn = (4 - body.len() % 4) % 4;
            body.extend(std::iter::repeat_n(b'=', padn));
            if b64dec(&body, url, out) {
                return true;
            }
            let b2 = &body[..body.len() / 4 * 4];
            return b64dec(b2, url, out);
        }
    }
    false
}

fn lower_ascii_bytes(b: &[u8]) -> Vec<u8> {
    b.iter().map(|c| c.to_ascii_lowercase()).collect()
}

fn find_runs(raw: &[u8], kind: &str, cb: &mut dyn FnMut(&[u8]) -> bool) {
    let n = raw.len();
    let mut i = 0usize;
    let in_b64 = |c: u8| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'\r' || c == b'\n';
    let in_url = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'\r' || c == b'\n';
    let in_hex2 = |c: u8| {
        c.is_ascii_hexdigit()
            || c == b' '
            || c == b'\t'
            || c == b'\r'
            || c == b'\n'
            || c == b','
            || c == b':'
            || c == b';'
    };
    let inset = |c: u8| match kind {
        "b64" => in_b64(c),
        "b64url" => in_url(c),
        _ => in_hex2(c),
    };
    while i < n {
        if !inset(raw[i]) {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < n && inset(raw[j]) {
            j += 1;
        }
        if kind == "hex" {
            let mut s = i;
            while s < j && !raw[s].is_ascii_hexdigit() {
                s += 1;
            }
            if s < j && j - s >= 2048 && !cb(&raw[s..j]) {
                return;
            }
        } else if j - i >= 1024 && !cb(&raw[i..j]) {
            return;
        }
        i = j;
    }
}

fn short_ext(ext: &str) -> String {
    if ext.is_empty() {
        "uzantısız".to_string()
    } else {
        ext.to_string()
    }
}

pub type DiskProgress = Box<dyn Fn(&DiskStats, &str) + Send + Sync>;
pub type DiskFound = Box<dyn Fn(&ScanResult) + Send + Sync>;

#[derive(Clone)]
struct Item {
    path: String,
    size: u64,
    reason: String,
}

#[derive(Default)]
struct QState {
    q: VecDeque<Item>,
    pending: usize,
    quit: bool,
}

#[derive(Default)]
struct Loose {
    items: Vec<(String, Bytes)>,
    files: Vec<(String, String)>,
    item_idx: HashMap<String, usize>,
    file_idx: HashMap<String, usize>,
    disk_root: String,
    reasons: BTreeSet<String>,
}

#[derive(Default)]
struct Shared {
    st: DiskStats,
    cur_dir: String,
    cache: HashMap<String, Option<usize>>,
    inflight: HashSet<String>,
    seen_paths: HashSet<u64>,
    followups: Vec<Item>,
    loose: Vec<(String, Loose)>,
    loose_idx: HashMap<String, usize>,
    loose_bytes: u64,
    loose_files: u64,
    flagged: Vec<ScanResult>,
    done: u64,
    skipped_walk: u64,
    walk_done: bool,
    extra_total: u64,
    mft_records: u64,
    rate_ema: f64,
    last_t: f64,
    last_done: u64,
    t_start: f64,
}

pub struct DiskScanner {
    roots: StrList,
    progress: Option<DiskProgress>,
    on_found: Option<DiskFound>,
    stop: Arc<StopFlag>,
    workers: i32,
    exclude: StrList,
    self_exe: String,
    sh: Mutex<Shared>,
    q: Mutex<QState>,
    qcv: Condvar,
    qspace: Condvar,
    qdone: Condvar,
    heavy: Mutex<(i32, u64)>,
    hcv: Condvar,
    plan: MemPlan,
    last_ui: AtomicI64,
}

fn re_agent() -> &'static Rx {
    static R: OnceLock<Rx> = OnceLock::new();
    R.get_or_init(|| Rx::new(r#"-javaagent:\s*"?([^"\r\n]+?\.jar)"#, Rx::I))
}
fn re_addmods() -> &'static Rx {
    static R: OnceLock<Rx> = OnceLock::new();
    R.get_or_init(|| Rx::new(r#"(?:fabric|loader)\.addMods\s*=\s*"?([^"\r\n ]+)"#, Rx::I))
}
fn re_jarref() -> &'static Rx {
    static R: OnceLock<Rx> = OnceLock::new();
    R.get_or_init(|| Rx::new(r#""([^"\r\n]+?\.jar)"|([^\s"';=<>|*?]+\.jar)\b"#, Rx::I))
}

struct HeavyHold<'a> {
    s: &'a DiskScanner,
    on: bool,
    need: u64,
}
impl Drop for HeavyHold<'_> {
    fn drop(&mut self) {
        if self.on {
            self.s.heavy_release(self.need);
        }
    }
}

impl DiskScanner {
    pub fn new(
        roots: StrList,
        progress: Option<DiskProgress>,
        stop: Option<Arc<StopFlag>>,
        workers: i32,
        exclude: StrList,
    ) -> DiskScanner {
        let plan = apply_mem_plan();
        let workers = if workers > 0 {
            workers
        } else {
            auto_workers(&roots, &plan)
        };
        let self_exe = self_exe_path();
        let mut ex = exclude;
        ex.push(self_exe.clone());
        let mut exclude_n: StrList = Vec::new();
        for e in &ex {
            if !e.is_empty() {
                exclude_n.push(path_norm(e));
            }
        }
        DiskScanner {
            roots,
            progress,
            on_found: None,
            stop: stop.unwrap_or_else(|| Arc::new(StopFlag::new())),
            workers,
            exclude: exclude_n,
            self_exe,
            sh: Mutex::new(Shared::default()),
            q: Mutex::new(QState::default()),
            qcv: Condvar::new(),
            qspace: Condvar::new(),
            qdone: Condvar::new(),
            heavy: Mutex::new((0, 0)),
            hcv: Condvar::new(),
            plan,
            last_ui: AtomicI64::new(0),
        }
    }

    pub fn set_on_found(&mut self, cb: DiskFound) {
        self.on_found = Some(cb);
    }

    fn stopped(&self) -> bool {
        self.stop.is_set()
    }

    fn ui(&self, force: bool) {
        let Some(pr) = &self.progress else {
            return;
        };
        let now = now_epoch();
        let now_ms = (now * 1000.0) as i64;
        let last = self.last_ui.load(Ordering::Relaxed);
        if !force && now_ms - last < 200 {
            return;
        }
        if self
            .last_ui
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
            && !force
        {
            return;
        }
        let (s, cd) = {
            let mut g = lk(&self.sh);
            let (est, eta) = Self::estimate(&mut g, now, force);
            g.st.est_total = est;
            g.st.eta_secs = eta;
            (g.st.clone(), g.cur_dir.clone())
        };
        let _ = catch_unwind(AssertUnwindSafe(|| pr(&s, &cd)));
    }

    fn estimate(g: &mut Shared, now: f64, last: bool) -> (i64, f64) {
        let done = g.done + g.skipped_walk;
        let dt = now - g.last_t;
        if g.last_t == 0.0 {
            g.last_t = now;
            g.last_done = done;
        } else if dt >= 0.15 {
            let inst = done.saturating_sub(g.last_done) as f64 / dt;
            let alpha = 1.0 - (-dt / 10.0).exp();
            g.rate_ema = if g.rate_ema == 0.0 {
                inst
            } else {
                g.rate_ema + alpha * (inst - g.rate_ema)
            };
            g.last_t = now;
            g.last_done = done;
        }
        let files = g.st.files.max(0) as u64;
        let total: u64 = if g.walk_done {
            files + g.extra_total
        } else if g.mft_records > 0 {
            let dirs = g.st.dirs.max(0) as u64;
            let frac = if files + dirs >= 2000 {
                files as f64 / (files + dirs) as f64
            } else {
                0.85
            };
            let est = (g.mft_records as f64 * frac) as u64;
            est.max(files + files / 20 + 1000) + g.extra_total
        } else {
            0
        };
        if total == 0 {
            return (0, -1.0);
        }
        let remaining = total.saturating_sub(done);
        if g.walk_done && remaining == 0 && last {
            return (total as i64, 0.0);
        }
        if g.rate_ema < 0.5 || now - g.t_start < 2.0 || done < 50 {
            return (total as i64, -1.0);
        }
        let eta = remaining as f64 / g.rate_ema;
        (total as i64, eta.clamp(0.0, 7.0 * 86400.0))
    }

    fn excluded(&self, p: &str) -> bool {
        let np = path_norm(p);
        for e in &self.exclude {
            if np == *e {
                return true;
            }
            if np.len() > e.len() && np.starts_with(e.as_str()) && np.as_bytes()[e.len()] as char == SEP {
                return true;
            }
        }
        false
    }

    fn put(&self, it: Item) {
        let mut g = lk(&self.q);
        while g.q.len() >= 4000 && !g.quit {
            g = self.qspace.wait(g).unwrap_or_else(|e| e.into_inner());
        }
        g.q.push_back(it);
        g.pending += 1;
        self.qcv.notify_one();
    }

    fn wait_idle(&self) {
        let mut g = lk(&self.q);
        while g.pending != 0 {
            g = self.qdone.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn worker(&self) {
        #[cfg(windows)]
        {
            use windows::Win32::System::Threading::{
                GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL,
            };
            // SAFETY: geçerli iş parçacığı sözde tanıtıcısı.
            unsafe {
                let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
            }
        }
        loop {
            let it = {
                let mut g = lk(&self.q);
                loop {
                    if let Some(it) = g.q.pop_front() {
                        self.qspace.notify_one();
                        break Some(it);
                    }
                    if g.quit {
                        break None;
                    }
                    g = self.qcv.wait(g).unwrap_or_else(|e| e.into_inner());
                }
            };
            let Some(it) = it else {
                return;
            };
            if !self.stopped() {
                let _ = catch_unwind(AssertUnwindSafe(|| self.check_file(&it)));
            }
            lk(&self.sh).done += 1;
            self.ui(false);
            let mut g = lk(&self.q);
            g.pending = g.pending.saturating_sub(1);
            if g.pending == 0 {
                self.qdone.notify_all();
            }
        }
    }

    fn with_workers(&self, body: impl FnOnce()) {
        lk(&self.q).quit = false;
        std::thread::scope(|sc| {
            for _ in 0..self.workers {
                let _ = std::thread::Builder::new()
                    .stack_size(16 << 20)
                    .spawn_scoped(sc, || self.worker());
            }
            let _ = catch_unwind(AssertUnwindSafe(body));
            {
                let mut g = lk(&self.q);
                g.quit = true;
                if self.stopped() {
                    let n = g.q.len();
                    g.pending = g.pending.saturating_sub(n);
                    g.q.clear();
                }
            }
            self.qcv.notify_all();
            self.qspace.notify_all();
        });
    }

    fn heavy_acquire(&self, need: u64) -> bool {
        if need > self.plan.budget {
            return false;
        }
        {
            let mut g = lk(&self.heavy);
            while g.0 >= self.plan.max_heavy || (g.0 > 0 && g.1 + need > self.plan.budget) {
                if self.stopped() {
                    return false;
                }
                g = self
                    .hcv
                    .wait_timeout(g, Duration::from_millis(200))
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
            g.0 += 1;
            g.1 += need;
        }
        let want = need + (128 << 20);
        let mut i = 0;
        while i < 50 && avail_phys() < want && !self.stopped() {
            std::thread::sleep(Duration::from_millis(200));
            i += 1;
        }
        if self.stopped() || avail_phys() < want {
            self.heavy_release(need);
            return false;
        }
        true
    }

    fn heavy_release(&self, need: u64) {
        {
            let mut g = lk(&self.heavy);
            g.0 -= 1;
            g.1 = g.1.saturating_sub(need);
        }
        self.hcv.notify_all();
    }

    fn rd(&self, p: &str, limit: i64, off: i64) -> Option<Bytes> {
        let d = read_file(p, limit, off);
        if d.is_none() {
            lk(&self.sh).st.denied += 1;
        }
        d
    }

    fn walk(&self) {
        let mut stack: Vec<String> = self.roots.clone();
        while !stack.is_empty() && !self.stopped() {
            let Some(d) = stack.pop() else {
                break;
            };
            if self.excluded(&d) {
                continue;
            }
            {
                let mut g = lk(&self.sh);
                g.cur_dir = d.clone();
                g.st.dirs += 1;
            }
            let mut ents: Vec<DirEntry> = Vec::new();
            if !list_dir(&d, &mut ents) {
                lk(&self.sh).st.denied += 1;
                continue;
            }
            for e in &ents {
                if self.stopped() {
                    break;
                }
                if e.is_link {
                    continue;
                }
                if e.is_dir {
                    if e.attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                        continue;
                    }
                    if disk_skip_dir(&e.path) {
                        lk(&self.sh).st.skipped_sys_dirs += 1;
                        stack.extend(disk_skip_keep_under(&e.path));
                        continue;
                    }
                    stack.push(e.path.clone());
                    continue;
                }
                if !e.is_file {
                    continue;
                }
                {
                    let mut g = lk(&self.sh);
                    g.st.files += 1;
                    if e.attrs & CLOUD_ONLY_ATTRS != 0 {
                        g.st.cloud += 1;
                        g.skipped_walk += 1;
                        continue;
                    }
                    if e.size < 30 || e.size > MAX_FILE {
                        g.skipped_walk += 1;
                        continue;
                    }
                }
                self.put(Item {
                    path: e.path.clone(),
                    size: e.size,
                    reason: String::new(),
                });
            }
            self.ui(false);
        }
    }

    fn system_dir(&self, p: &str) -> bool {
        #[cfg(windows)]
        {
            let mut sr = env("SystemRoot");
            if sr.is_empty() {
                sr = "C:\\Windows".to_string();
            }
            let d = format!("{}\\", path_norm(&sr));
            starts(&path_norm(p), &d)
        }
        #[cfg(not(windows))]
        {
            let _ = p;
            false
        }
    }

    #[cfg(windows)]
    fn scan_ads(&self, path: &str, streams: &[(String, i64)]) {
        for s in streams {
            if self.stopped() || s.1 < 30 || (s.1 as u64) > MAX_FILE {
                continue;
            }
            let spath = format!("{}:{}", path, s.0);
            {
                let mut g = lk(&self.sh);
                if !g.seen_paths.insert(path_hash(&path_normcase(&spath))) {
                    continue;
                }
            }
            let Some(data) = self.rd(&spath, -1, 0) else {
                continue;
            };
            if data.is_empty() {
                continue;
            }
            let label = format!("{}  (gizli veri akışı -> :{})", path, s.0);
            let reason = "NTFS alternatif veri akışı (dosyanın içinde gizlenmiş ikinci içerik)";
            let kind = sniff_kind(&data[..data.len().min(512)]);
            if kind == "class" {
                self.add_loose(&label, Some(&data), "", reason, true);
            } else if data.starts_with(b"MZ") {
                self.scan_pe(&label, &data, ".ads");
            } else if !kind.is_empty() {
                self.route(&label, &data, 1, ".ads", reason, "", reason);
            } else {
                self.scan_encoded(&label, &data, &label);
            }
        }
    }

    fn check_file(&self, it: &Item) {
        let path = it.path.as_str();
        let size = it.size;
        let mut reason = it.reason.clone();
        if self.excluded(path) {
            return;
        }
        {
            let mut g = lk(&self.sh);
            if !g.seen_paths.insert(path_hash(&path_normcase(path))) {
                return;
            }
        }
        let low = py_lower(path);
        let name = path_basename(&low);
        let ext = path_splitext(&name).1;
        let mut head: Bytes = Vec::new();
        let mut tail: Bytes = Vec::new();
        let mut streams: Vec<(String, i64)> = Vec::new();
        if !read_head_tail_streams(
            path,
            512,
            if size > 1024 { 4096 } else { 0 },
            &mut head,
            &mut tail,
            &mut streams,
        ) {
            lk(&self.sh).st.denied += 1;
            return;
        }
        if !streams.is_empty() {
            let _ = catch_unwind(AssertUnwindSafe(|| self.scan_ads(path, &streams)));
        }
        if head.starts_with(b"PK\x03\x04") {
            tail.clear(); // ZIP'te son parça kullanılmaz
        }
        let mut kind = sniff_kind(&head);
        if kind == "gz" && is_log_path(path) {
            kind = "";
        }
        let compressed = kind == "gz" || kind == "xz" || kind == "bz2";
        let tail_pk = memchr::memmem::find(&tail, b"PK\x05\x06").is_some()
            || (!tail.is_empty() && memchr::memmem::find(&tail, b"PK\x01\x02").is_some());
        let big_plain = kind.is_empty() && size >= HEAVY_BYTES && !tail_pk;
        let container = compressed || kind == "rar" || kind == "libarch" || kind == "7z" || kind == "tar";
        let heavy = (size >= HEAVY_BYTES && !big_plain) || container; // küçük ama aşırı sıkıştırılmış arşiv (bomba) de belleği şişirebilir
        let mut hold = HeavyHold {
            s: self,
            on: false,
            need: 0,
        };
        if heavy {
            let need = if container {
                size.min(MAX_FILE) + inner_cap() * 2
            } else {
                size.min(MAX_FILE) * 2
            } + (64 << 20);
            hold.need = need;
            if !self.heavy_acquire(need) {
                if !self.stopped() {
                    lk(&self.sh).st.skipped_mem += 1;
                }
                return;
            }
            hold.on = true;
        }
        if kind == "rar" || kind == "libarch" {
            if let Some(exp) = expected_ext(kind) {
                if !ends_any(&low, exp) && !(kind == "rar" && ends(&low, ".rar")) {
                    let note = format!(
                        "Kapsayıcı arşiv '{}' uzantısıyla gizlenmiş: {}",
                        short_ext(&ext),
                        path_basename(path)
                    );
                    reason = if reason.is_empty() {
                        note
                    } else {
                        format!("{} | {}", reason, note)
                    };
                }
            }
            self.open_container(path, &[], path, 0, &reason);
            return;
        }
        if kind == "class" {
            self.add_loose(path, None, path, &reason, false);
            return;
        }
        if !kind.is_empty() {
            if let Some(exp) = expected_ext(kind) {
                if !ends_any(&low, exp) {
                    let note = format!(
                        "Kapsayıcı {} arşivi '{}' uzantısıyla gizlenmiş: {}",
                        upper_ascii(kind),
                        short_ext(&ext),
                        path_basename(path)
                    );
                    reason = if reason.is_empty() {
                        note
                    } else {
                        format!("{} | {}", reason, note)
                    };
                }
            }
            if kind == "gz" || kind == "xz" || kind == "bz2" {
                let first = self.rd(path, 256 * 1024, 0);
                let mut pk: Bytes = Vec::new();
                match first {
                    Some(f) if !f.is_empty() && peek_decompress(kind, &f, &mut pk) && !sniff_kind(&pk).is_empty() => {}
                    _ => return,
                }
            }
            if let Some(data) = self.rd(path, -1, 0) {
                if !data.is_empty() {
                    self.route(path, &data, 0, &ext, &reason, path, "");
                }
            }
            return;
        }
        if memchr::memmem::find(&tail, b"PK\x05\x06").is_some()
            || (!tail.is_empty() && memchr::memmem::find(&tail, b"PK\x01\x02").is_some())
        {
            let data = self.rd(path, -1, 0);
            if let Some(d) = &data {
                if !d.is_empty() && embedded_java_zip(d) {
                    self.scan_archive(
                        path,
                        d,
                        &format!("başka bir dosyanın ({}) sonuna gömülmüş Java arşivi", short_ext(&ext)),
                        &reason,
                        &ext,
                        true,
                    );
                }
                if !d.is_empty() && head.starts_with(b"MZ") {
                    self.scan_pe(path, d, &ext);
                }
            }
            return;
        }
        if head.starts_with(b"MZ") && !self.system_dir(path) {
            let mut data: Option<Bytes> = None;
            if size <= MAX_PE {
                data = self.rd(path, -1, 0);
            } else {
                let a = read_file(path, 4 << 20, 0);
                let b = read_file(path, 1 << 20, (size - (1 << 20)) as i64);
                if let Some(mut a) = a {
                    if let Some(b) = b {
                        a.extend_from_slice(&b);
                    }
                    data = Some(a);
                }
            }
            if let Some(d) = data {
                if !d.is_empty() {
                    self.scan_pe(path, &d, &ext);
                }
            }
            return;
        }
        if size <= MAX_TEXT
            && !is_log_path(path)
            && (in_l(&ext, SCRIPT_EXT) || (in_l(&ext, CONFIG_EXT) && is_mc_path(path)))
        {
            self.scan_text(path);
            return;
        }
        if size <= MAX_ENCODED && !is_log_path(path) && looks_encoded(&head) {
            if let Some(raw) = self.rd(path, -1, 0) {
                if !raw.is_empty() {
                    lk(&self.sh).st.texts += 1;
                    self.scan_encoded(path, &raw, "");
                }
            }
        }
    }

    fn scan_pe(&self, label: &str, data: &[u8], ext: &str) {
        if !self.self_exe.is_empty() && path_norm(label) == path_norm(&self.self_exe) {
            return;
        }
        let mut ex = String::new();
        let mut ev: StrList = Vec::new();
        if !pe_injector_check(data, &mut ex, &mut ev) {
            return;
        }
        let mut res = ScanResult {
            file: label.to_string(),
            name: path_basename(label),
            sha256: sha256_hex(data),
            size: data.len() as u64,
            verdict: "KESIN HILE".to_string(),
            rank: 3,
            kind: "Yerel program (PE)".to_string(),
            ..Default::default()
        };
        if ext != ".exe" && ext != ".dll" {
            res.notes.push(format!(
                "Dosya uzantısı '{}' ama içeriği bir Windows programı/DLL.",
                ext
            ));
        }
        let mut f = Finding {
            key: "native_injector".to_string(),
            label: "Java'ya (Minecraft) kod enjekte eden yerel program".to_string(),
            category: "KESIN_HILE".to_string(),
            explain: ex,
            ..Default::default()
        };
        let mut u = Unit {
            unit: "dosya".to_string(),
            ..Default::default()
        };
        let mut g: RowGroup = Vec::new();
        for e in ev.iter().take(8) {
            g.push(Row {
                kind: "hint".to_string(),
                detail: e.clone(),
                cls: "-".to_string(),
                concept: "-".to_string(),
            });
        }
        u.groups.push(g);
        f.units.push(u);
        res.findings.push(f);
        let loc = location_note(label);
        if !loc.is_empty() {
            res.notes.insert(0, loc);
        }
        self.add_flagged(res);
    }

    fn add_flagged(&self, res: ScanResult) -> usize {
        let copy = self.on_found.is_some().then(|| res.clone());
        let idx = {
            let mut sh = lk(&self.sh);
            let idx = sh.flagged.len();
            sh.flagged.push(res);
            sh.st.flagged += 1;
            idx
        };
        self.notify_found(copy);
        idx
    }

    fn notify_found(&self, copy: Option<ScanResult>) {
        if let (Some(cb), Some(r)) = (&self.on_found, copy) {
            let _ = catch_unwind(AssertUnwindSafe(|| cb(&r)));
        }
    }

    fn open_container(&self, label: &str, mem: &[u8], disk_path: &str, depth: i32, reason: &str) {
        lk(&self.sh).st.containers += 1;
        let mut n = 0;
        let ai = archive_iterate(
            mem,
            disk_path,
            &mut |name: &str, data: &mut Bytes| {
                if self.stopped() {
                    return false;
                }
                n += 1;
                self.route_member(label, name, data, depth, reason);
                true
            },
            inner_cap(),
            Some(&*self.stop),
        );
        if ai.no_mem && n == 0 {
            lk(&self.sh).st.skipped_mem += 1;
        } else if !ai.opened || (n == 0 && !ai.encrypted && ai.names.is_empty()) {
            lk(&self.sh).st.unopened += 1;
        }
    }

    fn route_member(&self, clabel: &str, mname: &str, data: &[u8], depth: i32, reason: &str) {
        let ext = path_splitext(&py_lower(mname)).1;
        self.route(
            &format!("{} !/ {}", clabel, mname),
            data,
            depth + 1,
            &ext,
            reason,
            "",
            "",
        );
    }

    fn route(&self, label: &str, data: &[u8], depth: i32, ext: &str, reason: &str, disk_path: &str, how_in: &str) {
        if depth > MAX_DEPTH || self.stopped() || data.is_empty() {
            return;
        }
        let mut how = how_in.to_string();
        let kind = sniff_kind(&data[..data.len().min(512)]);
        if kind == "zip" {
            if how.is_empty() && !in_l(ext, ARCHIVE_EXT) && !ends(&py_lower(label), ".jar.disabled") {
                how = format!("uzantısı gizlenmiş arşiv ({})", short_ext(ext));
            }
            self.scan_archive(label, data, &how, reason, ext, depth > 0 && !how.is_empty());
            return;
        }
        if kind == "gz" || kind == "xz" || kind == "bz2" {
            let mut pk: Bytes = Vec::new();
            if !peek_decompress(kind, data, &mut pk) || sniff_kind(&pk).is_empty() {
                return;
            }
            let mut inner: Bytes = Vec::new();
            bounded_decompress(kind, data, &mut inner);
            if !inner.is_empty() && inner.len() as u64 <= inner_cap() {
                lk(&self.sh).st.containers += 1;
                let ik = sniff_kind(&inner[..inner.len().min(512)]);
                if !ik.is_empty() {
                    self.route(
                        label,
                        &inner,
                        depth + 1,
                        "",
                        reason,
                        "",
                        &format!(
                            "{} içine gizlenmiş {}",
                            kind,
                            if ik != "class" { "arşiv" } else { "Java sınıfı" }
                        ),
                    );
                }
            }
            return;
        }
        if kind == "tar" || kind == "7z" || kind == "rar" || kind == "libarch" {
            self.open_container(label, data, "", depth, reason);
            return;
        }
        if kind == "class" {
            self.add_loose(label, Some(data), disk_path, reason, depth > 0);
            return;
        }
        let tail = &data[data.len().saturating_sub(4096)..];
        if memchr::memmem::find(tail, b"PK\x05\x06").is_some() && embedded_java_zip(data) {
            let h = if how.is_empty() {
                format!("başka bir dosyanın ({}) sonuna gömülmüş Java arşivi", short_ext(ext))
            } else {
                how
            };
            self.scan_archive(label, data, &h, reason, ext, true);
        }
    }

    fn add_loose(&self, label: &str, data: Option<&[u8]>, disk_path: &str, reason: &str, container: bool) {
        let own: Option<Bytes>;
        let body: &[u8] = match data {
            Some(d) => d,
            None => {
                own = self.rd(disk_path, -1, 0);
                match &own {
                    Some(o) if !o.is_empty() => o,
                    _ => return,
                }
            }
        };
        let cname = match parse_class(body) {
            Ok(ci) => ci.name.clone(),
            Err(_) => return,
        };
        if cname.is_empty() {
            return;
        }
        let norm = replace_all(label, "\\", "/");
        let hidden = !ends(&py_lower(&norm), ".class");
        let stem: String = if !hidden {
            norm.get(..norm.len().saturating_sub(6)).unwrap_or(&norm).to_string()
        } else {
            path_splitext(&norm).0
        };
        let mut root: String;
        if (!hidden && ends(&stem, &format!("/{}", cname))) || stem == cname {
            let cut = stem.get(..stem.len().saturating_sub(cname.len())).unwrap_or("");
            root = rstrip(cut, "/");
            if root.is_empty() {
                root = ".".to_string();
            }
        } else {
            root = path_dirname(&norm);
            if root.is_empty() {
                root = ".".to_string();
            }
        }
        let entry = if !hidden {
            format!("{}.class", cname)
        } else {
            let e2 = path_splitext(&norm).1;
            format!("{}{}", cname, if e2.is_empty() { ".bin".to_string() } else { e2 })
        };
        let on_disk = !container && !disk_path.is_empty() && label == disk_path;
        let mut sh = lk(&self.sh);
        if on_disk {
            if sh.loose_files >= MAX_LOOSE_FILES {
                sh.st.skipped_loose += 1;
                return;
            }
        } else if sh.loose_bytes + body.len() as u64 > loose_cap() {
            sh.st.skipped_loose += 1;
            return;
        }
        let gi = match sh.loose_idx.get(&root) {
            Some(&i) => i,
            None => {
                let i = sh.loose.len();
                sh.loose_idx.insert(root.clone(), i);
                let l = Loose {
                    disk_root: if container { String::new() } else { root.clone() },
                    ..Default::default()
                };
                sh.loose.push((root, l));
                i
            }
        };
        let mut d_files = 0u64;
        let mut d_bytes_add = 0u64;
        let mut d_bytes_sub = 0u64;
        {
            let g = &mut sh.loose[gi].1;
            if on_disk {
                if let Some(&fi) = g.file_idx.get(&entry) {
                    g.files[fi].1 = disk_path.to_string(); // aynı sınıf: son görülen kazanır (eskisiyle aynı)
                } else {
                    g.file_idx.insert(entry.clone(), g.files.len());
                    g.files.push((entry, disk_path.to_string()));
                    d_files = 1;
                }
            } else if let Some(&ii) = g.item_idx.get(&entry) {
                d_bytes_sub = g.items[ii].1.len() as u64;
                d_bytes_add = body.len() as u64;
                g.items[ii].1 = body.to_vec();
            } else {
                g.item_idx.insert(entry.clone(), g.items.len());
                g.items.push((entry, body.to_vec()));
                d_bytes_add = body.len() as u64;
            }
            if !reason.is_empty() {
                g.reasons.insert(reason.to_string());
            }
        }
        sh.loose_files += d_files;
        sh.loose_bytes = sh.loose_bytes - d_bytes_sub.min(sh.loose_bytes) + d_bytes_add;
    }

    fn process_loose(&self) {
        let mut groups: Vec<(String, Loose)> = std::mem::take(&mut lk(&self.sh).loose);
        for rg in groups.iter_mut() {
            if self.stopped() {
                break;
            }
            let root = rg.0.clone();
            let g = &mut rg.1;
            if g.items.is_empty() && g.files.is_empty() {
                continue;
            }
            lk(&self.sh).st.loose_groups += 1;
            let mut side_names: StrList = Vec::new();
            let mut side_data: Vec<Bytes> = Vec::new();
            let dr = g.disk_root.clone();
            if !dr.is_empty() && is_dir(&dr) {
                for side in [
                    "fabric.mod.json",
                    "quilt.mod.json",
                    "plugin.yml",
                    "paper-plugin.yml",
                    "bungee.yml",
                    "velocity-plugin.json",
                    "META-INF/MANIFEST.MF",
                    "META-INF/mods.toml",
                    "META-INF/neoforge.mods.toml",
                ] {
                    let sp = path_join(&dr, side);
                    let sz = file_size(&sp);
                    if is_file(&sp) && sz.is_some_and(|s| s < 2_000_000) {
                        if let Some(b) = self.rd(&sp, -1, 0) {
                            if !b.is_empty() {
                                side_names.push(side.to_string());
                                side_data.push(b);
                            }
                        }
                    }
                }
                for fname in listdir_names(&dr) {
                    if ends(&fname, ".json") && (has(&fname, "mixin") || has(&fname, "refmap")) {
                        if let Some(b) = self.rd(&path_join(&dr, &fname), -1, 0) {
                            if !b.is_empty() {
                                side_names.push(fname.clone());
                                side_data.push(b);
                            }
                        }
                    }
                }
            }
            if g.files.len() > 1 {
                g.files.sort_by(|a, b| a.0.cmp(&b.0));
            }
            let mut disp = path_basename(&rstrip(&root, "/\\"));
            if disp.is_empty() {
                disp = root.clone();
            }
            let mut fi = 0usize;
            let mut part = 0;
            let mut first = true;
            while (first || fi < g.files.len()) && !self.stopped() {
                let mut zw = ZipWriter::new();
                let mut count = 0usize;
                let mut cbytes: u64 = 0;
                if first {
                    for kv in &g.items {
                        zw.add(&kv.0, &kv.1);
                        cbytes += kv.1.len() as u64;
                        count += 1;
                    }
                    {
                        let mut sh = lk(&self.sh);
                        sh.loose_bytes -= cbytes.min(sh.loose_bytes);
                    }
                    g.items = Vec::new();
                    g.item_idx = HashMap::new();
                    first = false;
                }
                while fi < g.files.len() && !self.stopped() {
                    if count > 0 && cbytes >= chunk_cap() {
                        break; // parça doldu: kalan sınıflar sonraki parçada
                    }
                    if let Some(b) = self.rd(&g.files[fi].1, MAX_PE as i64, 0) {
                        if !b.is_empty() {
                            cbytes += b.len() as u64;
                            zw.add(&g.files[fi].0, &b);
                            count += 1;
                        }
                    }
                    fi += 1;
                }
                if count == 0 {
                    continue;
                }
                part += 1;
                for i in 0..side_names.len() {
                    zw.add(&side_names[i], &side_data[i]);
                }
                let chunked = part > 1 || fi < g.files.len();
                let data = zw.finish();
                let label = format!(
                    "{}  (jar'a paketlenmemiş {} Java sınıfı){}",
                    root,
                    count,
                    if chunked {
                        format!("  [büyük klasör, parça {}]", part)
                    } else {
                        String::new()
                    }
                );
                let res = self.analyze(&disp, &data, &label);
                drop(data);
                if let Some(mut res) = res {
                    if res.rank > 0 {
                        res.notes.insert(
                            0,
                            "Gizleme: kod jar dosyası olarak değil, klasörde açık sınıflar halinde duruyor \
                             (doğrudan -cp / özel yükleyici ile çalıştırılabilir)."
                                .to_string(),
                        );
                        let mut rs: Vec<&String> = g.reasons.iter().collect();
                        rs.sort_by(|a, b| katla(a).cmp(&katla(b)).then_with(|| a.cmp(b)));
                        for r in rs {
                            res.notes.insert(0, r.clone());
                        }
                        let loc = location_note(&root);
                        if !loc.is_empty() {
                            res.notes.insert(0, loc);
                        }
                        self.add_flagged(res);
                    }
                }
            }
            g.files = Vec::new();
            g.file_idx = HashMap::new();
        }
        let mut sh = lk(&self.sh);
        let newer = std::mem::take(&mut sh.loose);
        let mut all = groups;
        for (r, l) in newer {
            if let Some(pos) = all.iter().position(|x| x.0 == r) {
                let dst = &mut all[pos].1;
                dst.items.extend(l.items);
                dst.files.extend(l.files);
                dst.item_idx.extend(l.item_idx);
                dst.file_idx.extend(l.file_idx);
                dst.reasons.extend(l.reasons);
            } else {
                all.push((r, l));
            }
        }
        sh.loose_idx = all.iter().enumerate().map(|(i, x)| (x.0.clone(), i)).collect();
        sh.loose = all;
    }

    fn analyze(&self, display: &str, data: &[u8], label: &str) -> Option<ScanResult> {
        let mut r = scan_jar_bytes(display, data, 0, label, true, Some(&*self.stop));
        if self.stopped() {
            return None;
        }
        apply_disk_filter(&mut r);
        Some(r)
    }

    fn scan_archive(&self, label: &str, data: &[u8], how: &str, reason: &str, ext: &str, strong: bool) {
        let _ = (ext, strong);
        lk(&self.sh).st.archives += 1;
        let sha = sha256_hex(data);
        let mut waiting = false;
        {
            let mut sh = lk(&self.sh);
            if let Some(c) = sh.cache.get(&sha).copied() {
                if let Some(i) = c {
                    sh.flagged[i].also_at.push(label.to_string());
                }
                return;
            }
            if sh.inflight.contains(&sha) {
                waiting = true;
            } else {
                sh.inflight.insert(sha.clone());
            }
        }
        if waiting {
            loop {
                if !lk(&self.sh).inflight.contains(&sha) || self.stopped() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let mut sh = lk(&self.sh);
            if let Some(Some(i)) = sh.cache.get(&sha).copied() {
                sh.flagged[i].also_at.push(label.to_string());
            }
            return;
        }
        let last = split(label, " !/ ", -1).pop().unwrap_or_default();
        let mut disp = path_basename(&last);
        if disp.is_empty() {
            disp = label.to_string();
        }
        let res = catch_unwind(AssertUnwindSafe(|| self.analyze(&disp, data, label))).unwrap_or(None);
        let Some(mut res) = res else {
            lk(&self.sh).inflight.remove(&sha);
            return;
        };
        if !how.is_empty() {
            res.notes.insert(0, format!("Gizleme: {}.", how));
        }
        if !reason.is_empty() {
            res.notes.insert(0, reason.to_string());
        }
        let loc = if res.rank > 0 {
            location_note(label)
        } else {
            String::new()
        };
        let mut copy: Option<ScanResult> = None;
        {
            let mut sh = lk(&self.sh);
            if res.rank > 0 {
                if !loc.is_empty() {
                    res.notes.insert(0, loc);
                }
                if self.on_found.is_some() {
                    copy = Some(res.clone());
                }
                let idx = sh.flagged.len();
                sh.flagged.push(res);
                sh.st.flagged += 1;
                sh.cache.insert(sha.clone(), Some(idx));
            } else {
                sh.cache.insert(sha.clone(), None);
            }
            sh.inflight.remove(&sha);
        }
        self.notify_found(copy);
    }

    fn scan_encoded(&self, path: &str, raw: &[u8], label_in: &str) {
        if self.stopped() || raw.is_empty() || raw.len() as u64 > MAX_ENCODED {
            return;
        }
        let label = if label_in.is_empty() { path } else { label_in };
        let mut seen = 0;
        let mut done: HashSet<String> = HashSet::new();
        let mut quit = false;
        for kind in ["b64", "b64url", "hex"] {
            if quit {
                break;
            }
            find_runs(raw, kind, &mut |blob: &[u8]| {
                if self.stopped() || seen >= 12 {
                    quit = true;
                    return false;
                }
                if blob.len() < 1200 {
                    return true;
                }
                let mut full: Bytes = Vec::new();
                if !decode_payload(kind, blob, &mut full) {
                    return true;
                }
                if full.len() < 64 || full.len() as u64 > inner_cap() {
                    return true;
                }
                if sniff_kind(&full[..full.len().min(512)]).is_empty() && !full.starts_with(b"MZ") {
                    return true;
                }
                let h = sha256_hex(&full);
                if !done.insert(h) {
                    return true;
                }
                seen += 1;
                let enc = match kind {
                    "b64" => "base64",
                    "b64url" => "base64url",
                    _ => "onaltılık (hex)",
                };
                let sub = format!("{}  (metin içinde {} kodlanmış)", label, enc);
                let how = format!("metnin içine {} olarak kodlanmış", enc);
                if full.starts_with(b"MZ") {
                    self.scan_pe(&sub, &full, ".bin");
                } else {
                    self.route(&sub, &full, 1, ".bin", &how, "", &how);
                }
                true
            });
        }
    }

    fn scan_text(&self, path: &str) {
        let Some(raw) = self.rd(path, -1, 0) else {
            return;
        };
        if raw.is_empty() {
            return;
        }
        lk(&self.sh).st.texts += 1;
        self.scan_encoded(path, &raw, "");
        let bom = raw.starts_with(b"\xff\xfe") || raw.starts_with(b"\xfe\xff");
        if memchr::memchr(0, &raw[..raw.len().min(2048)]).is_some() && !bom {
            return;
        }
        let txt = if bom { utf16_auto(&raw, 1) } else { utf8_decode(&raw, 1) };
        let lowtxt = py_lower(&txt);
        let lpath = py_lower(&replace_all(path, "\\", "/"));
        let name = rpartition_tail(&lpath, "/");
        let ext = path_splitext(&name).1;
        let mc_ctx = is_mc_path(path) || has_any(&lowtxt, MC_CONTENT_HINTS);
        let follow_ok = mc_ctx
            && !has(&lpath, "/config/")
            && (ext == ".bat"
                || ext == ".cmd"
                || ext == ".ps1"
                || ext == ".vbs"
                || has_any(&name, LAUNCHER_FILE_HINTS));
        let base_dir = path_dirname(path);
        for line in splitlines(&txt) {
            let ll = py_lower(&line);
            if has(&ll, "-javaagent") && mc_ctx {
                re_agent().finditer(line.as_bytes(), &mut |m| {
                    let agent = pystrip(&m.group(1));
                    if has_any(&py_lower(&agent), LEGIT_AGENT_HINTS) {
                        return true;
                    }
                    self.follow(
                        &agent,
                        &base_dir,
                        &format!("Başlatma dosyasında -javaagent ile gösterilen dosya: {}", path),
                    );
                    true
                });
            }
            if has(&ll, "addmods") {
                re_addmods().finditer(line.as_bytes(), &mut |m| {
                    let val = pystrip(&m.group(1));
                    #[cfg(windows)]
                    let parts: StrList = split(&val, ";", -1);
                    #[cfg(not(windows))]
                    let parts: StrList = split(&val, ";", -1).iter().flat_map(|a| split(a, ":", -1)).collect();
                    for part in &parts {
                        if !pystrip(part).is_empty() {
                            self.follow(
                                &pystrip(part),
                                &base_dir,
                                &format!("addMods ile yüklenen konum: {}", path),
                            );
                        }
                    }
                    true
                });
            }
            if follow_ok && has(&ll, ".jar") {
                re_jarref().finditer(line.as_bytes(), &mut |m| {
                    let g = if m.ok(1) { m.group(1) } else { m.group(2) };
                    self.follow(
                        &pystrip(&g),
                        &base_dir,
                        &format!("Başlatma dosyasında gösterilen jar: {}", path),
                    );
                    true
                });
            }
        }
    }

    fn follow(&self, target: &str, base_dir: &str, reason: &str) {
        let mut p = strip(&pystrip(target), "\"");
        if !path_isabs(&p) {
            p = path_join(base_dir, &p);
        }
        p = path_normpath(&p);
        let mut add: Vec<Item> = Vec::new();
        if is_file(&p) {
            let sz = file_size(&p);
            add.push(Item {
                path: p.clone(),
                size: sz.unwrap_or(0),
                reason: reason.to_string(),
            });
        } else if is_dir(&p) {
            walk_files(
                &p,
                &mut |fp: &str| {
                    if let Some(sz) = file_size(fp) {
                        add.push(Item {
                            path: fp.to_string(),
                            size: sz,
                            reason: reason.to_string(),
                        });
                    }
                },
                200000,
            );
        }
        lk(&self.sh).followups.extend(add);
    }

    fn init_estimate(&self, t0: f64) {
        let mut mft: u64 = 0;
        let mut ok = !self.roots.is_empty();
        for r in &self.roots {
            match volume_letter(r).and_then(mft_records) {
                Some(n) => mft += n,
                None => ok = false,
            }
        }
        let mut g = lk(&self.sh);
        g.t_start = t0;
        g.mft_records = if ok { mft } else { 0 };
    }

    fn snapshot(&self) -> (DiskStats, Vec<ResultP>) {
        let sh = lk(&self.sh);
        let res: Vec<ResultP> = sh.flagged.iter().map(|r| Arc::new(r.clone())).collect();
        (sh.st.clone(), res)
    }

    pub fn run(&mut self) -> DiskResult {
        let t0 = now_epoch();
        self.init_estimate(t0);
        self.with_workers(|| {
            self.walk();
            lk(&self.sh).walk_done = true;
            self.ui(true);
            self.wait_idle();
            for _round in 0..3 {
                let fu: Vec<Item> = std::mem::take(&mut lk(&self.sh).followups);
                if fu.is_empty() || self.stopped() {
                    break;
                }
                for it in fu {
                    if !self.excluded(&it.path) && it.size >= 30 && it.size <= MAX_FILE {
                        lk(&self.sh).extra_total += 1;
                        self.put(it);
                    }
                }
                self.wait_idle();
            }
            if !self.stopped() {
                self.process_loose();
            }
        });
        lk(&self.sh).walk_done = true;
        self.ui(true);
        let (st, mut results) = self.snapshot();
        let mut r = DiskResult {
            roots: self.roots.clone(),
            stats: st,
            duration: now_epoch() - t0,
            stopped: self.stopped(),
            ..Default::default()
        };
        results.sort_by_cached_key(|a| (std::cmp::Reverse(a.rank), py_lower(&a.file)));
        r.results = results;
        r.text_hits = Vec::new();
        r
    }

    pub fn scan_paths(&mut self, paths: &[String], reason: &str) -> DiskResult {
        let t0 = now_epoch();
        self.init_estimate(t0);
        self.with_workers(|| {
            for p in paths {
                let Some(sz) = file_size(p) else {
                    continue;
                };
                if (30..=MAX_FILE).contains(&sz) {
                    lk(&self.sh).extra_total += 1;
                    self.put(Item {
                        path: p.clone(),
                        size: sz,
                        reason: reason.to_string(),
                    });
                }
            }
            lk(&self.sh).walk_done = true;
            self.wait_idle();
            if !self.stopped() {
                self.process_loose();
            }
        });
        self.ui(true);
        let (st, results) = self.snapshot();
        DiskResult {
            stats: st,
            duration: now_epoch() - t0,
            results,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_turleri() {
        assert_eq!(sniff(b"PK\x03\x04abc"), "zip");
        assert_eq!(sniff(b"PK\x05\x06"), "zip");
        assert_eq!(sniff(b"\xef\xbb\xbfPK\x03\x04"), "zip");
        assert_eq!(sniff(b"\xff\xfeP\0K\0\x03\0\x04\0"), "zip");
        assert_eq!(sniff(b"\x1f\x8b\x08"), "gz");
        assert_eq!(sniff(b"\xfd7zXZ\x00x"), "xz");
        assert_eq!(sniff(b"BZh9xx"), "bz2");
        assert_eq!(sniff(b"BZh0xx"), "");
        assert_eq!(sniff(b"7z\xbc\xaf\x27\x1c"), "7z");
        assert_eq!(sniff(b"Rar!\x1a\x07\x00"), "rar");
        assert_eq!(sniff(b"\xca\xfe\xba\xbe\x00\x00\x00\x34"), "class");
        assert_eq!(sniff(b"\xca\xfe\xba\xbe\x00\x00\x00\x02"), "");
        assert_eq!(sniff(b"MSCF\0\0\0\0"), "libarch");
        assert_eq!(sniff(b"\x28\xb5\x2f\xfd"), "libarch");
        assert_eq!(sniff(b"xx-lh5-yy"), "libarch");
        assert_eq!(sniff(b"hello world"), "");
        let mut t = vec![0u8; 300];
        t[257..262].copy_from_slice(b"ustar");
        assert_eq!(sniff(&t), "tar");
    }

    #[test]
    fn base64_cozucu() {
        let mut o = Vec::new();
        assert!(b64dec(b"SGVsbG8=", false, &mut o));
        assert_eq!(o, b"Hello");
        assert!(!b64dec(b"SGVsbG8", false, &mut o));
        assert!(!b64dec(b"S", false, &mut o));
        assert!(b64dec(b"-_-_", true, &mut o));
    }

    #[test]
    fn hex_ve_yuk_cozme() {
        assert_eq!(fromhex(b"4d5a"), b"MZ");
        let mut o = Vec::new();
        assert!(decode_payload("hex", b"4d5a9000000000000000000000000000", &mut o));
        assert!(o.starts_with(b"MZ"));
        assert!(!decode_payload("hex", b"00112233445566778899aabbccddeeff", &mut o));
        let mut raw = b"PK\x03\x04".to_vec();
        raw.extend_from_slice(&[0u8; 40]);
        let enc = b64_encode(&raw);
        assert!(decode_payload("b64", enc.as_bytes(), &mut o));
        assert_eq!(o, raw);
    }

    fn b64_encode(d: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for ch in d.chunks(3) {
            let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
            s.push(A[(n >> 18) as usize & 63] as char);
            s.push(A[(n >> 12) as usize & 63] as char);
            s.push(if ch.len() > 1 {
                A[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            s.push(if ch.len() > 2 { A[n as usize & 63] as char } else { '=' });
        }
        s
    }

    #[test]
    fn kodlanmis_dizi_bulma() {
        let mut v = vec![b'A'; 1500];
        v.extend_from_slice(b" ! ");
        let mut n = 0;
        find_runs(&v, "b64", &mut |b| {
            n += b.len();
            true
        });
        assert!(n >= 1500);
    }

    #[test]
    fn gorunen_metin_kodlama() {
        let s: Vec<u8> = (0..300).map(|i| b"abcdefghij"[i % 10]).collect();
        assert!(looks_encoded(&s));
        assert!(!looks_encoded(b"short"));
        assert!(!looks_encoded(&vec![b'!'; 300]));
    }

    fn collect(mem: &[u8]) -> (ArcInfo, Vec<(String, usize)>) {
        let mut got = Vec::new();
        let info = archive_iterate(
            mem,
            "",
            &mut |n, d| {
                got.push((n.to_string(), d.len()));
                true
            },
            1 << 20,
            None,
        );
        (info, got)
    }

    fn make_tar() -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (n, len) in [("a/x.bin", 100usize), ("kucuk.txt", 5), ("b.dat", 64)] {
            let data = vec![7u8; len];
            let mut h = tar::Header::new_gnu();
            h.set_size(len as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, n, &data[..]).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn tar_gezme() {
        let t = make_tar();
        let (info, got) = collect(&t);
        assert!(info.opened && !info.encrypted);
        assert_eq!(info.names, vec!["a/x.bin", "kucuk.txt", "b.dat"]);
        assert_eq!(got, vec![("a/x.bin".to_string(), 100), ("b.dat".to_string(), 64)]);
    }

    #[test]
    fn tar_gz_gezme() {
        let t = make_tar();
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(&t).unwrap();
        let gz = e.finish().unwrap();
        let (info, got) = collect(&gz);
        assert!(info.opened);
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn ham_akis_ve_bos() {
        let (info, got) = collect(b"hello hello hello hello hello hello hello");
        assert!(info.opened);
        assert_eq!(info.names, vec!["data"]);
        assert!(got.is_empty());
        let (info, _) = collect(b"");
        assert!(info.names.is_empty());
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(&[9u8; 200]).unwrap();
        let (_, got) = collect(&e.finish().unwrap());
        assert_eq!(got, vec![("data".to_string(), 200)]);
    }

    #[test]
    fn cpio_newc() {
        fn ent(name: &str, data: &[u8]) -> Vec<u8> {
            let mut v = Vec::new();
            let nm = format!("{}\0", name);
            let hdr = format!(
                "070701{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
                1,
                0o100644,
                0,
                0,
                1,
                0,
                data.len(),
                0,
                0,
                0,
                0,
                nm.len(),
                0
            );
            v.extend_from_slice(hdr.as_bytes());
            v.extend_from_slice(nm.as_bytes());
            while v.len() % 4 != 0 {
                v.push(0);
            }
            v.extend_from_slice(data);
            while v.len() % 4 != 0 {
                v.push(0);
            }
            v
        }
        let mut c = ent("f1", &[1u8; 50]);
        c.extend(ent("f2", &[2u8; 33]));
        c.extend(ent("TRAILER!!!", b""));
        let (info, got) = collect(&c);
        assert_eq!(info.names, vec!["f1", "f2"]);
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].1, 33);
    }

    #[test]
    fn ar_gezme() {
        let mut a = b"!<arch>\n".to_vec();
        for (n, d) in [("one.o/", vec![1u8; 41]), ("two.o/", vec![2u8; 60])] {
            a.extend_from_slice(
                format!("{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", n, 0, 0, 0, "100644", d.len()).as_bytes(),
            );
            a.extend_from_slice(&d);
            if d.len() % 2 == 1 {
                a.push(b'\n');
            }
        }
        let (info, got) = collect(&a);
        assert_eq!(info.names, vec!["one.o", "two.o"]);
        assert_eq!(got.iter().map(|g| g.1).collect::<Vec<_>>(), vec![41, 60]);
    }

    #[test]
    fn bozuk_girdi_panik_yok() {
        let mut t = make_tar();
        t.truncate(700);
        let _ = collect(&t);
        let _ = collect(b"7z\xbc\xaf\x27\x1c garbage garbage garbage");
        let _ = collect(b"MSCF garbage");
        let _ = collect(b"\x28\xb5\x2f\xfd garbage garbage");
        let _ = collect(b"\x04\x22\x4d\x18 garbage garbage");
        let _ = collect(b"!<arch>\nxx");
        let _ = collect(b"070701zzzz");
    }

    #[test]
    fn atlanacak_klasor_kurallari() {
        assert!(under("c:\\windows\\system32", "c:\\windows"));
        assert!(!under("c:\\windowsx", "c:\\windows"));
    }

    #[test]
    fn yol_ozeti() {
        assert_ne!(path_hash("a"), path_hash("b"));
        assert_eq!(path_hash(""), 1469598103934665603);
    }

    #[test]
    fn bellek_butcesi_olceklenir() {
        let gb = 1u64 << 30;
        let p = plan_for(4 * gb, 1 * gb);
        assert!(p.budget <= gb && p.budget >= 256 * MB);
        assert_eq!(p.max_heavy, 1);
        let p = plan_for(16 * gb, 10 * gb);
        assert_eq!(p.budget, 1024 * MB);
        assert_eq!(p.max_heavy, 2);
    }

    #[test]
    fn tahmini_sure() {
        let mut g = Shared::default();
        g.t_start = 100.0;
        assert_eq!(DiskScanner::estimate(&mut g, 105.0, false), (0, -1.0));
        g.walk_done = true;
        g.st.files = 1000;
        DiskScanner::estimate(&mut g, 105.0, false);
        g.done = 500;
        let (t, eta) = DiskScanner::estimate(&mut g, 110.0, false);
        assert_eq!(t, 1000);
        assert!(eta > 0.0 && eta < 60.0, "{eta}");
        g.done = 1000;
        assert_eq!(DiskScanner::estimate(&mut g, 111.0, true).1, 0.0);
    }

    #[test]
    fn canli_bulgu_ve_ilerleme() {
        use std::sync::atomic::AtomicUsize;
        let root = r"C:\Users\admin\Desktop\JournalScanner\build\testdisk";
        if !is_dir(root) {
            return;
        }
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = calls.clone();
        let mut ds = DiskScanner::new(
            vec![root.to_string()],
            Some(Box::new(move |_, _| {
                c2.fetch_add(1, Ordering::Relaxed);
            })),
            None,
            0,
            Vec::new(),
        );
        ds.set_on_found(Box::new(move |_| {
            n2.fetch_add(1, Ordering::Relaxed);
        }));
        let r = ds.run();
        assert_eq!(n.load(Ordering::Relaxed) as i64, r.stats.flagged);
        assert!(calls.load(Ordering::Relaxed) >= 1);
        assert_eq!(r.stats.eta_secs, 0.0);
    }
}
