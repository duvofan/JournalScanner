use crate::content::{analyze_files, content_lines, ContentVerdict};
use crate::data::{KNOWN_CLIENTS, STRONG_CHEAT_TERMS};
use crate::locations::{recycle_bin_index, recycle_lookup};
use crate::util::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

#[derive(Debug, Clone)]
pub struct JournalHit {
    pub id: String,
    pub action: String,
    pub path: String,
    pub name: String,
    pub exists: bool,
    pub in_recycle: bool,
    pub when: String,
    pub source: String,
    pub verdict: String,
    pub tag: char,
    pub reason: String,
    pub detail: Vec<String>,
}
impl Default for JournalHit {
    fn default() -> Self {
        JournalHit {
            id: String::new(),
            action: String::new(),
            path: String::new(),
            name: String::new(),
            exists: false,
            in_recycle: false,
            when: String::new(),
            source: String::new(),
            verdict: "BILGI".to_string(),
            tag: 'i',
            reason: String::new(),
            detail: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct JournalScan {
    pub ran: bool,
    pub error: String,
    pub days: i32,
    pub entries: i32,
    pub from_usn: i32,
    pub from_recent: i32,
    pub files_checked: i32,
    pub deleted: i32,
    pub kesin: i32,
    pub yasakli: i32,
    pub supheli: i32,
    pub info: i32,
    pub verdict: String,
    pub hits: Vec<JournalHit>,
    pub notes: StrList,
    pub errors: StrList,
    pub sources: StrList,
}
impl Default for JournalScan {
    fn default() -> Self {
        JournalScan {
            ran: false,
            error: String::new(),
            days: 5,
            entries: 0,
            from_usn: 0,
            from_recent: 0,
            files_checked: 0,
            deleted: 0,
            kesin: 0,
            yasakli: 0,
            supheli: 0,
            info: 0,
            verdict: "TEMIZ".to_string(),
            hits: Vec::new(),
            notes: Vec::new(),
            errors: Vec::new(),
            sources: Vec::new(),
        }
    }
}

fn jnorm_alnum(s: &str) -> String {
    let mut o = String::new();
    for &c in s.as_bytes() {
        if c.is_ascii_uppercase() {
            o.push((c + 32) as char);
        } else if c.is_ascii_lowercase() || c.is_ascii_digit() {
            o.push(c as char);
        }
    }
    o
}

fn jcheat_tokens() -> &'static BTreeSet<String> {
    static S: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
        let mut s = BTreeSet::new();
        const DENY: [&str; 11] = [
            "baritone",
            "autototem",
            "freecam",
            "nofall",
            "fullbright",
            "minimap",
            "schematica",
            "optifine",
            "sodium",
            "iris",
            "litematica",
        ];
        for kc in KNOWN_CLIENTS {
            let t = jnorm_alnum(kc.1);
            if t.len() >= 8 && !DENY.contains(&t.as_str()) {
                s.insert(t);
            }
        }
        for t in STRONG_CHEAT_TERMS {
            let n = jnorm_alnum(t);
            if n.len() >= 7 {
                s.insert(n);
            }
        }
        for e in [
            "liquidbounce",
            "wurstclient",
            "meteorclient",
            "sigmaclient",
            "novoline",
            "aristois",
            "rusherhack",
            "thunderhack",
            "futureclient",
            "impactclient",
            "vapeclient",
            "nightx",
            "doomsday",
            "exhibition",
            "entropyclient",
            "moonclient",
            "riseclient",
            "konasclient",
            "fluxclient",
            "astolfo",
            "kamiblue",
            "salhack",
            "lambdaclient",
            "pyroclient",
            "dopeclient",
            "ghostclient",
            "madebygrave",
            "argonclient",
            "cliento",
        ] {
            s.insert(e.to_string());
        }
        s
    });
    &S
}

fn jmatch_cheat_token(norm: &str) -> String {
    if norm.is_empty() {
        return String::new();
    }
    for t in jcheat_tokens() {
        if norm.contains(t.as_str()) {
            return t.clone();
        }
    }
    String::new()
}

pub fn lnk_target_path(data: &[u8]) -> String {
    let n = data.len();
    if n < 0x4C {
        return String::new();
    }
    if rd32(data) != 0x4C {
        return String::new(); // HeaderSize
    }
    let flags = rd32(data.get(20..).unwrap_or(&[]));
    let mut off: usize = 0x4C;
    if flags & 0x1 != 0 {
        if off + 2 > n {
            return String::new();
        }
        let idlen = rd16(data.get(off..).unwrap_or(&[])) as usize;
        off += 2 + idlen;
    }
    if flags & 0x2 == 0 {
        return String::new(); // HasLinkInfo yok
    }
    if off + 28 > n {
        return String::new();
    }
    let li_size = rd32(data.get(off..).unwrap_or(&[])) as usize;
    if off + li_size > n || li_size < 28 {
        return String::new();
    }
    let li = match data.get(off..off + li_size) {
        Some(l) => l,
        None => return String::new(),
    };
    let hdr = rd32(&li[4..]);
    let liflags = rd32(&li[8..]);
    let lbp = rd32(&li[16..]) as usize; // LocalBasePathOffset
    let cps = rd32(&li[24..]) as usize; // CommonPathSuffixOffset
    let (mut lbp_u, mut cps_u) = (0usize, 0usize);
    if hdr >= 0x24 {
        lbp_u = rd32(li.get(28..).unwrap_or(&[])) as usize;
        cps_u = rd32(li.get(32..).unwrap_or(&[])) as usize;
    }

    let ansi = |o: usize| -> String {
        if o == 0 || o >= li_size {
            return String::new();
        }
        let tail = &li[o..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        cp1252_to_utf8(&tail[..end], true)
    };
    let uni = |o: usize| -> String {
        if o == 0 || o >= li_size {
            return String::new();
        }
        let mut s = utf16_decode(&li[o..], true, 1);
        if let Some(z) = s.find('\0') {
            s.truncate(z);
        }
        s
    };

    let mut base = String::new();
    if liflags & 0x1 != 0 {
        if lbp_u != 0 {
            base = uni(lbp_u);
        }
        if base.is_empty() {
            base = ansi(lbp);
        }
    }
    let mut suffix = String::new();
    if cps_u != 0 {
        suffix = uni(cps_u);
    }
    if suffix.is_empty() {
        suffix = ansi(cps);
    }
    if base.is_empty() {
        return String::new();
    }
    format!("{}{}", base, suffix)
}

#[derive(Debug, Clone, Default)]
struct JEntry {
    path: String,
    action: String,
    when: String,
    source: String,
    t: f64,
}

fn read_recent(dir: &str, cutoff: f64, out: &mut Vec<JEntry>) {
    if !is_dir(dir) {
        return;
    }
    let mut ents = Vec::new();
    list_dir(dir, &mut ents);
    for e in &ents {
        if e.is_dir {
            continue;
        }
        if !ends(&py_lower(&e.name), ".lnk") {
            continue;
        }
        if cutoff != 0.0 && e.mtime != 0.0 && e.mtime < cutoff {
            continue;
        }
        let d = match read_file(&path_join(dir, &e.name), -1, 0) {
            Some(d) => d,
            None => continue,
        };
        let target = lnk_target_path(&d);
        if target.is_empty() {
            continue;
        }
        out.push(JEntry {
            path: target,
            action: "açıldı".to_string(),
            t: e.mtime,
            when: if e.mtime != 0.0 {
                fmt_dt(Some(e.mtime))
            } else {
                String::new()
            },
            source: "Recent (.lnk)".to_string(),
        });
    }
}

const USN_REASON_DATA_OVERWRITE: u32 = 0x1;
const USN_REASON_DATA_EXTEND: u32 = 0x2;
const USN_REASON_DATA_TRUNCATION: u32 = 0x4;
const USN_REASON_FILE_CREATE: u32 = 0x100;
const USN_REASON_FILE_DELETE: u32 = 0x200;
const USN_REASON_RENAME_NEW_NAME: u32 = 0x2000;

#[derive(Debug, Clone, Default, PartialEq)]
struct UsnRec {
    parent_frn: u64,
    time_stamp: i64,
    reason: u32,
    name: String,
}

const USN_RECORD_V2_SIZE: usize = 64;

fn parse_usn_buffer(buf: &[u8]) -> Option<(i64, Vec<UsnRec>)> {
    if buf.len() < 8 {
        return None;
    }
    let next = rd64(buf) as i64;
    let mut recs = Vec::new();
    let mut off = 8usize;
    while off + USN_RECORD_V2_SIZE <= buf.len() {
        let rec = &buf[off..];
        let rec_len = rd32(rec) as usize;
        if rec_len == 0 {
            break;
        }
        let major = rd16(rec.get(4..).unwrap_or(&[]));
        let (parent, ts, reason, nlen, noff) = if major == 3 {
            (
                rd64(rec.get(24..).unwrap_or(&[])),
                rd64(rec.get(48..).unwrap_or(&[])) as i64,
                rd32(rec.get(56..).unwrap_or(&[])),
                rd16(rec.get(72..).unwrap_or(&[])) as usize,
                rd16(rec.get(74..).unwrap_or(&[])) as usize,
            )
        } else {
            (
                rd64(rec.get(16..).unwrap_or(&[])),
                rd64(rec.get(32..).unwrap_or(&[])) as i64,
                rd32(rec.get(40..).unwrap_or(&[])),
                rd16(rec.get(56..).unwrap_or(&[])) as usize,
                rd16(rec.get(58..).unwrap_or(&[])) as usize,
            )
        };
        let name = match rec.get(noff..noff.saturating_add(nlen & !1)) {
            Some(raw) => {
                let w: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                narrow(&w)
            }
            None => String::new(),
        };
        recs.push(UsnRec {
            parent_frn: parent,
            time_stamp: ts,
            reason,
            name,
        });
        off += rec_len;
    }
    Some((next, recs))
}

fn usn_action(reason: u32) -> Option<&'static str> {
    if reason & USN_REASON_FILE_DELETE != 0 {
        Some("silindi")
    } else if reason & USN_REASON_RENAME_NEW_NAME != 0 {
        Some("yeniden adlandırıldı")
    } else if reason & USN_REASON_FILE_CREATE != 0 {
        Some("oluşturuldu")
    } else if reason & (USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND | USN_REASON_DATA_TRUNCATION) != 0 {
        Some("değiştirildi")
    } else {
        None
    }
}

const INTERESTING: &[&str] = &[
    ".jar",
    ".zip",
    ".dll",
    ".exe",
    ".rar",
    ".7z",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".zst",
    ".cab",
    ".msi",
    ".iso",
    ".img",
    ".apk",
    ".jnlp",
    ".class",
    ".dat",
    ".txt",
    ".png",
    ".bin",
    ".js",
    ".vbs",
    ".ps1",
    ".bat",
    ".cmd",
    ".scr",
    ".com",
    ".pif",
    ".lnk",
    ".sys",
    ".node",
    ".pyd",
    ".asi",
    ".tmp",
    ".part",
    ".crdownload",
    ".json",
    ".cfg",
    ".properties",
    ".toml",
    ".jsonc",
    ".so",
    ".dylib",
    ".py",
    ".jarx",
    ".001",
];
const NOISE: &[&str] = &[
    ".log",
    ".etl",
    ".evtx",
    ".pf",
    ".db",
    ".db-wal",
    ".db-shm",
    ".ldb",
    ".sqlite",
    ".journal",
    ".lock",
    ".cache",
    ".idx",
    ".pdb",
    ".manifest",
    ".cat",
    ".mum",
    ".mui",
    ".nls",
    ".pri",
    ".resources",
    ".ini",
    ".xml",
    ".html",
    ".htm",
    ".css",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".ico",
    ".mp4",
    ".webm",
    ".ogg",
    ".wav",
    ".mp3",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
    ".pak",
    ".vdf",
    ".acf",
    ".bak",
    ".old",
    ".crc",
    ".map",
];

fn usn_wanted(name: &str, reason: u32) -> bool {
    let low = py_lower(name);
    let codeish = INTERESTING.iter().any(|e| low.ends_with(e));
    let no_ext = !low.contains('.');
    let hide_action = reason & (USN_REASON_RENAME_NEW_NAME | USN_REASON_FILE_DELETE) != 0;
    let noise = NOISE.iter().any(|e| low.ends_with(e));
    let any_ext_ok = hide_action && !noise;
    let tok = jmatch_cheat_token(&jnorm_alnum(name));
    codeish || no_ext || any_ext_ok || !tok.is_empty()
}

#[cfg(windows)]
mod usn_win {
    use super::*;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, GetFinalPathNameByHandleW, OpenFileById, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Ioctl::{FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL};
    use windows::Win32::System::IO::DeviceIoControl;

    const GENERIC_READ: u32 = 0x8000_0000;

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: tanıtıcı bu sarmalayıcıya aittir ve yalnızca bir kez kapatılır
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn final_path_from_handle(h: HANDLE) -> String {
        let mut buf = [0u16; 4096];
        // SAFETY: buf geçerli ve yazılabilir; uzunluk dilimden alınır
        let r = unsafe { GetFinalPathNameByHandleW(h, &mut buf[..4095], FILE_NAME_NORMALIZED) } as usize;
        if r == 0 || r >= 4095 {
            return String::new();
        }
        let mut w: &[u16] = &buf[..r];
        let pre: Vec<u16> = "\\\\?\\".encode_utf16().collect();
        if w.starts_with(&pre) {
            w = &w[4..];
        }
        narrow(w)
    }

    fn resolve_parent(hv: HANDLE, frn: u64, cache: &mut BTreeMap<u64, String>) -> String {
        if let Some(p) = cache.get(&frn) {
            return p.clone();
        }
        let mut path = String::new();
        let fid = FILE_ID_DESCRIPTOR {
            dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: windows::Win32::Storage::FileSystem::FileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 { FileId: frn as i64 },
        };
        // SAFETY: fid geçerli bir yapı; hv açık birim tanıtıcısı
        let hf = unsafe {
            OpenFileById(
                hv,
                &fid,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                FILE_FLAG_BACKUP_SEMANTICS,
            )
        };
        if let Ok(hf) = hf {
            if hf != INVALID_HANDLE_VALUE {
                let g = Handle(hf);
                path = final_path_from_handle(g.0);
            }
        }
        cache.insert(frn, path.clone());
        path
    }

    pub fn read_usn_volume(drive: char, cutoff: f64, out: &mut Vec<JEntry>, errs: &mut StrList) {
        let vol: Vec<u16> = format!("\\\\.\\{}:", drive)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: vol NUL ile biten geçerli geniş dizgi
        let hv = unsafe {
            CreateFileW(
                PCWSTR(vol.as_ptr()),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        let hv = match hv {
            Ok(h) if h != INVALID_HANDLE_VALUE => Handle(h),
            _ => {
                errs.push(format!("{}: USN günlüğü açılamadı (yönetici gerekir)", drive));
                return;
            }
        };

        let mut jd = [0u8; 80];
        let mut br: u32 = 0;
        // SAFETY: çıktı tamponu jd geçerli; br yerel değişken
        let ok = unsafe {
            DeviceIoControl(
                hv.0,
                FSCTL_QUERY_USN_JOURNAL,
                None,
                0,
                Some(jd.as_mut_ptr().cast()),
                jd.len() as u32,
                Some(&mut br),
                None,
            )
        };
        if ok.is_err() {
            errs.push(format!("{}: USN günlüğü yok veya sorgulanamadı", drive));
            return;
        }
        let journal_id = rd64(&jd);

        let mut parent_cache: BTreeMap<u64, String> = BTreeMap::new();
        let mut start_usn: i64 = 0;
        let mut buf = vec![0u8; 1 << 20];
        let mut guard = 0;
        let mut dedup: BTreeMap<String, JEntry> = BTreeMap::new();
        while guard < 4000 {
            guard += 1;
            let mut rd = [0u8; 40];
            rd[0..8].copy_from_slice(&start_usn.to_le_bytes());
            rd[8..12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
            rd[32..40].copy_from_slice(&journal_id.to_le_bytes());
            br = 0;
            // SAFETY: giriş ve çıktı tamponları geçerli; boyutlar dilimlerden gelir
            let ok = unsafe {
                DeviceIoControl(
                    hv.0,
                    FSCTL_READ_USN_JOURNAL,
                    Some(rd.as_ptr().cast()),
                    rd.len() as u32,
                    Some(buf.as_mut_ptr().cast()),
                    buf.len() as u32,
                    Some(&mut br),
                    None,
                )
            };
            if ok.is_err() {
                break;
            }
            let got = (br as usize).min(buf.len());
            if got < 8 {
                break;
            }
            let (next, recs) = match parse_usn_buffer(&buf[..got]) {
                Some(x) => x,
                None => break,
            };
            for rec in recs {
                let fe = filetime_to_epoch(rec.time_stamp as u64);
                let when = fe.unwrap_or(0.0);
                if cutoff != 0.0 && when < cutoff {
                    continue;
                }
                let action = match usn_action(rec.reason) {
                    Some(a) => a,
                    None => continue,
                };
                if !usn_wanted(&rec.name, rec.reason) {
                    continue;
                }
                let parent = resolve_parent(hv.0, rec.parent_frn, &mut parent_cache);
                let full = if parent.is_empty() {
                    rec.name.clone()
                } else {
                    path_join(&parent, &rec.name)
                };
                let key = py_lower(&full);
                let replace = match dedup.get(&key) {
                    None => true,
                    Some(d) => when > d.t,
                };
                if replace {
                    dedup.insert(
                        key,
                        JEntry {
                            path: full,
                            action: action.to_string(),
                            t: when,
                            when: fmt_dt(Some(when)),
                            source: "USN".to_string(),
                        },
                    );
                }
            }
            if next == start_usn {
                break;
            }
            start_usn = next;
        }
        out.extend(dedup.into_values());
    }
}

fn jrank_tag(r: i32) -> char {
    if r >= 3 {
        'k'
    } else if r == 2 {
        'y'
    } else if r == 1 {
        's'
    } else {
        't'
    }
}

fn action_pri(a: &str) -> i32 {
    match a {
        "silindi" => 5,
        "yeniden adlandırıldı" => 4,
        "oluşturuldu" => 3,
        "değiştirildi" => 2,
        _ => 1, // acildi
    }
}

struct Item {
    j: JEntry,
    exists: bool,
    in_recycle: bool,
    read_from: String,
}

pub fn scan_journal(days: i32, progress: Option<StrProgress>, stop: Option<&StopFlag>) -> JournalScan {
    let mut s = JournalScan {
        days,
        ..Default::default()
    };
    let cutoff = if days > 0 {
        now_epoch() - days as f64 * 86400.0
    } else {
        0.0
    };
    let say = |m: &str| {
        if let Some(p) = progress {
            p(m);
        }
    };
    let stopped = || stop.is_some_and(|f| f.is_set());

    let mut entries: Vec<JEntry> = Vec::new();
    #[allow(unused_mut)]
    let mut recent_dirs: StrList = Vec::new();
    let over = env("JS_JOURNAL_RECENT");
    if !over.is_empty() {
        for d in split(&over, ";", -1) {
            if !strip(&d, WS_CHARS).is_empty() {
                recent_dirs.push(strip(&d, WS_CHARS));
            }
        }
    }
    #[cfg(windows)]
    {
        let appdata = env("APPDATA");
        if !appdata.is_empty() {
            recent_dirs.push(path_join(&appdata, "Microsoft\\Windows\\Recent"));
            recent_dirs.push(path_join(&appdata, "Microsoft\\Office\\Recent"));
        }
    }
    say("Recent (.lnk) açılan dosyalar okunuyor...");
    #[allow(unused_mut)]
    let mut before = entries.len();
    for d in &recent_dirs {
        read_recent(d, cutoff, &mut entries);
        s.sources.push(format!("Recent: {}", d));
    }
    s.from_recent = (entries.len() - before) as i32;

    #[cfg(windows)]
    {
        say("NTFS USN değişim günlüğü okunuyor (oluşturulan/silinen/değiştirilen)...");
        before = entries.len();
        let sysdrv = env("SystemDrive"); // "C:"
        let drive = sysdrv.chars().next().unwrap_or('C');
        usn_win::read_usn_volume(drive, cutoff, &mut entries, &mut s.errors);
        s.from_usn = (entries.len() - before) as i32;
        if s.from_usn > 0 {
            s.sources.push(format!("USN günlüğü: {}:", drive));
        }
    }

    if entries.is_empty() {
        s.ran = true;
        if s.errors.is_empty() {
            s.notes.push(format!(
                "Son {} günde incelenecek dosya hareketi bulunamadı (Recent / USN).",
                days
            ));
        } else {
            s.notes
                .push("USN günlüğü okunamadı (yönetici gerekir). Recent (.lnk) kayıtları da boş.".to_string());
        }
        return s;
    }

    let mut uniq: BTreeMap<String, JEntry> = BTreeMap::new();
    for j in entries {
        if cutoff != 0.0 && j.t != 0.0 && j.t < cutoff {
            continue;
        }
        let key = py_lower(&j.path);
        let replace = match uniq.get(&key) {
            None => true,
            Some(o) => {
                action_pri(&j.action) > action_pri(&o.action)
                    || (action_pri(&j.action) == action_pri(&o.action) && j.t > o.t)
            }
        };
        if replace {
            uniq.insert(key, j);
        }
    }
    s.entries = uniq.len() as i32;

    say("Silinen dosyalar için Geri Dönüşüm Kutusu okunuyor...");
    let rbin = recycle_bin_index();
    let mut items: Vec<Item> = Vec::new();
    let mut to_read: StrList = Vec::new();
    for (_, j) in uniq {
        let mut it = Item {
            exists: is_file(&j.path),
            in_recycle: false,
            read_from: String::new(),
            j,
        };
        if it.exists {
            it.read_from = it.j.path.clone();
        } else {
            if !is_dir(&it.j.path) {
                s.deleted += 1;
            }
            let r = recycle_lookup(&rbin, &it.j.path);
            if !r.is_empty() {
                it.in_recycle = true;
                it.read_from = r;
            }
        }
        if !it.read_from.is_empty() {
            to_read.push(it.read_from.clone());
        }
        items.push(it);
    }

    let content = analyze_files(&to_read, stop, progress);

    for it in &items {
        if stopped() {
            break;
        }
        let j = &it.j;
        if is_dir(&j.path) {
            continue; // klasörler dosya değil
        }
        let nm = path_basename(&replace_all(&j.path, "\\", "/"));
        let tok = jmatch_cheat_token(&jnorm_alnum(&nm));
        let where_ = if it.exists {
            "  (cihazda VAR)"
        } else if it.in_recycle {
            "  (SİLİNMİŞ - Geri Dönüşüm Kutusu'nda bulundu)"
        } else {
            "  (cihazda YOK)"
        };
        let mut head: StrList = vec![
            format!("  Yol    : {}{}", j.path, where_),
            format!("  Eylem  : {}", j.action),
            format!("  Kaynak : {}", j.source),
            format!("  Zaman  : {}", if j.when.is_empty() { "-" } else { &j.when }),
        ];
        if it.in_recycle {
            head.push(format!("  Okunan : {}", it.read_from));
        }

        let mut h = JournalHit {
            action: j.action.clone(),
            path: j.path.clone(),
            name: nm.clone(),
            exists: it.exists,
            in_recycle: it.in_recycle,
            when: j.when.clone(),
            source: j.source.clone(),
            ..Default::default()
        };

        let mut c: Option<&ContentVerdict> = None;
        if !it.read_from.is_empty() {
            if let Some(cv) = content.get(&py_lower(&it.read_from)) {
                if cv.readable {
                    c = Some(cv);
                }
            }
        }
        if let Some(c) = c {
            s.files_checked += 1;
            if c.rank > 0 {
                h.verdict = c.verdict.clone();
                h.tag = jrank_tag(c.rank);
                h.reason = format!(
                    "Dosyanın İÇERİĞİ kod analiz motoruyla okundu: {} ({})",
                    h.verdict, j.action
                );
                h.detail = vec![format!("[{}]  {}   ({})", goster_buyuk(&h.verdict), nm, j.action)];
                h.detail.extend(head.iter().cloned());
                h.detail.push(
                    "  Karar  : Dosyanın İÇERİĞİ JournalScanner kod analiz motoruyla okundu; dosya ADI ve UZANTISI"
                        .to_string(),
                );
                h.detail
                    .push("           karara KATILMADI (uzantı değiştirilmiş olsa bile).".to_string());
                h.detail.push(String::new());
                h.detail.extend(content_lines(c));
                s.hits.push(h);
            }
        } else if !tok.is_empty() {
            h.verdict = "BILGI".to_string();
            h.tag = 'i';
            h.reason = format!("Dosya artık yok, içerik okunamadı -> karar verilmedi (ad: {})", tok);
            h.detail = vec![format!("[BİLGİ - içerik OKUNAMADI]  {}   ({})", nm, j.action)];
            h.detail.extend(head.iter().cloned());
            h.detail.push(
                "  Sonuç  : Dosya cihazda da Geri Dönüşüm Kutusu'nda da yok; içeriği okunamadığı için hile".to_string(),
            );
            h.detail
                .push("           karari VERİLMEDİ (yalnızca içerikten karar verilir).".to_string());
            h.detail.push(format!(
                "  Not    : Dosya adı bilinen bir hile adıyla eşleşiyor ({}); tek başına kanıt değildir.",
                tok
            ));
            s.hits.push(h);
        }
    }

    s.hits.sort_by_key(|h| match h.tag {
        'k' => 0,
        'y' => 1,
        's' => 2,
        _ => 3,
    });
    for (n, h) in s.hits.iter_mut().enumerate() {
        h.id = format!("j{}", n);
        match h.tag {
            'k' => s.kesin += 1,
            'y' => s.yasakli += 1,
            's' => s.supheli += 1,
            _ => s.info += 1,
        }
    }
    s.verdict = if s.kesin > 0 {
        "KESIN HILE"
    } else if s.yasakli > 0 {
        "YASAKLI ISLEV"
    } else if s.supheli > 0 {
        "SUPHELI"
    } else {
        "TEMIZ"
    }
    .to_string();
    s.ran = true;
    s
}

pub fn journal_hit_lines(h: &JournalHit) -> Vec<String> {
    if !h.detail.is_empty() {
        return h.detail.clone();
    }
    vec![
        format!("[{}]  {}", goster_buyuk(&h.verdict), h.name),
        format!("  {}", h.reason),
    ]
}

pub fn journal_overview_lines(s: &JournalScan) -> Vec<String> {
    let mut l: Vec<String> = vec![
        "JOURNAL GEÇMİŞİ (açılan / oluşturulan / değiştirilen / silinen)".to_string(),
        format!("Son {} gün  -  NTFS USN değişim günlüğü + Recent (.lnk)", s.days),
        "=".repeat(70),
        String::new(),
    ];
    if !s.ran && !s.error.is_empty() {
        l.push(format!("[HATA] {}", s.error));
        return l;
    }
    l.push(format!(
        "Kaynak: USN {}, Recent {}  ->  {} benzersiz dosya; {} silinmiş",
        s.from_usn, s.from_recent, s.entries, s.deleted
    ));
    l.push(format!(
        "{} dosyanın İÇERİĞİ kod analiz motoruyla okundu (silinmişler Geri Dönüşüm Kutusu'ndan).",
        s.files_checked
    ));
    l.push("Karar YALNIZCA dosya içeriğine göre verilir; dosya adı ve uzantı karara katılmaz.".to_string());
    l.push(String::new());
    if s.kesin + s.yasakli + s.supheli == 0 {
        l.push("Açılan / oluşturulan / silinen dosyaların içeriğinde hile ya da yasaklı işlev BULUNAMADI.".to_string());
    } else {
        l.push(format!(
            "GENEL KARAR: {}   (kesin {}, yasaklı {}, şüpheli {})",
            s.verdict, s.kesin, s.yasakli, s.supheli
        ));
    }
    if s.info != 0 {
        l.push(format!(
            "Bilgi satırı: {} (içeriği okunamayan, hile adli silinmiş dosya)",
            s.info
        ));
    }
    for x in &s.sources {
        l.push(format!("  - {}", x));
    }
    for n in &s.notes {
        l.push(String::new());
        l.push(n.clone());
    }
    for e in &s.errors {
        l.push(format!("  [!] {}", e));
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2(parent: u64, ts: i64, reason: u32, name: &str) -> Vec<u8> {
        let w: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let len = (60 + w.len() + 7) & !7;
        let mut r = vec![0u8; len.max(USN_RECORD_V2_SIZE)];
        let rl = r.len() as u32;
        r[0..4].copy_from_slice(&rl.to_le_bytes());
        r[4..6].copy_from_slice(&2u16.to_le_bytes());
        r[16..24].copy_from_slice(&parent.to_le_bytes());
        r[32..40].copy_from_slice(&ts.to_le_bytes());
        r[40..44].copy_from_slice(&reason.to_le_bytes());
        r[56..58].copy_from_slice(&(w.len() as u16).to_le_bytes());
        r[58..60].copy_from_slice(&60u16.to_le_bytes());
        r[60..60 + w.len()].copy_from_slice(&w);
        r
    }

    fn v3(parent: u64, ts: i64, reason: u32, name: &str) -> Vec<u8> {
        let w: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let len = (76 + w.len() + 7) & !7;
        let mut r = vec![0u8; len.max(USN_RECORD_V2_SIZE)];
        let rl = r.len() as u32;
        r[0..4].copy_from_slice(&rl.to_le_bytes());
        r[4..6].copy_from_slice(&3u16.to_le_bytes());
        r[24..32].copy_from_slice(&parent.to_le_bytes());
        r[48..56].copy_from_slice(&ts.to_le_bytes());
        r[56..60].copy_from_slice(&reason.to_le_bytes());
        r[72..74].copy_from_slice(&(w.len() as u16).to_le_bytes());
        r[74..76].copy_from_slice(&76u16.to_le_bytes());
        r[76..76 + w.len()].copy_from_slice(&w);
        r
    }

    #[test]
    fn usn_v2_v3_ayristirma() {
        let mut buf = 1234i64.to_le_bytes().to_vec();
        buf.extend(v2(5, 99, USN_REASON_FILE_CREATE, "a.jar"));
        buf.extend(v3(7, 100, USN_REASON_FILE_DELETE, "b.exe"));
        let (next, recs) = parse_usn_buffer(&buf).unwrap();
        assert_eq!(next, 1234);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].parent_frn, 5);
        assert_eq!(recs[0].name, "a.jar");
        assert_eq!(recs[1].parent_frn, 7);
        assert_eq!(recs[1].time_stamp, 100);
        assert_eq!(recs[1].name, "b.exe");
    }

    #[test]
    fn usn_bozuk_tampon() {
        assert!(parse_usn_buffer(&[1, 2, 3]).is_none());
        let mut buf = 1i64.to_le_bytes().to_vec();
        buf.extend(vec![0u8; 100]); // RecordLength = 0 -> durur
        let (next, recs) = parse_usn_buffer(&buf).unwrap();
        assert_eq!(next, 1);
        assert!(recs.is_empty());
        let mut r = v2(1, 1, 1, "x");
        r[58..60].copy_from_slice(&60000u16.to_le_bytes());
        let mut buf = 1i64.to_le_bytes().to_vec();
        buf.extend(r);
        let (_, recs) = parse_usn_buffer(&buf).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].name, "");
    }

    #[test]
    fn eylem_secimi() {
        assert_eq!(
            usn_action(USN_REASON_FILE_DELETE | USN_REASON_FILE_CREATE),
            Some("silindi")
        );
        assert_eq!(usn_action(USN_REASON_RENAME_NEW_NAME), Some("yeniden adlandırıldı"));
        assert_eq!(usn_action(USN_REASON_FILE_CREATE), Some("oluşturuldu"));
        assert_eq!(usn_action(USN_REASON_DATA_EXTEND), Some("değiştirildi"));
        assert_eq!(usn_action(0x8000_0000), None);
    }

    #[test]
    fn action_oncelik() {
        assert!(action_pri("silindi") > action_pri("yeniden adlandırıldı"));
        assert_eq!(action_pri("açıldı"), 1);
    }

    #[test]
    fn lnk_kisa_ve_bozuk() {
        assert_eq!(lnk_target_path(&[]), "");
        assert_eq!(lnk_target_path(&[0u8; 0x4C]), "");
        let mut d = vec![0u8; 0x4C];
        d[0] = 0x4C;
        assert_eq!(lnk_target_path(&d), ""); // HasLinkInfo yok
        d[20] = 0x3; // IDList + LinkInfo ama veri yok
        assert_eq!(lnk_target_path(&d), "");
    }

    #[test]
    fn jnorm() {
        assert_eq!(jnorm_alnum("Liquid-Bounce 1.0"), "liquidbounce10");
    }
}
