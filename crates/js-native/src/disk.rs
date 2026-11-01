use crate::analysis::*;
use crate::ctx::*;
use crate::pat_data::*;
use crate::patterns::*;
use crate::phases::*;
use crate::score::*;
use crate::util::*;
use crate::winutil::*;
use std::collections::BTreeSet;
use std::io::Read;
use std::os::windows::fs::MetadataExt;
use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Threading::*;

#[repr(C)]
#[derive(Clone, Copy)]
struct AvHex {
    object: usize,
    pid: usize,
    handle: usize,
    access: u32,
    bt: u16,
    type_idx: u16,
    attr: u32,
    res: u32,
}
#[repr(C)]
struct AvUstr {
    length: u16,
    max_length: u16,
    buffer: *mut u16,
}
#[repr(C, align(16))]
struct Align16<const N: usize>([u8; N]);

#[repr(C)]
struct HQuery {
    dup: HANDLE,
    access: u32,
    type_: [u16; 128],
    name: [u16; 1024],
    qo: crate::winutil::NtQo,
}

unsafe extern "system" fn hquery_thread(p: *mut core::ffi::c_void) -> u32 {
    let q = &mut *(p as *mut HQuery);
    let mut tb = Align16::<1100>([0; 1100]);
    let mut rl = 0u32;
    q.type_[0] = 0;
    q.name[0] = 0;
    if (q.qo)(q.dup, 2, tb.0.as_mut_ptr() as *mut core::ffi::c_void, 1100, &mut rl) >= 0 {
        let u = &*(tb.0.as_ptr() as *const AvUstr);
        let n = ((u.length / 2) as usize).min(127);
        if !u.buffer.is_null() {
            std::ptr::copy_nonoverlapping(u.buffer, q.type_.as_mut_ptr(), n);
            q.type_[n] = 0;
        }
    }
    let tlen = q.type_.iter().position(|&c| c == 0).unwrap_or(0);
    let ty = String::from_utf16_lossy(&q.type_[..tlen]);
    if ty == "File" {
        if q.access == 0x0012019f || q.access == 0x001a019f || q.access == 0x00120189 || q.access == 0x00120089 {
            return 0; // senkron boru: bilinen kilitlenme maskeleri
        }
        if GetFileType(q.dup) == FILE_TYPE_DISK {
            let n = GetFinalPathNameByHandleW(q.dup, &mut q.name[..1000], GETFINALPATHNAMEBYHANDLE_FLAGS(0));
            if n >= 1000 {
                q.name[0] = 0;
            }
        }
    } else if ty == "Mutant" || ty == "Event" || ty == "Semaphore" || ty == "Section" {
        let mut nb = Align16::<2200>([0; 2200]);
        if (q.qo)(q.dup, 1, nb.0.as_mut_ptr() as *mut core::ffi::c_void, 2200, &mut rl) >= 0 {
            let u = &*(nb.0.as_ptr() as *const AvUstr);
            let n = ((u.length / 2) as usize).min(1000);
            if !u.buffer.is_null() {
                std::ptr::copy_nonoverlapping(u.buffer, q.name.as_mut_ptr(), n);
                q.name[n] = 0;
            }
        }
    }
    0
}

impl Ctx {
    pub fn phase_handles(&mut self, t: &Target) {
        self.begin_phase(7, "Handle / kernel nesne denetimi");
        let (summary, col) = self.phase_handles_inner(t);
        self.end_phase_guard(&summary, col);
    }

    fn phase_handles_inner(&mut self, t: &Target) -> (String, usize) {
        let start_idx = self.findings.len();
        let (Some(qsi), Some(qo)) = (self.nt.qsi, self.nt.qo) else {
            return ("atlandı (NT API yok)".into(), COL_YEL);
        };
        let mut buf: Vec<u8> = vec![0u8; 8 << 20];
        let mut need = 0u32;
        let mut st: i32 = 0;
        for _ in 0..10 {
            st = unsafe {
                qsi(
                    0x40,
                    buf.as_mut_ptr() as *mut core::ffi::c_void,
                    buf.len() as u32,
                    &mut need,
                )
            };
            if st == 0xC0000004u32 as i32 {
                let nl = (need as usize + (4 << 20)).max(buf.len() * 2);
                buf.resize(nl, 0);
                continue;
            }
            break;
        }
        if st < 0 {
            return ("atlandı (handle listesi alınamadı)".into(), COL_YEL);
        }
        let count = usize::from_le_bytes(buf[..8].try_into().unwrap_or([0; 8]));
        let esz = std::mem::size_of::<AvHex>();
        let cnt = count.min((buf.len() - 16) / esz);
        let mut mine = 0;
        for i in 0..cnt {
            if i & 255 == 0 {
                self.prog_set_n(i, cnt);
            }
            let off = 16 + i * esz;
            // SAFETY: off + esz <= buf.len() (cnt sınırlandı)
            let e: AvHex = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const AvHex) };
            if e.pid != t.pid as usize {
                continue;
            }
            mine += 1;
            let mut dup = HANDLE::default();
            let ok_dup = unsafe {
                DuplicateHandle(
                    t.h,
                    HANDLE(e.handle as *mut core::ffi::c_void),
                    GetCurrentProcess(),
                    &mut dup,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
                .is_ok()
            };
            if !ok_dup || dup.0.is_null() {
                continue;
            }
            let mut q = Box::new(HQuery {
                dup,
                access: e.access,
                type_: [0; 128],
                name: [0; 1024],
                qo,
            });
            let th = unsafe {
                CreateThread(
                    None,
                    0,
                    Some(hquery_thread),
                    Some(&mut *q as *mut HQuery as *const core::ffi::c_void),
                    THREAD_CREATION_FLAGS(0),
                    None,
                )
            };
            let mut ok = false;
            let mut leaked = false;
            if let Ok(th) = th {
                if unsafe { WaitForSingleObject(th, 300) } == WAIT_OBJECT_0 {
                    ok = true;
                } else {
                    unsafe {
                        let _ = TerminateThread(th, 1);
                    }
                    leaked = true;
                }
                unsafe {
                    let _ = CloseHandle(th);
                }
            }
            if !ok {
                unsafe {
                    let _ = CloseHandle(dup);
                }
                if leaked {
                    std::mem::forget(q); // sonlandırılan thread belleği kullanıyor olabilir: serbest bırakma
                }
                continue;
            }
            let tl = q.type_.iter().position(|&c| c == 0).unwrap_or(0);
            let nl = q.name.iter().position(|&c| c == 0).unwrap_or(0);
            let ty = String::from_utf16_lossy(&q.type_[..tl]);
            let name = String::from_utf16_lossy(&q.name[..nl]);
            unsafe {
                let _ = CloseHandle(dup);
            }
            if name.is_empty() {
                continue;
            }
            if ty == "File" {
                let p = norm_path(&name);
                let lp = lower_w(&p);
                let is_dll = lp.len() > 4 && lp.ends_with(".dll");
                if !is_dll {
                    continue;
                }
                if is_under(&lp, &self.dirs.sysroot) || is_under(&lp, &self.dirs.pf) || is_under(&lp, &self.dirs.pf86) {
                    continue;
                }
                let Some(a) = self.analyze_file(&p) else { continue };
                if a.verdict >= Verdict::Suspect {
                    let v = a.verdict;
                    self.register(
                        "AÇIK HANDLE (javaw bu dosyayı açıyor)",
                        &p,
                        Some(a),
                        "javaw bu dosyaya açık handle tutuyor",
                        "",
                    );
                    self.out(
                        &format!("  [!] javaw'in açtığı dosya: {} -> {}", p, verdict_tag(v)),
                        if v == Verdict::Confirmed { COL_RED } else { COL_YEL },
                    );
                } else if self.cfg.verbose {
                    self.out(&format!("  [i] açık dll: {}  {}", p, verdict_tag(a.verdict)), COL_GRY);
                }
            } else {
                let nm = name.clone();
                let mut cx = StrCtx::default();
                let mut strong = 0;
                let mut lab = String::new();
                let db = get_db();
                match_string(nm.as_bytes(), &mut cx, false, |id, _, _| {
                    let pi = &db.pats[id as usize];
                    if pi.cat == C_FAMILY || pi.cat == C_CLIENT_A || pi.cat == C_MOD_STRONG {
                        strong += 1;
                        lab = pi.label.to_string();
                    }
                });
                if strong != 0 {
                    let mut a = Analysis {
                        path: nm.clone(),
                        sig_text: "kernel nesnesi".into(),
                        ..Default::default()
                    };
                    add_ev(
                        &mut a,
                        'H',
                        35,
                        &format!("javaw içinde hile ifadesi taşıyan kernel nesnesi ({}): {}", ty, nm),
                    );
                    decide(&mut a);
                    self.register(
                        &format!("KERNEL NESNESI ({})", ty),
                        &nm,
                        Some(Arc::new(a)),
                        &format!("nesne adı hile ifadesi içeriyor: {}", lab),
                        "",
                    );
                    self.out(&format!("  [!] hile ifadeli {} nesnesi: {}", ty, nm), COL_YEL);
                }
            }
        }
        let mut worst = Verdict::Clean;
        let mut flagged = 0;
        for f in self.findings.iter().skip(start_idx) {
            let v = f.verd();
            if v >= Verdict::Suspect {
                flagged += 1;
                if v > worst {
                    worst = v;
                }
            }
        }
        let s = format!(
            "{} handle{}",
            mine,
            if flagged != 0 {
                format!("  -> {} İZ", flagged)
            } else {
                "  temiz".to_string()
            }
        );
        let col = if flagged != 0 {
            if worst == Verdict::Confirmed {
                COL_RED
            } else {
                COL_YEL
            }
        } else {
            COL_GRN
        };
        (s, col)
    }
}

#[derive(Default, Clone)]
pub struct DiskStats {
    pub dirs: u64,
    pub files: u64,
    pub probed: u64,
    pub pes: u64,
    pub analyzed: u64,
    pub skipped_signed: u64,
    pub hits: u64,
    pub conf: u64,
}
#[derive(Default, Clone)]
pub struct DiskItem {
    pub path: String,
    pub size: u64,
    pub w: f64, // tahmini işlem süresi (sn)
}

const SKIP_EXTS: &[&str] = &[
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
    ".ico",
    ".svg",
    ".tga",
    ".dds",
    ".psd",
    ".mp3",
    ".mp4",
    ".mkv",
    ".avi",
    ".mov",
    ".wav",
    ".ogg",
    ".flac",
    ".m4a",
    ".webm",
    ".zip",
    ".rar",
    ".7z",
    ".gz",
    ".tar",
    ".iso",
    ".cab",
    ".msi",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".txt",
    ".log",
    ".json",
    ".xml",
    ".html",
    ".htm",
    ".css",
    ".js",
    ".ts",
    ".md",
    ".ini",
    ".cfg",
    ".properties",
    ".yml",
    ".yaml",
    ".toml",
    ".csv",
    ".db",
    ".sqlite",
    ".ldb",
    ".jar",
    ".class",
    ".lang",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".pak",
    ".nbt",
    ".mca",
    ".mcmeta",
    ".lock",
    ".pyc",
    ".py",
    ".java",
    ".cpp",
    ".h",
    ".c",
    ".cs",
    ".vcxproj",
    ".sln",
    ".obj",
    ".lib",
    ".pdb",
    ".idb",
    ".ilk",
    ".exp",
    ".res",
    ".lnk",
    ".url",
    ".bak",
    ".old",
    ".etl",
    ".evtx",
    ".dmp",
    ".vhd",
    ".vhdx",
    ".vmdk",
    ".nupkg",
    ".whl",
    ".gguf",
];

pub fn skip_ext(e: &str) -> bool {
    SKIP_EXTS.contains(&e)
}

pub fn ext_of(full: &str) -> String {
    let sl = full.rfind(['\\', '/']);
    let dt = full.rfind('.');
    match dt {
        Some(d) if sl.is_none_or(|s| d > s) => lower_w(&full[d..]),
        _ => String::new(),
    }
}

pub fn disk_weight(ext: &str, size: u64) -> f64 {
    const PE: [&str; 16] = [
        ".dll", ".exe", ".sys", ".drv", ".ocx", ".cpl", ".scr", ".efi", ".mui", ".pyd", ".node", ".asi", ".tmp",
        ".bin", ".dat", "",
    ];
    if PE.contains(&ext) {
        0.004 + size as f64 / (60.0 * 1048576.0)
    } else {
        0.0006
    }
}

pub fn skip_dir_path(sysroot: &str, full: &str) -> bool {
    let l = lower_w(full);
    const SUB: [&str; 24] = [
        "\\windows\\winsxs",
        "\\windows\\installer",
        "\\windows\\servicing",
        "\\windows\\assembly",
        "\\windows\\system32",
        "\\windows\\syswow64",
        "\\windows\\softwaredistribution",
        "\\$windows.~bt",
        "\\$winreagent",
        "\\system volume information",
        "\\node_modules",
        "\\.git\\",
        "\\appdata\\local\\packages",
        "\\microsoft\\windowsapps",
        "\\.gradle\\",
        "\\.m2\\",
        "\\.ivy2\\",
        "\\.sdkman\\",
        "\\google\\chrome\\user data",
        "\\microsoft\\edge\\user data",
        "\\code cache",
        "\\gpucache",
        "\\cache_data",
        "\\cache2",
    ];
    if SUB.iter().any(|s| l.contains(s)) {
        return true;
    }
    if l.len() > 4 && !sysroot.is_empty() && is_under(&l, sysroot) && !is_under(&l, &format!("{}\\temp", sysroot)) {
        return true; // Windows dizini (Temp hariç)
    }
    false
}

impl Ctx {
    fn disk_candidate(&self, full: &str, size: u64) -> bool {
        if size > (160u64 << 20) || size < 8192 {
            return false;
        }
        if skip_ext(&ext_of(full)) && size < 32768 {
            return false;
        }
        if lower_w(full) == self.dirs.self_exe {
            return false;
        }
        true
    }

    fn check_disk_file(&mut self, full: &str, size: u64) {
        let ext = ext_of(full);
        let skip_e = skip_ext(&ext);
        let Ok(mut f) = std::fs::File::open(long_path(full)) else {
            return;
        };
        let mut hdr = [0u8; 4096];
        let rd = f.read(&mut hdr).unwrap_or(0);
        let ok = rd > 0;
        drop(f);
        self.disk_stats.probed += 1;
        if !ok || rd < 0x200 {
            return;
        }
        if hdr[0] != b'M' || hdr[1] != b'Z' {
            return; // yalnızca PE (DLL/EXE) dosyaları; uzantısı ne olursa olsun
        }
        let lf = rd32(&hdr, 0x3C) as usize;
        if lf < 0x40 || lf + 0x120 > rd || rd32(&hdr, lf) != 0x4550 {
            return;
        }
        self.disk_stats.pes += 1;
        let magic = rd16(&hdr, lf + 24);
        let sd = lf + 24 + if magic == 0x20B { 112 } else { 96 } + 4 * 8;
        if sd + 8 <= rd && rd32(&hdr, sd + 4) > 0 && size > (1 << 20) && !in_user_drop_dir(&self.dirs, full) {
            let si = self.sigs.verify_cached(full);
            if si.valid && si.trusted {
                self.disk_stats.skipped_signed += 1;
                return;
            }
        }
        let a = self.analyze_file(full);
        self.disk_stats.analyzed += 1;
        let Some(a) = a else { return };
        if a.verdict != Verdict::Tool && (a.verdict >= Verdict::Suspect || a.s > 0 || a.t >= 40) {
            let note = if skip_e {
                format!("uzantısı ({}) ile gizlenmiş PE dosyası", ext)
            } else {
                String::new()
            };
            self.register("DİSK DOSYASI", full, Some(a.clone()), &note, "");
            if a.verdict >= Verdict::Suspect {
                self.disk_stats.hits += 1;
                if a.verdict == Verdict::Confirmed {
                    self.disk_stats.conf += 1;
                }
                self.out(
                    &format!("  [!] {} -> {} S={} T={}", full, verdict_tag(a.verdict), a.s, a.t),
                    if a.verdict == Verdict::Confirmed {
                        COL_RED
                    } else {
                        COL_YEL
                    },
                );
            }
        }
    }

    fn disk_roots(&self) -> Vec<String> {
        let mut roots: Vec<String> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut add = |r: &str, roots: &mut Vec<String>| {
            if r.is_empty() {
                return;
            }
            let l = lower_w(r);
            if seen.contains(&l) {
                return;
            }
            if !std::fs::metadata(r).map(|m| m.is_dir()).unwrap_or(false) {
                return;
            }
            seen.insert(l);
            roots.push(r.to_string());
        };
        let user = norm_path(&get_env("USERPROFILE"));
        let drives = unsafe { GetLogicalDrives() };
        let fixed_drives = || -> Vec<String> {
            let mut v = Vec::new();
            for i in 0..26u32 {
                if drives & (1 << i) != 0 {
                    let r = format!("{}:\\", (b'A' + i as u8) as char);
                    let w = wz(&r);
                    if unsafe { GetDriveTypeW(PCWSTR(w.as_ptr())) } == 3 {
                        v.push(r);
                    }
                }
            }
            v
        };
        if !self.cfg.roots.is_empty() {
            for r in &self.cfg.roots {
                let mut rr = norm_path(r);
                while rr.len() > 3 && (rr.ends_with('\\') || rr.ends_with('/')) {
                    rr.pop();
                }
                add(&rr, &mut roots);
            }
        } else if self.cfg.full {
            for r in fixed_drives() {
                add(&r, &mut roots);
            }
        } else {
            let users_dir = match user.rfind('\\') {
                Some(k) if k > 2 => user[..k].to_string(),
                _ => String::new(),
            };
            if !users_dir.is_empty() {
                if let Ok(rd) = std::fs::read_dir(&users_dir) {
                    for e in rd.flatten() {
                        let Ok(md) = e.metadata() else { continue };
                        let attrs = md.file_attributes();
                        if attrs & 0x10 == 0 || attrs & 0x400 != 0 {
                            continue;
                        }
                        let nm = e.file_name().to_string_lossy().into_owned();
                        let n = lower_w(&nm);
                        if n == "." || n == ".." || n == "default" || n == "default user" || n == "all users" {
                            continue;
                        }
                        add(&format!("{}\\{}", users_dir, nm), &mut roots);
                    }
                }
            } else {
                add(&user, &mut roots);
            }
            add(&norm_path(&get_env("ProgramData")), &mut roots);
            add(&format!("{}\\Temp", norm_path(&get_env("SystemRoot"))), &mut roots);
            for r in fixed_drives() {
                add(&format!("{}$Recycle.Bin", r), &mut roots);
            }
        }
        roots
    }

    pub fn disk_enumerate(&mut self) {
        self.disk_items.clear();
        self.disk_stats = DiskStats::default();
        self.disk_work = 0.0;
        let mut last = 0u64;
        let roots = self.disk_roots();
        self.disk_roots_n = roots.len();
        for root in &roots {
            if self.cfg.verbose {
                self.out(&format!("  > {}", root), COL_GRY);
            }
            let mut stack: Vec<String> = vec![root.clone()];
            while let Some(dir) = stack.pop() {
                self.disk_stats.dirs += 1;
                if let Ok(rd) = std::fs::read_dir(long_path(&dir)) {
                    for e in rd.flatten() {
                        let Ok(md) = e.metadata() else { continue };
                        let nm = e.file_name().to_string_lossy().into_owned();
                        let full = format!("{}\\{}", dir, nm);
                        let attrs = md.file_attributes();
                        if attrs & 0x10 != 0 {
                            if attrs & 0x400 != 0 {
                                continue;
                            }
                            if skip_dir_path(&self.dirs.sysroot, &full) {
                                continue;
                            }
                            stack.push(full);
                        } else {
                            self.disk_stats.files += 1;
                            let sz = md.len();
                            if self.disk_candidate(&full, sz) {
                                let w = disk_weight(&ext_of(&full), sz);
                                self.disk_work += w;
                                self.disk_items.push(DiskItem {
                                    path: full,
                                    size: sz,
                                    w,
                                });
                            }
                        }
                    }
                }
                let now = self.tick();
                if now - last > 250 {
                    last = now;
                    self.prep_note = format!(
                        "disk listeleniyor: {} klasör, {} dosya",
                        self.disk_stats.dirs, self.disk_stats.files
                    );
                    self.prog_draw(false);
                }
            }
        }
        self.prep_note.clear();
        self.disk_listed = true;
    }

    pub fn phase_disk(&mut self) {
        self.begin_phase(8, "Disk taraması (içerik tabanlı)");
        if !self.disk_listed {
            self.disk_enumerate();
        }
        let line = format!(
            "  {} kök dizin, {} dosya listelendi; {} aday dosyanın içeriği incelenecek{}. (Hile dosyaları, silinse bile Geri Dönüşüm Kutusu'nda aranır.)",
            self.disk_roots_n,
            self.disk_stats.files,
            self.disk_items.len(),
            if self.cfg.full { " [--full: tüm sabit diskler]" } else { "" }
        );
        self.out(&line, COL_DEF);
        let mut done = 0.0;
        let items = std::mem::take(&mut self.disk_items);
        for it in &items {
            let f = if self.disk_work > 0.0 {
                done / self.disk_work
            } else {
                1.0
            };
            self.prog_set(f);
            self.check_disk_file(&it.path, it.size);
            done += it.w;
        }
        self.disk_items = items;
        let st = self.disk_stats.clone();
        let summary = format!(
            "{} dizin, {} dosya, {} PE incelendi{}",
            st.dirs,
            st.files,
            st.pes,
            if st.hits != 0 {
                format!("  -> {} HİLE DOSYASI", st.hits)
            } else {
                "  temiz".to_string()
            }
        );
        let col = if st.conf != 0 {
            COL_RED
        } else if st.hits != 0 {
            COL_YEL
        } else {
            COL_GRN
        };
        self.end_phase_guard(&summary, col);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exts() {
        assert_eq!(ext_of("c:\\a\\b.DLL"), ".dll");
        assert_eq!(ext_of("c:\\a.b\\file"), "");
        assert!(skip_ext(".png"));
        assert!(!skip_ext(".dll"));
        assert!(!skip_ext(".tmp0"));
    }
    #[test]
    fn weights() {
        assert!(disk_weight(".dll", 60 << 20) > 1.0);
        assert_eq!(disk_weight(".txt", 10), 0.0006);
    }
    #[test]
    fn skip_dirs() {
        assert!(skip_dir_path("c:\\windows", "C:\\Users\\a\\node_modules\\x"));
        assert!(skip_dir_path("c:\\windows", "C:\\Windows\\Fonts"));
        assert!(!skip_dir_path("c:\\windows", "C:\\Windows\\Temp\\x"));
    }
}
