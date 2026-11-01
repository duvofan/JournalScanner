use crate::analysis::*;
use crate::analyze::analyze_buffer;
use crate::ctx::*;
use crate::pat_data::*;
use crate::patterns::{get_db, match_string, StrCtx};
use crate::payload::{parse_unload_trace, UnloadEnt};
use crate::score::*;
use crate::util::*;
use crate::winutil::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::System::Threading::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct Region {
    pub base: u64,
    pub size: u64,
    pub state: u32,
    pub typ: u32,
    pub protect: u32,
    pub alloc_prot: u32,
    pub alloc_base: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ModInfo {
    pub base: u64,
    pub size: u64,
    pub path: String,
}

#[derive(Default)]
pub struct Target {
    pub pid: u32,
    pub h: HANDLE,
    pub wow64: bool,
    pub limited: bool,
    pub exe: String,
    pub cmd: String,
    pub regs: Vec<Region>,
    pub mods: Vec<ModInfo>,
}

#[derive(Clone, Default)]
pub struct UnloadRec {
    pub e: UnloadEnt,
    pub pid: u32,
    pub cls: String,
}

pub fn rpm(h: HANDLE, addr: u64, buf: &mut [u8]) -> bool {
    let mut rd = 0usize;
    unsafe {
        ReadProcessMemory(
            h,
            addr as usize as *const core::ffi::c_void,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            buf.len(),
            Some(&mut rd),
        )
        .is_ok()
            && rd == buf.len()
    }
}

fn rpm_u64(h: HANDLE, addr: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    if rpm(h, addr, &mut b) {
        Some(u64::from_le_bytes(b))
    } else {
        None
    }
}
fn rpm_u32(h: HANDLE, addr: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    if rpm(h, addr, &mut b) {
        Some(u32::from_le_bytes(b))
    } else {
        None
    }
}
fn rpm_u16(h: HANDLE, addr: u64) -> Option<u16> {
    let mut b = [0u8; 2];
    if rpm(h, addr, &mut b) {
        Some(u16::from_le_bytes(b))
    } else {
        None
    }
}

pub fn read_pagewise(h: HANDLE, addr: u64, buf: &mut [u8]) -> usize {
    let n = buf.len();
    let (mut pos, mut ok) = (0usize, 0usize);
    while pos < n {
        let a = addr.wrapping_add(pos as u64);
        let c = (4096 - (a & 4095) as usize).min(n - pos);
        let mut rd = 0usize;
        let good = unsafe {
            ReadProcessMemory(
                h,
                a as usize as *const core::ffi::c_void,
                buf[pos..].as_mut_ptr() as *mut core::ffi::c_void,
                c,
                Some(&mut rd),
            )
            .is_ok()
                && rd == c
        };
        if good {
            ok += c;
        } else {
            for b in &mut buf[pos..pos + c] {
                *b = 0;
            }
        }
        pos += c;
    }
    ok
}

pub fn read_mem(h: HANDLE, addr: u64, n: usize, out: &mut Vec<u8>) -> bool {
    out.clear();
    if out.try_reserve_exact(n).is_err() {
        return false;
    }
    out.resize(n, 0);
    if rpm(h, addr, out) {
        return true;
    }
    read_pagewise(h, addr, out) > 0
}

pub fn enum_regions(h: HANDLE) -> Vec<Region> {
    let mut v = Vec::new();
    let mut addr: u64 = 0;
    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let r = unsafe {
            VirtualQueryEx(
                h,
                Some(addr as usize as *const core::ffi::c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if r != std::mem::size_of::<MEMORY_BASIC_INFORMATION>() {
            break;
        }
        let rg = Region {
            base: mbi.BaseAddress as usize as u64,
            size: mbi.RegionSize as u64,
            state: mbi.State.0,
            typ: mbi.Type.0,
            protect: mbi.Protect.0,
            alloc_prot: mbi.AllocationProtect.0,
            alloc_base: mbi.AllocationBase as usize as u64,
        };
        v.push(rg);
        let nx = rg.base.wrapping_add(rg.size);
        if nx <= addr || nx >= 0x0000_7FFF_FFFF_0000 {
            break;
        }
        addr = nx;
    }
    v
}

pub const MEM_COMMIT_V: u32 = 0x1000;
pub const MEM_IMAGE_V: u32 = 0x1000000;
pub const MEM_MAPPED_V: u32 = 0x40000;

pub fn prot_str(p: u32) -> &'static str {
    match p & 0xFF {
        0x01 => "---",
        0x02 => "R",
        0x04 => "RW",
        0x08 => "RWC",
        0x10 => "X",
        0x20 => "RX",
        0x40 => "RWX",
        0x80 => "RWXC",
        _ => "?",
    }
}

pub fn reg_desc(r: &Region) -> String {
    format!(
        "{} {} {}",
        if r.typ == MEM_IMAGE_V {
            "IMAGE"
        } else if r.typ == MEM_MAPPED_V {
            "MAPPED"
        } else {
            "PRIVATE"
        },
        prot_str(r.protect),
        fmt_size(r.size)
    )
}

pub fn is_exec_prot(p: u32) -> bool {
    let p = p & 0xFF;
    p == 0x10 || p == 0x20 || p == 0x40 || p == 0x80
}

pub fn find_region(t: &Target, addr: u64) -> Option<&Region> {
    let (mut lo, mut hi) = (0usize, t.regs.len());
    while lo < hi {
        let m = (lo + hi) / 2;
        let r = &t.regs[m];
        if addr < r.base {
            hi = m;
        } else if addr >= r.base + r.size {
            lo = m + 1;
        } else {
            return Some(r);
        }
    }
    None
}

pub fn mapped_name(dev_map: &[(String, String)], h: HANDLE, addr: u64) -> String {
    let mut b = [0u16; 1024];
    let n = unsafe { GetMappedFileNameW(h, addr as usize as *const core::ffi::c_void, &mut b) };
    if n == 0 {
        return String::new();
    }
    nt_to_dos(dev_map, &from_w(&b[..n as usize]))
}

fn read_cmd_line(nt: &NtFns, h: HANDLE, wow64: bool) -> String {
    let Some(qip) = nt.qip else { return String::new() };
    let buf: u64;
    let len: u16;
    if !wow64 {
        let mut pbi = AvPbi::default();
        let mut rl = 0u32;
        let rc = unsafe {
            qip(
                h,
                0,
                &mut pbi as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<AvPbi>() as u32,
                &mut rl,
            )
        };
        if rc < 0 || pbi.peb_base_address == 0 {
            return String::new();
        }
        let Some(pp) = rpm_u64(h, pbi.peb_base_address as u64 + 0x20) else {
            return String::new();
        };
        if pp == 0 {
            return String::new();
        }
        let (Some(l), Some(b)) = (rpm_u16(h, pp + 0x70), rpm_u64(h, pp + 0x78)) else {
            return String::new();
        };
        len = l;
        buf = b;
    } else {
        let mut peb32: usize = 0;
        let mut rl = 0u32;
        let rc = unsafe {
            qip(
                h,
                26,
                &mut peb32 as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<usize>() as u32,
                &mut rl,
            )
        };
        if rc < 0 || peb32 == 0 {
            return String::new();
        }
        let Some(pp) = rpm_u32(h, peb32 as u64 + 0x10) else {
            return String::new();
        };
        if pp == 0 {
            return String::new();
        }
        let (Some(l), Some(b)) = (rpm_u16(h, pp as u64 + 0x40), rpm_u32(h, pp as u64 + 0x44)) else {
            return String::new();
        };
        len = l;
        buf = b as u64;
    }
    if buf == 0 || len == 0 || len > 32000 {
        return String::new();
    }
    let mut bytes = vec![0u8; len as usize / 2 * 2];
    if !rpm(h, buf, &mut bytes) {
        return String::new();
    }
    let w: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    from_w(&w)
}

pub fn split_cmd(c: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut cur = String::new();
    let mut q = false;
    for ch in c.chars() {
        if ch == '"' {
            q = !q;
        } else if ch == ' ' && !q {
            if !cur.is_empty() {
                v.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        v.push(cur);
    }
    v
}

fn mc_like(cmd: &str) -> bool {
    let l = lower_w(cmd);
    l.contains("minecraft")
        || l.contains("--gamedir")
        || l.contains("lwjgl")
        || l.contains("fabric")
        || l.contains("forge")
        || l.contains("--assetsdir")
}

impl Ctx {
    pub fn list_modules(&mut self, h: HANDLE) -> Vec<ModInfo> {
        let mut out = Vec::new();
        let mut mods = vec![HMODULE::default(); 2048];
        let mut need = 0u32;
        let r = unsafe {
            EnumProcessModulesEx(
                h,
                mods.as_mut_ptr(),
                (mods.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut need,
                LIST_MODULES_ALL,
            )
        };
        if r.is_err() {
            self.list_mod_err = unsafe { GetLastError().0 };
            return out;
        }
        if need as usize > mods.len() * std::mem::size_of::<HMODULE>() {
            mods.resize(need as usize / std::mem::size_of::<HMODULE>() + 16, HMODULE::default());
            let r2 = unsafe {
                EnumProcessModulesEx(
                    h,
                    mods.as_mut_ptr(),
                    (mods.len() * std::mem::size_of::<HMODULE>()) as u32,
                    &mut need,
                    LIST_MODULES_ALL,
                )
            };
            if r2.is_err() {
                return out;
            }
        }
        let cnt = (need as usize / std::mem::size_of::<HMODULE>()).min(mods.len());
        for &hm in mods.iter().take(cnt) {
            let mut mi = MODULEINFO::default();
            if unsafe { GetModuleInformation(h, hm, &mut mi, std::mem::size_of::<MODULEINFO>() as u32) }.is_err() {
                continue;
            }
            let mut p = [0u16; 520];
            let l = unsafe { GetModuleFileNameExW(Some(h), Some(hm), &mut p) };
            let mut m = ModInfo {
                base: mi.lpBaseOfDll as usize as u64,
                size: mi.SizeOfImage as u64,
                path: String::new(),
            };
            if l != 0 {
                m.path = norm_path(&from_w(&p[..l as usize]));
            }
            out.push(m);
        }
        out
    }

    pub fn in_sys_dir(&self, low_path: &str) -> bool {
        is_under(low_path, &format!("{}\\system32", self.dirs.sysroot))
            || is_under(low_path, &format!("{}\\syswow64", self.dirs.sysroot))
            || is_under(low_path, &format!("{}\\winsxs", self.dirs.sysroot))
    }

    pub fn find_targets(&mut self) -> Vec<Target> {
        let mut all: Vec<Target> = Vec::new();
        let s = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
            Ok(s) => s,
            Err(_) => return all,
        };
        let mut pe: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = unsafe { Process32FirstW(s, &mut pe) }.is_ok();
        while more {
            let name_end = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(pe.szExeFile.len());
            let n = lower_w(&from_w(&pe.szExeFile[..name_end]));
            let pid = pe.th32ProcessID;
            let mut renamed = false;
            let mut skip = false;
            if self.cfg.pid != 0 && pid != self.cfg.pid {
                skip = true;
            }
            if !skip {
                if n == "javaw.exe" || n == "java.exe" {
                    self.javaw_seen += 1;
                }
                if n != "javaw.exe" && n != "java.exe" {
                    if pid <= 4 || pid == unsafe { GetCurrentProcessId() } {
                        skip = true;
                    } else if let Ok(ph) =
                        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
                    {
                        let mut has_jvm = false;
                        let mut hm = vec![HMODULE::default(); 1024];
                        let mut need = 0u32;
                        if unsafe {
                            EnumProcessModulesEx(
                                ph,
                                hm.as_mut_ptr(),
                                (hm.len() * std::mem::size_of::<HMODULE>()) as u32,
                                &mut need,
                                LIST_MODULES_ALL,
                            )
                        }
                        .is_ok()
                        {
                            let cnt = (need as usize / std::mem::size_of::<HMODULE>()).min(hm.len());
                            for &m in hm.iter().take(cnt) {
                                if has_jvm {
                                    break;
                                }
                                let mut bn = [0u16; 260];
                                let l = unsafe { GetModuleBaseNameW(ph, Some(m), &mut bn) };
                                if l != 0 && lower_w(&from_w(&bn[..l as usize])) == "jvm.dll" {
                                    has_jvm = true;
                                }
                            }
                        }
                        unsafe {
                            let _ = CloseHandle(ph);
                        }
                        if !has_jvm {
                            skip = true;
                        } else {
                            renamed = true;
                        }
                    } else {
                        skip = true;
                    }
                }
            }
            if !skip {
                let mut t = Target {
                    pid,
                    ..Default::default()
                };
                match unsafe {
                    OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
                        false,
                        pid,
                    )
                } {
                    Ok(h) => t.h = h,
                    Err(_) => {
                        if let Ok(h) =
                            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid) }
                        {
                            t.h = h;
                            t.limited = true;
                            self.out(
                                &format!("  [!] PID {} için SINIRLI erişim (modül/bellek haritası alınamayabilir). Programı YÖNETİCİ olarak çalıştırın.", pid),
                                COL_YEL,
                            );
                        }
                    }
                }
                if t.h.is_invalid() || t.h.0.is_null() {
                    self.javaw_open_fail += 1;
                    let e = unsafe { GetLastError().0 };
                    self.out(
                        &format!(
                            "  [!] PID {} açılamadı (hata {}). Programı YÖNETİCİ olarak çalıştırın.",
                            pid, e
                        ),
                        COL_YEL,
                    );
                } else {
                    let mut w = windows::core::BOOL(0);
                    unsafe {
                        let _ = IsWow64Process(t.h, &mut w);
                    }
                    t.wow64 = w.as_bool();
                    let mut ex = [0u16; 520];
                    let mut el = ex.len() as u32;
                    if unsafe {
                        QueryFullProcessImageNameW(
                            t.h,
                            PROCESS_NAME_WIN32,
                            windows::core::PWSTR(ex.as_mut_ptr()),
                            &mut el,
                        )
                    }
                    .is_ok()
                    {
                        t.exe = from_w(&ex[..el as usize]);
                    }
                    t.cmd = read_cmd_line(&self.nt, t.h, t.wow64);
                    let mut keep = true;
                    if renamed {
                        if !mc_like(&t.cmd) {
                            unsafe {
                                let _ = CloseHandle(t.h);
                            }
                            keep = false;
                        } else {
                            self.javaw_seen += 1;
                            let mut b = Analysis {
                                path: t.exe.clone(),
                                sig_text: "yeniden adlandırılmış JVM".into(),
                                ..Default::default()
                            };
                            add_ev(
                                &mut b,
                                'H',
                                30,
                                &format!("Minecraft JVM'i 'java/javaw.exe' adını TAŞIMIYOR ({}, PID {}): tarayıcı/anti-cheat'ten kaçmak için javaw.exe yeniden adlandırılmış olabilir", base_name(&t.exe), t.pid),
                            );
                            decide(&mut b);
                            self.register(
                                "YENİDEN ADLANDIRILMIŞ JVM (hedef gizleme)",
                                &t.exe,
                                Some(Arc::new(b)),
                                "jvm.dll yüklü, komut satırı Minecraft/Fabric/Forge belirtisi taşıyor",
                                "",
                            );
                            self.out(
                                &format!(
                                    "  [!] Minecraft JVM'i yeniden adlandırılmış: {} (PID {})",
                                    base_name(&t.exe),
                                    t.pid
                                ),
                                COL_YEL,
                            );
                        }
                    }
                    if keep {
                        all.push(t);
                    }
                }
            }
            more = unsafe { Process32NextW(s, &mut pe) }.is_ok();
        }
        unsafe {
            let _ = CloseHandle(s);
        }
        let mut mc: Vec<Target> = Vec::new();
        let mut rest: Vec<Target> = Vec::new();
        for t in all {
            if mc_like(&t.cmd) {
                mc.push(t);
            } else {
                rest.push(t);
            }
        }
        if mc.is_empty() {
            return rest; // Minecraft izi yoksa tüm javaw/java süreçleri taranır
        }
        for t in rest {
            unsafe {
                let _ = CloseHandle(t.h);
            }
        }
        mc
    }

    pub fn count_exports_tail(&self, path: &str, pe: &mut crate::pe::PeInfo) {
        use std::io::{Read, Seek, SeekFrom};
        if pe.exp_dir_rva == 0 || pe.secs.is_empty() {
            return;
        }
        let rva_to_file = |rva: u32| -> u64 {
            for s in &pe.secs {
                let span = s.vsize.max(s.raw_size);
                if rva >= s.rva && rva - s.rva < span {
                    let d = rva - s.rva;
                    if d >= s.raw_size {
                        return 0;
                    }
                    return s.raw_ptr as u64 + d as u64;
                }
            }
            0
        };
        let ed_off = rva_to_file(pe.exp_dir_rva);
        if ed_off == 0 {
            return;
        }
        let Ok(mut f) = std::fs::File::open(path) else { return };
        let Ok(md) = f.metadata() else { return };
        let fs = md.len();
        if fs < ed_off + 40 {
            return;
        }
        let win_start = ed_off;
        let mut win_len: u64 = if pe.exp_dir_size != 0 {
            pe.exp_dir_size as u64 + (1 << 20)
        } else {
            4 << 20
        };
        if win_len > (48 << 20) {
            win_len = 48 << 20;
        }
        if win_start + win_len > fs {
            win_len = fs - win_start;
        }
        let mut w = vec![0u8; win_len as usize];
        if f.seek(SeekFrom::Start(win_start)).is_err() {
            return;
        }
        let rd = f.read(&mut w).unwrap_or(0);
        if rd < 40 {
            return;
        }
        let n = rd;
        let at = |file_off: u64, need: usize| -> Option<&[u8]> {
            if file_off < win_start {
                return None;
            }
            let idx = (file_off - win_start) as usize;
            if idx + need > n {
                return None;
            }
            Some(&w[idx..idx + need])
        };
        let Some(ed) = at(ed_off, 40) else { return };
        let mut n_names = rd32(ed, 24);
        let names_rva = rd32(ed, 32);
        if n_names > 100000 {
            n_names = 100000;
        }
        let arr_off = rva_to_file(names_rva);
        let (mut cef, mut total) = (0u32, 0u32);
        for i in 0..n_names {
            let Some(ap) = at(arr_off + i as u64 * 4, 4) else { break };
            let s_off = rva_to_file(rd32(ap, 0));
            if s_off == 0 {
                continue;
            }
            let Some(sp) = at(s_off, 1) else { continue };
            let _ = sp;
            total += 1;
            if let Some(p4) = at(s_off, 4) {
                if p4 == b"cef_" {
                    cef += 1;
                }
            }
        }
        if total != 0 {
            pe.exp_cef = cef;
            pe.exp_total = total;
        }
    }

    pub fn analyze_file(&mut self, path: &str) -> Option<Arc<Analysis>> {
        let key = lower_w(path);
        if let Some(a) = self.an_cache.get(&key) {
            return a.clone();
        }
        let mut res: Option<Arc<Analysis>> = None;
        let mut buf: Vec<u8> = Vec::new();
        let (ok, trunc_f) = read_file_all(path, &mut buf, 160u64 << 20, true);
        if ok {
            let mut a = Analysis::default();
            let o = AnalyzeOpts {
                in_user_dir: in_user_drop_dir(&self.dirs, path),
                keep_strings: !self.cfg.dump_dir.is_empty(),
                ..Default::default()
            };
            analyze_buffer(&buf, &o, &mut a);
            a.path = path.to_string();
            if trunc_f {
                if a.pe.valid && a.pe.exp_cef == 0 && a.pe.exp_dir_rva != 0 {
                    let mut pe = std::mem::take(&mut a.pe);
                    self.count_exports_tail(path, &mut pe);
                    a.pe = pe;
                }
                if a.pe.exp_cef >= 40 && (a.pe.exp_cef as u64) * 2 >= a.pe.exp_total as u64 {
                    a.benign_cef = true;
                } else {
                    add_ev(&mut a, 'H', 10, "dosya 160 MB sınırından büyük: yalnızca ilk 160 MB analiz edildi (cop veri eklenerek analizden kaçırma denemesi olabilir)");
                }
                decide(&mut a);
            }
            if a.verdict >= Verdict::Suspect || a.s > 0 || a.t >= 25 {
                let s = self.sigs.verify_cached(path);
                a.sig_valid = s.valid;
                a.sig_text = sig_text(&s);
                if s.valid && s.trusted {
                    a.trusted = true;
                    decide(&mut a);
                }
            } else {
                a.sig_text = "(imza kontrol edilmedi: kanıt yok)".to_string();
            }
            if a.verdict == Verdict::Clean && a.s == 0 && a.t < 25 {
                let l = Analysis {
                    path: a.path.clone(),
                    sig_text: a.sig_text.clone(),
                    verdict: a.verdict,
                    vreason: a.vreason.clone(),
                    s: a.s,
                    t: a.t,
                    size: a.size,
                    sha: a.sha.clone(),
                    jv: a.jv.clone(),
                    ..Default::default()
                };
                a = l;
            }
            res = Some(Arc::new(a));
        }
        self.an_cache.insert(key, res.clone());
        res
    }

    pub fn phase_info(&mut self, t: &Target) {
        self.out(
            &format!(
                "  PID {}  {}  [{}]",
                t.pid,
                t.exe,
                if t.wow64 { "32-bit" } else { "64-bit" }
            ),
            COL_GRN,
        );
        let tk = split_cmd(&t.cmd);
        let (mut ver, mut gdir) = (String::new(), String::new());
        for i in 0..tk.len() {
            let l = lower_w(&tk[i]);
            if l == "--version" && i + 1 < tk.len() {
                ver = tk[i + 1].clone();
            }
            if l == "--gamedir" && i + 1 < tk.len() {
                gdir = tk[i + 1].clone();
            }
        }
        if !ver.is_empty() || !gdir.is_empty() {
            self.out(
                &format!(
                    "  Minecraft sürüm: {}   gameDir: {}",
                    if ver.is_empty() { "?" } else { &ver },
                    if gdir.is_empty() { "?" } else { &gdir }
                ),
                COL_DEF,
            );
        }
        for a in &tk {
            let l = lower_w(a);
            if !l.starts_with("-agentpath:") {
                continue;
            }
            let what = "-agentpath";
            let mut path = a.get(11..).unwrap_or("").to_string();
            if let Some(eq) = path.find('=') {
                path.truncate(eq);
            }
            if let Some(sc) = path.find(';') {
                path.truncate(sc);
            }
            let path = norm_path(&path);
            let ex = file_exists(&path);
            self.out(
                &format!(
                    "  JVM parametresi {}: {}{}",
                    what,
                    path,
                    if ex { "" } else { "  (dosya yok)" }
                ),
                COL_YEL,
            );
            if ex {
                if let Some(an) = self.analyze_file(&path) {
                    self.out(
                        &format!(
                            "     -> analiz: {} S={} T={}  {}",
                            verdict_tag(an.verdict),
                            an.s,
                            an.t,
                            an.vreason
                        ),
                        COL_DEF,
                    );
                    if an.verdict >= Verdict::Suspect {
                        self.register(
                            &format!("JVM AJANI ({})", what),
                            &path,
                            Some(an),
                            "javaw başlatma parametresiyle yüklenmiş ajan",
                            "",
                        );
                    }
                }
            }
        }
    }

    fn analyze_module_mem(&mut self, t: &Target, m: &ModInfo, s: &SigInfo) -> Option<Arc<Analysis>> {
        if m.size == 0 {
            return None;
        }
        let mut img = Vec::new();
        if !read_mem(t.h, m.base, m.size.min(96 << 20) as usize, &mut img) {
            return None; // 96 MB'tan büyük görüntünün yalnızca ilk 96 MB'ı analiz edilir
        }
        let mut a = Analysis::default();
        let o = AnalyzeOpts {
            mem_image: true,
            in_user_dir: in_user_drop_dir(&self.dirs, &m.path),
            keep_strings: !self.cfg.dump_dir.is_empty(),
            ..Default::default()
        };
        analyze_buffer(&img, &o, &mut a);
        a.path = m.path.clone();
        a.sig_text = format!("{}  [bellek görüntüsü analizi]", sig_text(s));
        if m.size > img.len() as u64 && a.pe.valid && a.pe.exp_cef == 0 && a.pe.exp_dir_rva != 0 && !m.path.is_empty() {
            let mut pe = std::mem::take(&mut a.pe);
            self.count_exports_tail(&m.path, &mut pe);
            a.pe = pe;
            if a.pe.exp_cef >= 40 && (a.pe.exp_cef as u64) * 2 >= a.pe.exp_total as u64 {
                a.benign_cef = true;
                decide(&mut a);
            }
        }
        Some(Arc::new(a))
    }

    pub fn phase_modules(&mut self, t: &mut Target) {
        self.begin_phase(1, "Yüklü modül denetimi");
        let (summary, col) = self.phase_modules_inner(t);
        self.end_phase_guard(&summary, col);
    }

    fn phase_modules_inner(&mut self, t: &mut Target) -> (String, usize) {
        t.mods = self.list_modules(t.h);
        let (mut trusted, mut other) = (0, 0);
        let mut hit_names: Vec<String> = Vec::new();
        let mut worst = Verdict::Clean;
        let total = t.mods.len();
        let mods = t.mods.clone();
        for (mod_idx, m) in mods.iter().enumerate() {
            self.prog_set_n(mod_idx, total);
            if m.path.is_empty() {
                other += 1;
                self.out(
                    &format!("  [?] yolsuz modül 0x{:X} ({})", m.base, fmt_size(m.size)),
                    COL_YEL,
                );
                let none = SigInfo::default();
                let mm = self.analyze_module_mem(t, m, &none);
                let mut b = match &mm {
                    Some(x) => (**x).clone(),
                    None => Analysis::default(),
                };
                b.path = format!("<yolsuz modül 0x{:X}>", m.base);
                b.sig_text = "dosya yolu çözülemedi".into();
                add_ev(
                    &mut b,
                    'H',
                    30,
                    &format!("javaw modül listesinde dosya yolu OLMAYAN modül var (0x{:X}, {}): PEB girdisi düzenlenmiş veya dosya silinmiş", m.base, fmt_size(m.size)),
                );
                decide(&mut b);
                let bp = b.path.clone();
                let bv = b.verdict;
                let ix = self.register(
                    "GİZLİ MODÜL (PEB'den silinmiş)",
                    &bp,
                    Some(Arc::new(b)),
                    &format!("yolsuz modül, taban 0x{:X}", m.base),
                    "",
                );
                self.findings[ix].loaded = true;
                self.mod_finding.insert(m.base, ix);
                hit_names.push(bp);
                if bv > worst {
                    worst = bv;
                }
                continue;
            }
            let s = self.sigs.verify_cached(&m.path);
            if s.valid && s.trusted {
                trusted += 1;
                if self.cfg.verbose {
                    self.out(&format!("  [ok] {}  ({})", base_name(&m.path), s.signer), COL_GRY);
                }
                continue;
            }
            other += 1;
            let f = self.analyze_file(&m.path);
            let mm = self.analyze_module_mem(t, m, &s);
            let mut a = f.clone();
            if let Some(mx) = &mm {
                let take = match &f {
                    None => true,
                    Some(fx) => mx.verdict > fx.verdict || (mx.verdict == fx.verdict && mx.s + mx.t > fx.s + fx.t),
                };
                if take {
                    a = Some(mx.clone());
                }
            }
            let Some(a) = a else {
                self.out(&format!("  [?] okunamayan modül: {}", m.path), COL_YEL);
                let mut b = Analysis {
                    path: m.path.clone(),
                    sig_text: format!("{}  [okunamadı]", sig_text(&s)),
                    ..Default::default()
                };
                add_ev(&mut b, 'H', 30, "imzasız/güvenilmeyen modül javaw içinde yüklü ama hem dosyadan hem bellekten OKUNAMADI (dosya silinmiş/kilitli ya da bellek korumalı): analizden kaçma veya self-destruct izi");
                decide(&mut b);
                let bv = b.verdict;
                let ix = self.register(
                    "YÜKLÜ MODÜL (javaw içinde AKTİF)",
                    &m.path,
                    Some(Arc::new(b)),
                    &format!("taban 0x{:X}, boyut {}; içeriği okunamadı", m.base, fmt_size(m.size)),
                    "",
                );
                self.findings[ix].loaded = true;
                self.mod_finding.insert(m.base, ix);
                hit_names.push(base_name(&m.path));
                if bv > worst {
                    worst = bv;
                }
                continue;
            };
            let mem_worse = matches!((&f, &mm), (Some(fx), Some(mx)) if mx.verdict > fx.verdict);
            let notable = a.verdict >= Verdict::Suspect || a.s > 0 || a.t >= 25;
            let line = format!(
                "  {} {}: {}  -> {} S={} T={}",
                if a.verdict >= Verdict::Suspect { "[!]" } else { "[i]" },
                if s.valid {
                    "imzalı(güvenilir değil)"
                } else {
                    "imzasız"
                },
                m.path,
                verdict_tag(a.verdict),
                a.s,
                a.t
            );
            if notable || self.cfg.verbose {
                let c = if a.verdict == Verdict::Confirmed {
                    COL_RED
                } else if a.verdict == Verdict::Suspect {
                    COL_YEL
                } else {
                    COL_GRY
                };
                self.out(&line, c);
            }
            if a.verdict >= Verdict::Suspect {
                if a.verdict == Verdict::Confirmed {
                    self.out(
                        &format!("  [!!!] HİLE ŞU AN javaw İÇİNDE ÇALIŞIYOR: {}", base_name(&m.path)),
                        COL_RED,
                    );
                }
                let av = a.verdict;
                let ix = self.register(
                    "YÜKLÜ MODÜL (javaw içinde AKTİF)",
                    &m.path,
                    Some(a),
                    &format!("taban 0x{:X}, boyut {}", m.base, fmt_size(m.size)),
                    "",
                );
                self.findings[ix].loaded = true;
                self.mod_finding.insert(m.base, ix);
                hit_names.push(base_name(&m.path));
                if av > worst {
                    worst = av;
                }
                if mem_worse {
                    self.findings[ix].notes.push("çalışan bellek görüntüsü diskteki dosyadan daha şüpheli: modül paketli/şifreli olabilir (disk kopyası temiz görünse bile bellek hile içeriyor)".into());
                }
                if f.is_none() {
                    self.findings[ix]
                        .notes
                        .push("dosya okunamadı (silinmiş/kilitli): karar yalnızca bellek görüntüsünden verildi".into());
                }
            }
        }
        if t.mods.is_empty() {
            return (
                format!("modül listesi ALINAMADI (Win32 hata {}): sürece erişim sınırlı, tarama eksik kalır - YÖNETİCİ olarak çalıştırın", self.list_mod_err),
                COL_YEL,
            );
        }
        let s = format!(
            "{} modül ({} imzalı, {} incelendi){}",
            t.mods.len(),
            trusted,
            other,
            if hit_names.is_empty() {
                "  temiz".to_string()
            } else {
                format!("  -> HİLE: {}", join_l(&hit_names, 3, ", "))
            }
        );
        let col = if hit_names.is_empty() {
            COL_GRN
        } else if worst == Verdict::Confirmed {
            COL_RED
        } else {
            COL_YEL
        };
        (s, col)
    }

    pub fn phase_hidden(&mut self, t: &mut Target) {
        self.begin_phase(2, "Gizli modül (VAD-PEB)");
        self.hid_flagged = 0;
        t.regs = enum_regions(t.h);
        let loaded: HashSet<u64> = t.mods.iter().map(|m| m.base).collect();
        let mut groups: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for (i, r) in t.regs.iter().enumerate() {
            if r.state == MEM_COMMIT_V && r.typ == MEM_IMAGE_V {
                groups.entry(r.alloc_base).or_default().push(i);
            }
        }
        let mut hidden = 0;
        let total = groups.len();
        for (grp_idx, (gbase, gidx)) in groups.iter().enumerate() {
            self.prog_set_n(grp_idx, total);
            if loaded.contains(gbase) {
                continue;
            }
            let exec = gidx.iter().any(|&i| is_exec_prot(t.regs[i].protect));
            if !exec {
                continue;
            }
            let last = t.regs[*gidx.last().unwrap_or(&0)];
            let size = last.base + last.size - gbase;
            hidden += 1;
            let path = mapped_name(&self.dev_map, t.h, *gbase);
            if !path.is_empty() && file_exists(&path) {
                let s = self.sigs.verify_cached(&path);
                if s.valid && s.trusted {
                    self.out(
                        &format!("  [i] PEB listesinde olmayan ama güvenilir imzalı görüntü: {}", path),
                        COL_GRY,
                    );
                    continue;
                }
            }
            let mut a: Option<Arc<Analysis>> = None;
            if !path.is_empty() && file_exists(&path) {
                a = self.analyze_file(&path);
            }
            if a.is_none() {
                let mut img = Vec::new();
                if size < (96 << 20) && read_mem(t.h, *gbase, size as usize, &mut img) {
                    let mut x = Analysis::default();
                    let o = AnalyzeOpts {
                        mem_image: true,
                        ..Default::default()
                    };
                    analyze_buffer(&img, &o, &mut x);
                    x.path = if path.is_empty() {
                        format!("<bellek 0x{:X}>", gbase)
                    } else {
                        path.clone()
                    };
                    x.sig_text = "dosya yok/okunamadı - bellek görüntüsü analiz edildi".into();
                    a = Some(Arc::new(x));
                }
            }
            let Some(a) = a else { continue };
            let mut b = (*a).clone(); // paylaşılan önbelleği bozmamak için kopya
            add_ev(
                &mut b,
                'H',
                40,
                &format!("PEB modül listesinde YOK ama bellekte çalıştırılabilir görüntü var (0x{:X}, {}): modül listesinden gizlenmiş / manuel map", gbase, fmt_size(size)),
            );
            decide(&mut b);
            let vt = verdict_tag(b.verdict);
            let col = if b.verdict == Verdict::Confirmed {
                COL_RED
            } else {
                COL_YEL
            };
            self.out(
                &format!(
                    "  [!] GİZLİ GÖRÜNTÜ 0x{:X} ({}) {} -> {}",
                    gbase,
                    fmt_size(size),
                    if path.is_empty() { "<dosya adı yok>" } else { &path },
                    vt
                ),
                col,
            );
            self.hid_flagged += 1;
            let reg_path = if path.is_empty() {
                format!("<gizli-0x{:X}>", gbase)
            } else {
                path.clone()
            };
            let title = if path.is_empty() {
                format!("gizli görüntü 0x{:X}", gbase)
            } else {
                String::new()
            };
            let ix = self.register(
                "GİZLİ MODÜL (PEB'den silinmiş)",
                &reg_path,
                Some(Arc::new(b)),
                &format!("VAD'de var, PEB'de yok; taban 0x{:X}", gbase),
                &title,
            );
            self.findings[ix].loaded = true;
        }
        self.out(
            &format!(
                "  VAD'de {} görüntü grubu incelendi; PEB'de olmayan çalıştırılabilir: {}",
                groups.len(),
                hidden
            ),
            if hidden != 0 { COL_YEL } else { COL_GRN },
        );
        let summary = format!(
            "{} görüntü grubu (VAD), PEB'de olmayan çalıştırılabilir: {}{}",
            groups.len(),
            hidden,
            if self.hid_flagged != 0 {
                format!("  -> {} GİZLİ HİLE GÖRÜNTÜSÜ", self.hid_flagged)
            } else {
                "  temiz".to_string()
            }
        );
        let col = if self.hid_flagged != 0 { COL_RED } else { COL_GRN };
        self.end_phase_guard(&summary, col);
    }

    fn read_trace_candidate(
        h: HANDLE,
        arr: u64,
        elem_size: usize,
        count: usize,
        out: &mut Vec<UnloadEnt>,
        readable: &mut bool,
    ) -> bool {
        out.clear();
        if arr == 0 || !(92..=256).contains(&elem_size) || count == 0 || count > 1024 {
            return false;
        }
        let mut buf = vec![0u8; elem_size * count];
        if !rpm(h, arr, &mut buf) {
            return false;
        }
        *readable = true;
        match parse_unload_trace(&buf, elem_size, count) {
            Some(v) => {
                *out = v;
                !out.is_empty()
            }
            None => false,
        }
    }

    pub fn phase_unloaded(&mut self, t: &Target) {
        self.begin_phase(3, "Boşaltılmış modül kaydı (self-destruct)");
        let (summary, col) = self.phase_unloaded_inner(t);
        self.end_phase_guard(&summary, col);
    }

    fn phase_unloaded_inner(&mut self, t: &Target) -> (String, usize) {
        let skip = |why: &str| (format!("atlandı: {}", why), COL_YEL);
        if t.wow64 {
            return skip("32-bit süreç");
        }
        type FnEx = unsafe extern "system" fn(*mut *mut u32, *mut *mut u32, *mut *mut core::ffi::c_void);
        type FnOld = unsafe extern "system" fn() -> *mut core::ffi::c_void;
        let nt_name = wz("ntdll.dll");
        let nt = unsafe { GetModuleHandleW(PCWSTR(nt_name.as_ptr())) }.ok();
        let fn_ex: Option<FnEx> = nt
            .and_then(|h| unsafe { GetProcAddress(h, windows::core::s!("RtlGetUnloadEventTraceEx")) })
            .map(|p| unsafe { std::mem::transmute::<_, FnEx>(p) });
        let fn_old: Option<FnOld> = nt
            .and_then(|h| unsafe { GetProcAddress(h, windows::core::s!("RtlGetUnloadEventTrace")) })
            .map(|p| unsafe { std::mem::transmute::<_, FnOld>(p) });
        if fn_ex.is_none() && fn_old.is_none() {
            return skip("bu Windows'ta unload-kayıt API'si yok");
        }
        let our_nt = nt.map(|h| h.0 as usize as u64).unwrap_or(0);
        let mut their_nt = 0u64;
        for m in &t.mods {
            if lower_w(&base_name(&m.path)) == "ntdll.dll" {
                their_nt = m.base;
            }
        }
        if their_nt != 0 && their_nt != our_nt {
            return skip("ntdll taban adresi farklı (kayıt adresi çözülemedi)");
        }
        let mut ents: Vec<UnloadEnt> = Vec::new();
        let (mut any, mut readable) = (false, false);
        if let Some(f) = fn_ex {
            let mut size_ptr: *mut u32 = std::ptr::null_mut();
            let mut count_ptr: *mut u32 = std::ptr::null_mut();
            let mut trace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
            unsafe { f(&mut size_ptr, &mut count_ptr, &mut trace_ptr) };
            if !size_ptr.is_null() && !count_ptr.is_null() && !trace_ptr.is_null() {
                if let (Some(es), Some(ec)) = (
                    rpm_u32(t.h, size_ptr as usize as u64),
                    rpm_u32(t.h, count_ptr as usize as u64),
                ) {
                    if let Some(arr) = rpm_u64(t.h, trace_ptr as usize as u64) {
                        if Self::read_trace_candidate(t.h, arr, es as usize, ec as usize, &mut ents, &mut readable) {
                            any = true;
                        }
                    }
                    if !any
                        && Self::read_trace_candidate(
                            t.h,
                            trace_ptr as usize as u64,
                            es as usize,
                            ec as usize,
                            &mut ents,
                            &mut readable,
                        )
                    {
                        any = true;
                    }
                }
            }
        }
        if !any {
            if let Some(f) = fn_old {
                let p = unsafe { f() } as usize as u64;
                for sz in [104usize, 96, 112] {
                    if Self::read_trace_candidate(t.h, p, sz, 16, &mut ents, &mut readable) {
                        any = true;
                        break;
                    }
                }
            }
        }
        if !any && !readable {
            return skip("kayıt javaw belleğindan okunamadı");
        }
        if !any {
            return (
                "0 kayıt  temiz (javaw'dan hiç modül boşaltılmamış)".to_string(),
                COL_GRN,
            );
        }
        let loaded_names: BTreeSet<String> = t.mods.iter().map(|m| lower_w(&base_name(&m.path))).collect();
        let sys32 = format!("{}\\system32\\", self.dirs.sysroot);
        let mut red_flag = 0;
        let mut unknown_names: Vec<String> = Vec::new();
        for e in &ents {
            let wn = e.name.clone();
            let lwn = lower_w(&wn);
            let mut ur = UnloadRec {
                e: e.clone(),
                pid: t.pid,
                cls: "unknown".into(),
            };
            let is_again = loaded_names.contains(&lwn);
            let mut sysdll = false;
            if !is_again {
                let sp = format!("{}{}", sys32, wn);
                if file_exists(&sp) {
                    let si = self.sigs.verify_cached(&sp);
                    sysdll = si.valid && si.trusted;
                }
            }
            if sysdll {
                ur.cls = "sys".into();
                self.out(
                    &format!(
                        "   #{:<4} {:<32} {}  (sistem DLL'i, imzalı)",
                        e.seq,
                        e.name,
                        addr_s(e.base)
                    ),
                    COL_GRY,
                );
                self.unloaded.push(ur);
                continue;
            }
            if is_again {
                ur.cls = "again".into();
                self.out(
                    &format!(
                        "   #{:<4} {:<32} {}  (şu an tekrar yüklü)",
                        e.seq,
                        e.name,
                        addr_s(e.base)
                    ),
                    COL_GRY,
                );
                self.unloaded.push(ur);
                continue;
            }
            unknown_names.push(e.name.clone());
            let mut cx = StrCtx::default();
            let mut strong = 0;
            let mut lab = String::new();
            let db = get_db();
            match_string(e.name.as_bytes(), &mut cx, false, |id, _, _| {
                let pi = &db.pats[id as usize];
                if pi.cat == C_FAMILY || pi.cat == C_CLIENT_A || pi.cat == C_MOD_STRONG {
                    strong += 1;
                    lab = pi.label.to_string();
                }
            });
            self.out(
                &format!(
                    "   [?] #{:<4} {:<32} taban {}  boyut {}  PE zamanı {}",
                    e.seq,
                    e.name,
                    addr_s(e.base),
                    fmt_size(e.size),
                    fmt_time(e.ts)
                ),
                COL_YEL,
            );
            if strong != 0 {
                red_flag += 1;
                let mut a = Analysis {
                    path: e.name.clone(),
                    sig_text: "boşaltılmış modül kaydı".into(),
                    ..Default::default()
                };
                add_ev(
                    &mut a,
                    'H',
                    45,
                    &format!(
                        "javaw'dan boşaltılmış modül adı hile ifadesi içeriyor ({}): {}",
                        lab, e.name
                    ),
                );
                decide(&mut a);
                self.register(
                    "BOŞALTILMIŞ MODÜL (adı hile)",
                    &e.name,
                    Some(Arc::new(a)),
                    &format!(
                        "taban {}, boyut {}, PE zamanı {}",
                        addr_s(e.base),
                        fmt_size(e.size),
                        fmt_time(e.ts)
                    ),
                    "",
                );
            }
            self.unloaded.push(ur);
        }
        let summary = format!(
            "{} kayıt{}",
            ents.len(),
            if unknown_names.is_empty() {
                "  temiz (hepsi sistem DLL'i / tekrar yüklü)".to_string()
            } else {
                format!(
                    "  -> {} sistem dışı: {}  (diskle eşleştirme sonunda)",
                    unknown_names.len(),
                    join_l(&unknown_names, 4, ", ")
                )
            }
        );
        let col = if red_flag != 0 {
            COL_RED
        } else if unknown_names.is_empty() {
            COL_GRN
        } else {
            COL_YEL
        };
        (summary, col)
    }

    pub fn hex_at(h: HANDLE, addr: u64, n: usize) -> String {
        let mut b = Vec::new();
        if !read_mem(h, addr, n, &mut b) {
            return "(okunamadı)".to_string();
        }
        hex_bytes(&b)
    }

    fn group_span(t: &Target, alloc_base: u64) -> u64 {
        let (mut lo, mut hi) = (u64::MAX, 0u64);
        for r in &t.regs {
            if r.alloc_base == alloc_base {
                lo = lo.min(r.base);
                hi = hi.max(r.base + r.size);
            }
        }
        hi.saturating_sub(lo)
    }

    fn is_load_library_start(t: &Target, a: u64) -> bool {
        let mut addrs: Vec<u64> = Vec::new();
        for mn in ["kernel32.dll", "kernelbase.dll", "ntdll.dll"] {
            let w = wz(mn);
            let Ok(hm) = (unsafe { GetModuleHandleW(PCWSTR(w.as_ptr())) }) else {
                continue;
            };
            let ours = hm.0 as usize as u64;
            let mut theirs = 0u64;
            for m in &t.mods {
                if lower_w(&base_name(&m.path)) == mn {
                    theirs = m.base;
                }
            }
            if theirs == 0 || theirs != ours {
                continue;
            }
            for fnn in [
                windows::core::s!("LoadLibraryA"),
                windows::core::s!("LoadLibraryW"),
                windows::core::s!("LoadLibraryExA"),
                windows::core::s!("LoadLibraryExW"),
                windows::core::s!("LdrLoadDll"),
            ] {
                if let Some(p) = unsafe { GetProcAddress(hm, fnn) } {
                    addrs.push(p as usize as u64);
                }
            }
        }
        addrs.contains(&a)
    }

    #[cfg(target_arch = "x86_64")]
    fn thread_rip(tid: u32) -> Option<u64> {
        unsafe {
            let th = OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                false,
                tid,
            )
            .ok()?;
            let mut res = None;
            if SuspendThread(th) != u32::MAX {
                let mut ctx: CONTEXT = std::mem::zeroed();
                ctx.ContextFlags = CONTEXT_CONTROL_AMD64;
                if GetThreadContext(th, &mut ctx).is_ok() {
                    res = Some(ctx.Rip);
                }
                ResumeThread(th);
            }
            let _ = CloseHandle(th);
            res
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn thread_rip(_tid: u32) -> Option<u64> {
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn check_thread(
        &mut self,
        t: &Target,
        tid: u32,
        a: u64,
        rip: bool,
        reg_an: &mut BTreeMap<u64, Arc<Analysis>>,
        st: &mut ThreadStats,
    ) {
        let mod_ = t.mods.iter().find(|m| a >= m.base && a < m.base + m.size).cloned();
        let what = if rip {
            "şu an çalıştığı konum (RIP)"
        } else {
            "başlangıç adresi"
        };
        if let Some(m) = mod_ {
            if !rip {
                st.backed += 1;
            }
            if let Some(&ix) = self.mod_finding.get(&m.base) {
                if !rip {
                    st.in_cheat += 1;
                    self.findings[ix].notes.push(format!(
                        "AKTİF thread TID {} bu modülde başlıyor (0x{:X}) -> modül kodu şu an çalışıyor",
                        tid, a
                    ));
                }
            }
            if !rip && Self::is_load_library_start(t, a) {
                let mut b = Analysis {
                    path: format!("<LoadLibrary thread TID {}>", tid),
                    sig_text: "thread başlangıcı LoadLibrary/LdrLoadDll".into(),
                    ..Default::default()
                };
                add_ev(&mut b, 'H', 30, &format!("Thread TID {} doğrudan LoadLibrary/LdrLoadDll adresinde başlıyor (0x{:X}): CreateRemoteThread+LoadLibrary DLL enjeksiyonunun klasik izi", tid, a));
                decide(&mut b);
                let bp = b.path.clone();
                let bv = b.verdict;
                self.register(
                    "UNBACKED THREAD (LoadLibrary başlangıçlı: enjeksiyon izi)",
                    &bp,
                    Some(Arc::new(b)),
                    &format!("TID {}", tid),
                    "",
                );
                st.flagged += 1;
                st.worst = st.worst.max(bv);
                self.out(
                    &format!("  [!] TID {} LoadLibrary adresinde başlıyor (enjeksiyon izi)", tid),
                    COL_YEL,
                );
            }
            return;
        }
        let r = find_region(t, a).copied();
        let Some(r) = r.filter(|r| r.state == MEM_COMMIT_V) else {
            if rip {
                return;
            }
            let mut unl = String::new();
            let mut sys_unl = false;
            for ur in &self.unloaded {
                if ur.pid == t.pid && a >= ur.e.base && a < ur.e.base + ur.e.size {
                    unl = ur.e.name.clone();
                    sys_unl = ur.cls == "sys";
                    break;
                }
            }
            if sys_unl {
                return;
            }
            let mut b = Analysis {
                path: format!("<yetim thread 0x{:X}>", a),
                sig_text: "başlangıç adresi boş/ayrılmış bellek".into(),
                ..Default::default()
            };
            if unl.is_empty() {
                add_ev(&mut b, 'H', 25, &format!("Thread TID {} başlangıç adresi (0x{:X}) COMMIT edilmemiş/serbest bırakılmış bellekte: kodu bellekten silinmiş ama thread hala sürüyor (self-destruct artığı)", tid, a));
            } else {
                add_ev(&mut b, 'H', 45, &format!("Thread TID {}, javaw'dan BOŞALTILMIŞ '{}' modülünün adres aralığında (0x{:X}) başlıyor: modül boşaltılmış (self-destruct) ama thread sürüyor", tid, unl, a));
            }
            decide(&mut b);
            let bp = b.path.clone();
            let bv = b.verdict;
            self.register(
                "YETİM THREAD (self-destruct artığı)",
                &bp,
                Some(Arc::new(b)),
                &format!("TID {}", tid),
                "",
            );
            st.flagged += 1;
            st.worst = st.worst.max(bv);
            self.out(
                &format!(
                    "  [!] YETİM thread TID {}: başlangıç 0x{:X} serbest bellekte{}{}",
                    tid,
                    a,
                    if unl.is_empty() {
                        ""
                    } else {
                        " (boşaltılmış modül: "
                    },
                    if unl.is_empty() {
                        String::new()
                    } else {
                        format!("{})", unl)
                    }
                ),
                COL_YEL,
            );
            return;
        };
        if r.typ == MEM_IMAGE_V {
            if let Some(f) = self
                .findings
                .iter_mut()
                .find(|f| f.kinds.iter().any(|k| k.contains("GİZLİ")))
            {
                f.notes.push(format!(
                    "AKTİF thread TID {} gizli görüntüde {} (0x{:X})",
                    tid,
                    if rip { "çalışıyor" } else { "başlıyor" },
                    a
                ));
            }
            return;
        }
        if !is_exec_prot(r.protect) && !is_exec_prot(r.alloc_prot) {
            return; // yürütülemeyen bellek
        }
        if rip && Self::group_span(t, r.alloc_base) >= (24 << 20) {
            return; // JVM JIT kod önbelleği
        }
        if r.typ == MEM_MAPPED_V {
            let mn = mapped_name(&self.dev_map, t.h, r.alloc_base);
            if !mn.is_empty() && file_exists(&mn) {
                let si = self.sigs.verify_cached(&mn);
                if si.valid && si.trusted {
                    return;
                }
            }
        }
        let an: Arc<Analysis>;
        if let Some(x) = reg_an.get(&r.alloc_base) {
            an = x.clone();
        } else {
            let mut mem = Vec::new();
            let sz = (r.base + r.size - r.alloc_base).min(8 << 20) as usize;
            if !read_mem(t.h, r.alloc_base, sz, &mut mem) {
                return;
            }
            let mut x = Analysis::default();
            let o = AnalyzeOpts {
                mem_image: false,
                auto_layout: true,
                ..Default::default()
            };
            analyze_buffer(&mem, &o, &mut x);
            x.path = format!("<bellek 0x{:X}>", r.alloc_base);
            x.sig_text = "bellek bölgesi (dosya yok)".into();
            an = Arc::new(x);
            reg_an.insert(r.alloc_base, an.clone());
        }
        let mut b = (*an).clone();
        let evidence = b.is_pe || b.s > 0 || b.t >= 25;
        add_ev(
            &mut b,
            'H',
            if evidence {
                if rip {
                    35
                } else {
                    30
                }
            } else if rip {
                25
            } else {
                20
            },
            &format!(
                "Thread TID {} {} dosya/modül DIŞINDA, yürütülebilir bellekte (0x{:X}, {}){}",
                tid,
                what,
                a,
                reg_desc(&r),
                if evidence {
                    ""
                } else {
                    ": içerik kanıtı yok, tek başına ŞÜPHELİ (elle doğrulayın)"
                }
            ),
        );
        decide(&mut b);
        st.flagged += 1;
        st.worst = st.worst.max(b.verdict);
        let bp = b.path.clone();
        let bv = b.verdict;
        let b = Arc::new(b);
        let kind = if rip {
            "UNBACKED THREAD (şu an dosyasız bellekte çalışıyor)"
        } else {
            "UNBACKED THREAD (dosyasız bellekte başlıyor)"
        };
        let ix = self.register(
            kind,
            &bp,
            Some(b.clone()),
            &format!(
                "TID {} {} 0x{:X}; bölge {}; baytlar: {}",
                tid,
                what,
                a,
                reg_desc(&r),
                Self::hex_at(t.h, a, 16)
            ),
            "",
        );
        let better = match &self.findings[ix].an {
            None => true,
            Some(old) => b.verdict > old.verdict,
        };
        if better {
            self.findings[ix].an = Some(b);
        }
        self.out(
            &format!(
                "  [!] TID {} {} dosyasız bellekte (0x{:X}, {}) içerik: {}",
                tid,
                if rip { "şu an" } else { "başlıyor" },
                a,
                reg_desc(&r),
                verdict_tag(bv)
            ),
            if bv == Verdict::Confirmed { COL_RED } else { COL_YEL },
        );
    }

    pub fn phase_unbacked(&mut self, t: &mut Target) {
        self.begin_phase(4, "Unbacked Thread taraması");
        let (summary, col) = self.phase_unbacked_inner(t);
        self.end_phase_guard(&summary, col);
    }

    fn phase_unbacked_inner(&mut self, t: &mut Target) -> (String, usize) {
        let Some(qit) = self.nt.qit else {
            return ("atlandı (NtQueryInformationThread yok)".into(), COL_YEL);
        };
        let s = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) } {
            Ok(s) => s,
            Err(_) => return ("atlandı (thread listesi alınamadı)".into(), COL_YEL),
        };
        t.regs = enum_regions(t.h);
        if t.regs.is_empty() {
            unsafe {
                let _ = CloseHandle(s);
            }
            return (
                "atlandı (bellek haritası alınamadı: süreç kapanıyor veya erişim yok)".into(),
                COL_YEL,
            );
        }
        {
            let fresh = self.list_modules(t.h);
            if !fresh.is_empty() {
                t.mods = fresh; // faz 1'den sonra yüklenen modüllerin thread'leri "dosyasız" sayılmasın
            }
        }
        let me = unsafe { GetCurrentThreadId() };
        let mut te: THREADENTRY32 = unsafe { std::mem::zeroed() };
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut st = ThreadStats::default();
        let (mut n, mut deep_n) = (0usize, 0usize);
        let mut threads: Vec<(u32, u64)> = Vec::new();
        let mut more = unsafe { Thread32First(s, &mut te) }.is_ok();
        while more {
            if te.th32OwnerProcessID == t.pid && te.th32ThreadID != me {
                let th = unsafe { OpenThread(THREAD_QUERY_INFORMATION, false, te.th32ThreadID) }
                    .or_else(|_| unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, te.th32ThreadID) });
                if let Ok(th) = th {
                    let mut stp: usize = 0;
                    let mut rl = 0u32;
                    let rc = unsafe {
                        qit(
                            th,
                            9,
                            &mut stp as *mut _ as *mut core::ffi::c_void,
                            std::mem::size_of::<usize>() as u32,
                            &mut rl,
                        )
                    };
                    unsafe {
                        let _ = CloseHandle(th);
                    }
                    if rc >= 0 {
                        threads.push((te.th32ThreadID, stp as u64));
                    }
                }
            }
            more = unsafe { Thread32Next(s, &mut te) }.is_ok();
        }
        unsafe {
            let _ = CloseHandle(s);
        }
        let mut reg_an: BTreeMap<u64, Arc<Analysis>> = BTreeMap::new();
        for th in &threads {
            n += 1;
            self.prog_set(0.7 * n as f64 / threads.len() as f64);
            if th.1 != 0 {
                self.check_thread(t, th.0, th.1, false, &mut reg_an, &mut st);
            }
        }
        if self.cfg.deep_threads && !t.wow64 {
            for th in &threads {
                if deep_n >= 600 {
                    break;
                }
                if let Some(rip) = Self::thread_rip(th.0) {
                    if rip != 0 {
                        deep_n += 1;
                        self.check_thread(t, th.0, rip, true, &mut reg_an, &mut st);
                    }
                }
            }
        }
        let mut reg_scanned = 0;
        {
            let mut seen_alloc: BTreeSet<u64> = BTreeSet::new();
            let regs = t.regs.clone();
            let mut ri = 0usize;
            while ri < regs.len() && reg_scanned < 80 {
                self.prog_set(0.75 + 0.25 * ri as f64 / regs.len() as f64);
                let r = regs[ri];
                ri += 1;
                if r.state != MEM_COMMIT_V || r.typ == MEM_IMAGE_V || !is_exec_prot(r.protect) || r.size < 4096 {
                    continue;
                }
                if reg_an.contains_key(&r.alloc_base) || !seen_alloc.insert(r.alloc_base) {
                    continue; // thread kontrolünde zaten incelendi
                }
                if Self::group_span(t, r.alloc_base) >= (24 << 20) {
                    continue; // JVM JIT kod önbelleği
                }
                if r.typ == MEM_MAPPED_V {
                    let mn = mapped_name(&self.dev_map, t.h, r.alloc_base);
                    if !mn.is_empty() && file_exists(&mn) {
                        let si = self.sigs.verify_cached(&mn);
                        if si.valid && si.trusted {
                            continue;
                        }
                    }
                }
                let mut mem = Vec::new();
                let sz = (r.base + r.size - r.alloc_base).min(8 << 20) as usize;
                if !read_mem(t.h, r.alloc_base, sz, &mut mem) {
                    continue;
                }
                let mut a = Analysis::default();
                let o = AnalyzeOpts {
                    mem_image: false,
                    auto_layout: true,
                    ..Default::default()
                };
                analyze_buffer(&mem, &o, &mut a);
                reg_scanned += 1;
                if !(a.is_pe || a.s > 0 || a.t >= 25) {
                    continue;
                }
                a.path = format!("<bellek 0x{:X}>", r.alloc_base);
                a.sig_text = "bellek bölgesi (dosya yok)".into();
                let pe_note = if a.is_pe { " (PE başlığı duruyor)" } else { "" };
                add_ev(
                    &mut a,
                    'H',
                    30,
                    &format!(
                        "Dosyasız yürütülebilir bellek bölgesi (0x{:X}, {}) hile/JVM-Minecraft içeriği taşıyor{}: manuel map / enjekte edilmiş kod (thread veya hook olmasa bile)",
                        r.alloc_base,
                        reg_desc(&r),
                        pe_note
                    ),
                );
                decide(&mut a);
                let ap = a.path.clone();
                let av = a.verdict;
                self.register(
                    "UNBACKED BELLEK (dosyasız yürütülebilir bölge: içerik kanıtı)",
                    &ap,
                    Some(Arc::new(a)),
                    &format!("bölge {}", reg_desc(&r)),
                    "",
                );
                st.flagged += 1;
                st.worst = st.worst.max(av);
                self.out(
                    &format!(
                        "  [!] dosyasız yürütülebilir bölge 0x{:X} ({}) içerik: {}",
                        r.alloc_base,
                        reg_desc(&r),
                        verdict_tag(av)
                    ),
                    if av == Verdict::Confirmed { COL_RED } else { COL_YEL },
                );
            }
        }
        let summary = format!(
            "{} thread ({} modül-içi{}){}{}{}",
            n,
            st.backed,
            if self.cfg.deep_threads {
                format!(", {} RIP kontrolü", deep_n)
            } else {
                String::new()
            },
            if st.flagged != 0 {
                format!("  -> {} UNBACKED/yetim thread", st.flagged)
            } else {
                "  temiz".to_string()
            },
            if self.hid_flagged != 0 {
                format!("  | gizli görüntü: {}", self.hid_flagged)
            } else {
                String::new()
            },
            if st.in_cheat != 0 {
                format!("  | hile modülünde aktif thread: {}", st.in_cheat)
            } else {
                String::new()
            }
        );
        let col = if st.flagged != 0 || self.hid_flagged != 0 || st.in_cheat != 0 {
            if st.worst == Verdict::Confirmed || self.hid_flagged != 0 || st.in_cheat != 0 {
                COL_RED
            } else {
                COL_YEL
            }
        } else {
            COL_GRN
        };
        (summary, col)
    }
}

#[derive(Default)]
pub struct ThreadStats {
    pub backed: i32,
    pub in_cheat: i32,
    pub flagged: i32,
    pub worst: Verdict,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_split() {
        assert_eq!(split_cmd("a \"b c\" d"), vec!["a", "b c", "d"]);
    }
    #[test]
    fn prot() {
        assert_eq!(prot_str(0x40), "RWX");
        assert!(is_exec_prot(0x20));
        assert!(!is_exec_prot(0x04));
    }
    #[test]
    fn mclike() {
        assert!(mc_like("java -cp lwjgl.jar"));
        assert!(!mc_like("notepad"));
    }
}
