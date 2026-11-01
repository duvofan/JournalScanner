use crate::classfile::ClassInfo;
use crate::jbytecode::{JavaAcc, JavaProfile};
use crate::pat_data::C_COUNT;
use crate::pe::PeInfo;
use crate::util::*;
use std::collections::{BTreeMap, BTreeSet};

pub fn bs(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[inline]
fn at(d: &[u8], i: usize) -> u8 {
    d.get(i).copied().unwrap_or(0)
}

pub fn vk_name(vk: u32) -> String {
    const T: &[(u32, &str)] = &[
        (0x01, "LBUTTON"),
        (0x02, "RBUTTON"),
        (0x04, "MBUTTON"),
        (0x05, "XBUTTON1"),
        (0x06, "XBUTTON2"),
        (0x08, "BACKSPACE"),
        (0x09, "TAB"),
        (0x0D, "ENTER"),
        (0x10, "SHIFT"),
        (0x11, "CTRL"),
        (0x12, "ALT"),
        (0x13, "PAUSE"),
        (0x14, "CAPSLOCK"),
        (0x1B, "ESC"),
        (0x20, "SPACE"),
        (0x21, "PAGEUP"),
        (0x22, "PAGEDOWN"),
        (0x23, "END"),
        (0x24, "HOME"),
        (0x25, "LEFT"),
        (0x26, "UP"),
        (0x27, "RIGHT"),
        (0x28, "DOWN"),
        (0x2C, "PRINTSCREEN"),
        (0x2D, "INSERT"),
        (0x2E, "DELETE"),
        (0x5B, "LWIN"),
        (0x5C, "RWIN"),
        (0x90, "NUMLOCK"),
        (0x91, "SCROLLLOCK"),
        (0xA0, "LSHIFT"),
        (0xA1, "RSHIFT"),
        (0xA2, "LCTRL"),
        (0xA3, "RCTRL"),
        (0xA4, "LALT"),
        (0xA5, "RALT"),
        (0xBA, ";"),
        (0xBB, "="),
        (0xBC, ","),
        (0xBD, "-"),
        (0xBE, "."),
        (0xBF, "/"),
        (0xC0, "`"),
        (0xDB, "["),
        (0xDC, "\\"),
        (0xDD, "]"),
        (0xDE, "'"),
    ];
    for (v, n) in T {
        if *v == vk {
            return n.to_string();
        }
    }
    if (0x30..=0x39).contains(&vk) || (0x41..=0x5A).contains(&vk) {
        return (vk as u8 as char).to_string();
    }
    if (0x60..=0x69).contains(&vk) {
        return format!("NUMPAD{}", vk - 0x60);
    }
    if (0x70..=0x87).contains(&vk) {
        return format!("F{}", vk - 0x6F);
    }
    format!("VK_0x{:02X}", vk)
}

#[derive(Debug, Clone, Default)]
pub struct Ev {
    pub cls: char,
    pub w: i32,
    pub text: String,
}

#[derive(Debug, Clone, Default)]
pub struct KeyUse {
    pub vk: u32,
    pub api: String,
    pub rva: u32,
    pub near_unload: bool,
    pub count: i32,
    pub exit_branch: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SdProfile {
    pub unload: bool,
    pub file_del: bool,
    pub mem_wipe: bool,
    pub cmd_del: bool,
    pub peb_unlink: bool,
    pub sd_str: bool,
    pub level: i32,
    pub level_name: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum Verdict {
    Tool = -1,
    #[default]
    Clean = 0,
    Info = 1,
    Suspect = 2,
    Confirmed = 3,
}

#[derive(Debug, Clone, Default)]
pub struct Hit1 {
    pub text: String,
    pub off: usize,
}

#[derive(Debug, Clone, Default)]
pub struct HiddenStr {
    pub text: String,
    pub how: String,
    pub off: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AnalyzeOpts {
    pub mem_image: bool,
    pub auto_layout: bool,
    pub in_user_dir: bool,
    pub keep_strings: bool,
}

#[derive(Clone)]
pub struct Analysis {
    pub path: String,
    pub sig_text: String,
    pub sig_valid: bool,
    pub in_user_dir: bool,
    pub size: usize,
    pub sha: String,
    pub entropy: f64,
    pub pe: PeInfo,
    pub is_pe: bool,
    pub mem_image: bool,
    pub hits: BTreeMap<i32, Hit1>,
    pub phits: BTreeMap<i32, Hit1>,
    pub mc_refs: BTreeSet<String>,
    pub srg: BTreeSet<String>,
    pub urls: BTreeSet<String>,
    pub ips: BTreeSet<String>,
    pub paths: BTreeSet<String>,
    pub cmds: BTreeSet<String>,
    pub regs: BTreeSet<String>,
    pub dict_s: BTreeSet<String>,
    pub jni_desc: Vec<String>,
    pub jni_desc_count: i32,
    pub keys: Vec<KeyUse>,
    pub unload_sites: Vec<String>,
    pub jvmti_const: bool,
    pub jvmti_ver: u32,
    pub peb_walk: bool,
    pub fnv_hash: bool,
    pub bypass_const: bool,
    pub classes: Vec<ClassInfo>,
    pub zip_names: Vec<String>,
    pub zip_count: i32,
    pub jacc: JavaAcc,
    pub jv: JavaProfile,
    pub jmeta: BTreeMap<String, Vec<u8>>,
    pub beh_red: bool,
    pub beh_yellow: bool,
    pub packer: String,
    pub packer_strong: bool,
    pub pdb_sus: bool,
    pub cat_labels: Vec<Vec<String>>,
    pub pay_cat_labels: Vec<Vec<String>>,
    pub ev: Vec<Ev>,
    pub s: i32,
    pub t: i32,
    pub h: i32,
    pub verdict: Verdict,
    pub vreason: String,
    pub sd: SdProfile,
    pub client_distinct: i32,
    pub fam_w: i32,
    pub has_marker: bool,
    pub fam_strong: bool,
    pub strong_s: bool,
    pub trusted: bool,
    pub jvm_cap: bool,
    pub pdb_family: bool,
    pub benign_jvm: bool,
    pub benign_cef: bool,
    pub strs: Vec<String>,
    pub hidden: Vec<HiddenStr>,
    pub hid_stack: i32,
    pub hid_xor: i32,
    pub hid_payload: i32,
}

impl Default for Analysis {
    fn default() -> Self {
        Analysis {
            path: String::new(),
            sig_text: String::new(),
            sig_valid: false,
            in_user_dir: false,
            size: 0,
            sha: String::new(),
            entropy: 0.0,
            pe: PeInfo::default(),
            is_pe: false,
            mem_image: false,
            hits: BTreeMap::new(),
            phits: BTreeMap::new(),
            mc_refs: BTreeSet::new(),
            srg: BTreeSet::new(),
            urls: BTreeSet::new(),
            ips: BTreeSet::new(),
            paths: BTreeSet::new(),
            cmds: BTreeSet::new(),
            regs: BTreeSet::new(),
            dict_s: BTreeSet::new(),
            jni_desc: Vec::new(),
            jni_desc_count: 0,
            keys: Vec::new(),
            unload_sites: Vec::new(),
            jvmti_const: false,
            jvmti_ver: 0,
            peb_walk: false,
            fnv_hash: false,
            bypass_const: false,
            classes: Vec::new(),
            zip_names: Vec::new(),
            zip_count: 0,
            jacc: JavaAcc::default(),
            jv: JavaProfile::default(),
            jmeta: BTreeMap::new(),
            beh_red: false,
            beh_yellow: false,
            packer: String::new(),
            packer_strong: false,
            pdb_sus: false,
            cat_labels: vec![Vec::new(); C_COUNT],
            pay_cat_labels: vec![Vec::new(); C_COUNT],
            ev: Vec::new(),
            s: 0,
            t: 0,
            h: 0,
            verdict: Verdict::Clean,
            vreason: String::new(),
            sd: SdProfile::default(),
            client_distinct: 0,
            fam_w: 0,
            has_marker: false,
            fam_strong: false,
            strong_s: false,
            trusted: false,
            jvm_cap: false,
            pdb_family: false,
            benign_jvm: false,
            benign_cef: false,
            strs: Vec::new(),
            hidden: Vec::new(),
            hid_stack: 0,
            hid_xor: 0,
            hid_payload: 0,
        }
    }
}

pub fn add_ev(a: &mut Analysis, cls: char, w: i32, t: &str) {
    a.ev.push(Ev {
        cls,
        w,
        text: t.to_string(),
    });
    match cls {
        'S' => a.s += w,
        'T' => a.t += w,
        'H' => a.h += w,
        _ => {}
    }
}

pub fn add_cap(s: &mut BTreeSet<String>, v: String, cap: usize) {
    if s.len() < cap {
        s.insert(v);
    }
}

pub fn noisy_url(u: &str) -> bool {
    const SKIP: [&str; 23] = [
        "microsoft.com",
        "w3.org",
        "verisign",
        "symantec",
        "digicert",
        "sectigo",
        "globalsign",
        "thawte",
        "entrust",
        "usertrust",
        "comodo",
        "godaddy",
        "apache.org",
        "openssl.org",
        "gnu.org",
        "xml.org",
        "aka.ms",
        "oracle.com",
        "java.com",
        "openjdk",
        "mojang.com",
        "minecraft.net",
        "windowsupdate",
    ];
    let l = lower_str(u);
    SKIP.iter().any(|s| l.contains(s))
}

pub fn find_ipv4(s: &[u8]) -> String {
    let n = s.len();
    for i in 0..n {
        if !is_dig(s[i]) {
            continue;
        }
        if i > 0 && (is_alnum(s[i - 1]) || s[i - 1] == b'.') {
            continue;
        }
        let mut parts = 0usize;
        let mut j = i;
        let mut ok = true;
        let mut v = [0u32; 4];
        while parts < 4 && j < n && is_dig(s[j]) {
            let st = j;
            let mut val = 0u32;
            while j < n && is_dig(s[j]) && j - st < 4 {
                val = val * 10 + (s[j] - b'0') as u32;
                j += 1;
            }
            if j - st > 3 || val > 255 || (j - st > 1 && s[st] == b'0') {
                ok = false;
                break;
            }
            v[parts] = val;
            parts += 1;
            if parts < 4 {
                if j < n && s[j] == b'.' {
                    j += 1;
                } else {
                    ok = false;
                    break;
                }
            }
        }
        if !ok || parts != 4 {
            continue;
        }
        if j < n && (is_alnum(s[j]) || s[j] == b'.') {
            continue;
        }
        if v[0] == 0
            || v[0] == 10
            || v[0] == 127
            || v[0] == 255
            || (v[0] == 169 && v[1] == 254)
            || (v[0] == 192 && v[1] == 168)
            || (v[0] == 172 && (16..=31).contains(&v[1]))
        {
            continue;
        }
        if v[0] < 20 && v[1] < 20 && v[2] < 20 && v[3] < 20 {
            continue; // sürüm numarası gibi
        }
        return bs(&s[i..j]);
    }
    String::new()
}

fn find_from(h: &[u8], k: &[u8], from: usize) -> Option<usize> {
    if from > h.len() {
        return None;
    }
    memchr::memmem::find(&h[from..], k).map(|i| i + from)
}

pub fn contains(h: &[u8], k: &str) -> bool {
    memchr::memmem::find(h, k.as_bytes()).is_some()
}

pub fn collect_mc(low: &[u8], a: &mut Analysis) {
    const KEYS: [&str; 5] = [
        "net/minecraft/",
        "net.minecraft.",
        "com/mojang/",
        "net/minecraftforge/",
        "net/fabricmc/",
    ];
    for k in KEYS {
        let kl = k.len();
        let mut pos = 0usize;
        while let Some(pp) = find_from(low, k.as_bytes(), pos) {
            pos = pp;
            let mut e = pos + kl;
            while e < low.len() && (is_alnum(low[e]) || matches!(low[e], b'_' | b'/' | b'$' | b'.')) {
                e += 1;
            }
            if e > pos + kl && a.mc_refs.len() < 4000 {
                a.mc_refs.insert(bs(&low[pos..pos + (e - pos).min(120)]));
            }
            pos = e;
        }
    }
}

pub fn collect_srg(low: &[u8], a: &mut Analysis) {
    const KEYS: [&str; 4] = ["field_", "method_", "class_", "func_"];
    for k in KEYS {
        let kl = k.len();
        let mut pos = 0usize;
        while let Some(pp) = find_from(low, k.as_bytes(), pos) {
            pos = pp;
            let left_ok = pos == 0 || !is_alnum(low[pos - 1]);
            let mut e = pos + kl;
            while e < low.len() && is_dig(low[e]) {
                e += 1;
            }
            if left_ok && e - (pos + kl) >= 3 && a.srg.len() < 1000 {
                a.srg.insert(bs(&low[pos..e]));
            }
            pos = if e > pos { e } else { pos + 1 };
        }
    }
}

pub fn looks_jni_desc(s: &[u8]) -> bool {
    let n = s.len();
    if n < 3 || n > 220 || s[0] != b'(' {
        return false;
    }
    let mut i = 1usize;
    let ty = |allow_v: bool, i: &mut usize| -> bool {
        while *i < n && s[*i] == b'[' {
            *i += 1;
        }
        if *i >= n {
            return false;
        }
        let c = s[*i];
        if c == b'L' {
            let mut e = *i + 1;
            while e < n && s[e] != b';' {
                let ch = s[e];
                if !(is_alnum(ch) || ch == b'/' || ch == b'$' || ch == b'_') {
                    return false;
                }
                e += 1;
            }
            if e >= n || e == *i + 1 {
                return false;
            }
            *i = e + 1;
            return true;
        }
        if c == b'V' {
            if !allow_v {
                return false;
            }
            *i += 1;
            return true;
        }
        if matches!(c, b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z') {
            *i += 1;
            return true;
        }
        false
    };
    while i < n && s[i] != b')' {
        if !ty(false, &mut i) {
            return false;
        }
    }
    if i >= n || s[i] != b')' {
        return false;
    }
    i += 1;
    if !ty(true, &mut i) {
        return false;
    }
    i == n
}

pub fn collect_misc(s: &[u8], low: &[u8], a: &mut Analysis) {
    let n = s.len();
    if n >= 8 {
        collect_mc(low, a);
        collect_srg(low, a);
        if let Some(u) = find_from(low, b"http", 0) {
            if low[u..].starts_with(b"http://") || low[u..].starts_with(b"https://") {
                let mut e = u;
                while e < n && !matches!(s[e], b' ' | b'"' | b'\'' | b'<' | b'>') {
                    e += 1;
                }
                let url = bs(&s[u..u + (e - u).min(200)]);
                if url.len() >= 12 && url.as_bytes().get(8..).is_some_and(|t| t.contains(&b'.')) && !noisy_url(&url) {
                    add_cap(&mut a.urls, url, 40);
                }
            }
        }
        let ip = find_ipv4(s);
        if !ip.is_empty() {
            add_cap(&mut a.ips, ip, 20);
        }
        if n >= 6 && is_al(s[0]) && s[1] == b':' && s[2] == b'\\' {
            add_cap(&mut a.paths, bs(&s[..n.min(200)]), 50);
        }
        if low.starts_with(b"software\\") || low.starts_with(b"hkey_") {
            add_cap(&mut a.regs, bs(&s[..n.min(160)]), 20);
        }
        if contains(low, "cmd /c")
            || contains(low, "cmd.exe")
            || contains(low, "powershell")
            || contains(low, "del /")
            || contains(low, "attrib ")
            || contains(low, "ping ")
        {
            add_cap(&mut a.cmds, bs(&s[..n.min(200)]), 20);
        }
    }
    if looks_jni_desc(s) {
        a.jni_desc_count += 1;
        if a.jni_desc.len() < 12 {
            a.jni_desc.push(bs(s));
        }
    }
}

fn same_func(d: &[u8], a: usize, b: usize) -> bool {
    let n = d.len();
    let (a, mut b) = if a > b { (b, a) } else { (a, b) };
    if b >= n {
        b = n - 1;
    }
    let mut run = 0;
    for i in a..=b {
        if d[i] == 0xCC {
            run += 1;
            if run >= 4 {
                return false;
            }
        } else {
            run = 0;
        }
    }
    true
}

pub fn key_of_interest(v: u32) -> bool {
    v == 0x2D
        || v == 0x2E
        || v == 0x24
        || v == 0x23
        || v == 0x21
        || v == 0x22
        || v == 0x13
        || v == 0x91
        || (0x70..=0x7B).contains(&v)
        || v == 0xA1
        || v == 0xA3
        || v == 0xA5
        || v == 0xC0
        || v == 0xDC
        || v == 0xDB
        || v == 0xDD
}

fn volatile_reg(r: i32) -> bool {
    r == 0 || r == 1 || r == 2 || (8..=11).contains(&r)
}

pub fn off_to_rva(pe: &PeInfo, off: usize) -> u32 {
    if pe.mem_layout {
        return off as u32;
    }
    for sc in &pe.secs {
        if off >= sc.raw_ptr as usize && (off as u64) < sc.raw_ptr as u64 + sc.raw_size as u64 {
            return sc.rva.wrapping_add((off - sc.raw_ptr as usize) as u32);
        }
    }
    off as u32
}

struct XSec {
    off: usize,
    len: usize,
    va: u64,
}

fn rel_target(va: u64, ilen: u64, rel: u32) -> u64 {
    va.wrapping_add(ilen).wrapping_add(rel as i32 as i64 as u64)
}

pub fn analyze_code(d: &[u8], a: &mut Analysis) {
    let n = d.len();
    let mut xs: Vec<XSec> = Vec::new();
    for s in &a.pe.secs {
        if s.chars & 0x2000_0000 == 0 && s.chars & 0x20 == 0 {
            continue;
        }
        let (off, mut len) = if a.pe.mem_layout {
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
        xs.push(XSec {
            off,
            len,
            va: a.pe.image_base.wrapping_add(s.rva as u64),
        });
    }
    let is64 = a.pe.is64;
    let mut slots: BTreeMap<u64, String> = BTreeMap::new();
    for im in &a.pe.imps {
        let f = lower_str(&im.func);
        if matches!(
            f.as_str(),
            "getasynckeystate"
                | "getkeystate"
                | "registerhotkey"
                | "freelibraryandexitthread"
                | "freelibrary"
                | "getkeyboardstate"
                | "getrawinputdata"
        ) {
            slots.insert(im.slot_va, f);
        }
    }
    let mut thunks: BTreeMap<u64, String> = BTreeMap::new();
    let mut calls: Vec<(usize, String)> = Vec::new();
    let tgt = |va: u64, q: usize, ilen: u64, rel_at: usize| -> u64 {
        if is64 {
            rel_target(va, ilen, rd32(d, rel_at))
        } else {
            let _ = q;
            rd32(d, rel_at) as u64
        }
    };
    if !slots.is_empty() {
        for s in &xs {
            let mut i = 0usize;
            while i + 6 <= s.len {
                let q = s.off + i;
                if d[q] == 0xFF && d[q + 1] == 0x25 {
                    let va = s.va.wrapping_add(i as u64);
                    let target = tgt(va, q, 6, q + 2);
                    if let Some(v) = slots.get(&target) {
                        thunks.insert(va, v.clone());
                    }
                }
                i += 1;
            }
        }
    }
    if !slots.is_empty() {
        for s in &xs {
            let mut i = 0usize;
            while i + 6 <= s.len {
                let q = s.off + i;
                if d[q] == 0xFF && d[q + 1] == 0x15 {
                    let va = s.va.wrapping_add(i as u64);
                    let target = tgt(va, q, 6, q + 2);
                    if let Some(v) = slots.get(&target) {
                        calls.push((q, v.clone()));
                    }
                } else if d[q] == 0xE8 && !thunks.is_empty() {
                    let va = s.va.wrapping_add(i as u64);
                    let target = rel_target(va, 5, rd32(d, q + 1));
                    if let Some(v) = thunks.get(&target) {
                        calls.push((q, v.clone()));
                    }
                } else if !is64 && ((d[q] == 0x8B && (d[q + 1] & 0xC7) == 0x05) || d[q] == 0xA1) && i + 6 <= s.len {
                    let short_form = d[q] == 0xA1;
                    let key = rd32(d, q + if short_form { 1 } else { 2 }) as u64;
                    if let Some(v) = slots.get(&key) {
                        let reg: i32 = if short_form { 0 } else { ((d[q + 1] >> 3) & 7) as i32 };
                        let base = if short_form { 5 } else { 6 };
                        let win = if volatile_reg(reg) { 24 } else { 1400 };
                        let mut k = base;
                        while k < win && i + k + 2 <= s.len {
                            let r = q + k;
                            if d[r] == 0xFF && d[r + 1] == (0xD0 + reg) as u8 {
                                calls.push((s.off + i + k, v.clone()));
                                if volatile_reg(reg) {
                                    break;
                                }
                            }
                            k += 1;
                        }
                    }
                } else if is64
                    && (d[q] == 0x48 || d[q] == 0x4C)
                    && d[q + 1] == 0x8B
                    && (d[q + 2] & 0xC7) == 0x05
                    && i + 7 <= s.len
                {
                    let va = s.va.wrapping_add(i as u64);
                    let target = rel_target(va, 7, rd32(d, q + 3));
                    if let Some(v) = slots.get(&target) {
                        let reg: i32 = ((d[q + 2] >> 3) & 7) as i32 + if d[q] == 0x4C { 8 } else { 0 };
                        let win = if volatile_reg(reg) { 24 } else { 1400 };
                        let mut k = 7;
                        while k < win && i + k + 3 <= s.len {
                            let r = q + k;
                            let hit = if reg < 8 {
                                d[r] == 0xFF && d[r + 1] == (0xD0 + reg) as u8
                            } else {
                                d[r] == 0x41 && d[r + 1] == 0xFF && d[r + 2] == (0xD0 + reg - 8) as u8
                            };
                            if hit {
                                calls.push((s.off + i + k, v.clone()));
                                if volatile_reg(reg) {
                                    break;
                                }
                            }
                            k += 1;
                        }
                    }
                }
                i += 1;
            }
        }
    }
    let mut unload_at: Vec<usize> = Vec::new();
    for c in &calls {
        if c.1 == "freelibraryandexitthread" || c.1 == "freelibrary" {
            unload_at.push(c.0);
        }
    }
    for &u in &unload_at {
        if a.unload_sites.len() < 6 {
            a.unload_sites.push(hex(off_to_rva(&a.pe, u) as u64));
        }
    }
    let exit_branch = |ci: usize| -> bool {
        let len;
        if ci + 6 <= n && d[ci] == 0xFF && d[ci + 1] == 0x15 {
            len = 6;
        } else if ci + 5 <= n && d[ci] == 0xE8 {
            len = 5;
        } else if ci + 2 <= n && d[ci] == 0xFF && (d[ci + 1] & 0xF8) == 0xD0 {
            len = 2;
        } else if ci + 3 <= n && d[ci] == 0x41 && d[ci + 1] == 0xFF {
            len = 3;
        } else {
            return false;
        }
        let mut k = ci + len;
        while k < ci + len + 14 && k + 2 <= n {
            let (rel, inst_end): (i64, usize);
            if (0x70..=0x7F).contains(&d[k]) {
                rel = d[k + 1] as i8 as i64;
                inst_end = k + 2;
            } else if d[k] == 0x0F && k + 6 <= n && (0x80..=0x8F).contains(&d[k + 1]) {
                rel = rd32(d, k + 2) as i32 as i64;
                inst_end = k + 6;
            } else {
                k += 1;
                continue;
            }
            let target = inst_end as i64 + rel;
            if target > inst_end as i64 {
                for &u in &unload_at {
                    if u as i64 >= target && u as i64 - target <= 0x60 {
                        return true;
                    }
                }
            }
            return false;
        }
        false
    };
    let mut found: BTreeMap<(u32, String), KeyUse> = BTreeMap::new();
    for c in &calls {
        if c.1 != "getasynckeystate" && c.1 != "getkeystate" && c.1 != "registerhotkey" {
            continue;
        }
        let ci = c.0;
        let mut vk = 0u32;
        let mut got = false;
        if is64 {
            let lo = ci.saturating_sub(28);
            let mut j = ci;
            while j > lo + 4 && !got {
                j -= 1;
                if c.1 == "registerhotkey" {
                    if d[j - 1] == 0x41 && d[j] == 0xB9 && j + 5 <= n {
                        let v = rd32(d, j + 1);
                        if v != 0 && v <= 0xFF {
                            vk = v;
                            got = true;
                        }
                    }
                } else if d[j] == 0xB9 && j + 5 <= n {
                    let v = rd32(d, j + 1);
                    if v != 0 && v <= 0xFF {
                        vk = v;
                        got = true;
                    }
                }
            }
        } else {
            let lo = ci.saturating_sub(24);
            let mut j = ci;
            while j > lo && !got {
                j -= 1;
                if d[j] == 0x6A && j + 2 <= n && at(d, j + 1) != 0 && at(d, j + 1) < 0x80 {
                    vk = d[j + 1] as u32;
                    got = true;
                } else if d[j] == 0x68 && j + 5 <= n {
                    let v = rd32(d, j + 1);
                    if v != 0 && v <= 0xFF {
                        vk = v;
                        got = true;
                    }
                } else if d[j] == 0xC7 && j + 7 <= n && at(d, j + 1) == 0x04 && at(d, j + 2) == 0x24 {
                    let v = rd32(d, j + 3);
                    if v != 0 && v <= 0xFF {
                        vk = v;
                        got = true;
                    }
                }
            }
        }
        if !got {
            continue;
        }
        let key = (vk, c.1.clone());
        let near = |ci: usize, unload_at: &[usize]| -> bool {
            for &u in unload_at {
                let dist = if u > ci { u - ci } else { ci - u };
                if dist < 0x3000 && same_func(d, ci, u) {
                    return true;
                }
            }
            false
        };
        match found.get_mut(&key) {
            None => {
                let api = match c.1.as_str() {
                    "getasynckeystate" => "GetAsyncKeyState",
                    "getkeystate" => "GetKeyState",
                    _ => "RegisterHotKey",
                };
                let ku = KeyUse {
                    vk,
                    api: api.to_string(),
                    rva: off_to_rva(&a.pe, ci),
                    near_unload: near(ci, &unload_at),
                    count: 1,
                    exit_branch: exit_branch(ci),
                };
                found.insert(key, ku);
            }
            Some(it) => {
                it.count += 1;
                if !it.exit_branch && exit_branch(ci) {
                    it.exit_branch = true;
                }
                if !it.near_unload && near(ci, &unload_at) {
                    it.near_unload = true;
                }
            }
        }
    }
    for (_, v) in found {
        a.keys.push(v);
    }
    {
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        let mut cnt = 0;
        for s in &xs {
            let mut i = 0usize;
            while i + 8 < s.len && cnt < 6 {
                let q = s.off + i;
                let after: usize;
                if d[q] == 0x3D && rd32(d, q + 1) == 0x100 {
                    after = 5;
                } else if d[q] == 0x81 && (at(d, q + 1) & 0xF8) == 0xF8 && rd32(d, q + 2) == 0x100 {
                    after = 6;
                } else if d[q] == 0x41
                    && at(d, q + 1) == 0x81
                    && (at(d, q + 2) & 0xF8) == 0xF8
                    && rd32(d, q + 3) == 0x100
                {
                    after = 7;
                } else {
                    i += 1;
                    continue;
                }
                let lim = (s.len - i - after).min(48);
                for k in 0..lim {
                    let r = q + after + k;
                    let v: u32;
                    if (d[r] == 0x83 || d[r] == 0x80) && (at(d, r + 1) & 0xF8) == 0xF8 {
                        v = at(d, r + 2) as u32;
                    } else if (d[r] == 0x41 || d[r] == 0x48 || d[r] == 0x49)
                        && (at(d, r + 1) == 0x83 || at(d, r + 1) == 0x80)
                        && (at(d, r + 2) & 0xF8) == 0xF8
                    {
                        v = at(d, r + 3) as u32;
                    } else if d[r] == 0x3C {
                        v = at(d, r + 1) as u32;
                    } else {
                        continue;
                    }
                    if key_of_interest(v) && !seen.contains(&v) {
                        seen.insert(v);
                        cnt += 1;
                        a.keys.push(KeyUse {
                            vk: v,
                            api: "WM_KEYDOWN karşılaştırması (olası menu/GUI tuşu)".to_string(),
                            rva: s.va.wrapping_sub(a.pe.image_base).wrapping_add(i as u64) as u32,
                            near_unload: false,
                            count: 1,
                            exit_branch: false,
                        });
                    }
                }
                i += 1;
            }
        }
    }
    for s in &xs {
        let mut i = 0usize;
        while i + 9 <= s.len {
            let q = s.off + i;
            if is64 {
                if d[q] == 0x65
                    && (d[q + 1] == 0x48 || d[q + 1] == 0x4C)
                    && d[q + 2] == 0x8B
                    && (d[q + 3] & 0xC7) == 0x04
                    && d[q + 4] == 0x25
                    && rd32(d, q + 5) == 0x60
                {
                    a.peb_walk = true;
                }
            } else {
                if d[q] == 0x64 && d[q + 1] == 0xA1 && rd32(d, q + 2) == 0x30 {
                    a.peb_walk = true;
                }
                if d[q] == 0x64 && d[q + 1] == 0x8B && (d[q + 2] & 0xC7) == 0x05 && rd32(d, q + 3) == 0x30 {
                    a.peb_walk = true;
                }
            }
            if i >= 2 && d[q] == 0x93 && d[q + 1] == 0x01 && d[q + 2] == 0x00 && d[q + 3] == 0x01 && d[q - 2] == 0x69 {
                a.fnv_hash = true;
            }
            if i >= 2 {
                let v = rd32(d, q);
                let m1 = d[q - 1];
                let m2 = d[q - 2];
                let op =
                    (0xB8..=0xBF).contains(&m1) || m1 == 0x68 || (i >= 3 && m2 == 0x41 && (0xB8..=0xBF).contains(&m1));
                if op
                    && (v == 0x3001_0000
                        || v == 0x3001_0100
                        || v == 0x3001_0200
                        || v == 0x3009_0000
                        || v == 0x300B_0000
                        || v == 0x3013_0000
                        || v == 0x3015_0000)
                {
                    a.jvmti_const = true;
                    a.jvmti_ver = v;
                }
                let op2 = (0xB8..=0xBF).contains(&m1)
                    || m1 == 0x3D
                    || (i >= 3 && (m2 == 0x41 || m2 == 0x81) && m1 >= 0xB8)
                    || (m2 == 0x81 && (m1 & 0xF8) == 0xF8);
                if op2 && v == 0xFCE0_1E99 {
                    a.bypass_const = true;
                }
            }
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vk() {
        assert_eq!(vk_name(0x2D), "INSERT");
        assert_eq!(vk_name(0x41), "A");
        assert_eq!(vk_name(0x70), "F1");
        assert_eq!(vk_name(0x61), "NUMPAD1");
        assert_eq!(vk_name(0x07), "VK_0x07");
    }
    #[test]
    fn ipv4() {
        assert_eq!(find_ipv4(b"connect 8.8.8.8 now"), "");
        assert_eq!(find_ipv4(b"host 45.33.32.156:25565"), "45.33.32.156");
        assert_eq!(find_ipv4(b"192.168.1.1"), "");
        assert_eq!(find_ipv4(b"1.2.3.4"), "");
    }
    #[test]
    fn jni_desc() {
        assert!(looks_jni_desc(b"(Ljava/lang/String;I)V"));
        assert!(!looks_jni_desc(b"(null)"));
        assert!(!looks_jni_desc(b"(void)"));
    }
    #[test]
    fn urls() {
        assert!(noisy_url("https://www.microsoft.com/x"));
        assert!(!noisy_url("https://evil.example/x"));
    }
    #[test]
    fn code_empty() {
        let mut a = Analysis::default();
        analyze_code(&[0u8; 64], &mut a);
        assert!(a.keys.is_empty());
    }
}
