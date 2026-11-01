use crate::analysis::*;
use crate::analyze::analyze_buffer;
use crate::ctx::*;
use crate::pe::*;
use crate::phases::*;
use crate::score::*;
use crate::util::*;
use crate::winutil::*;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use windows::Win32::Foundation::HANDLE;

pub struct ExpFn {
    pub name: String,
    pub rva: u32,
}
#[derive(Clone, Copy)]
pub struct RelocEnt {
    pub rva: u32,
    pub typ: u8,
}

pub fn pe_data_dir(p: &[u8], idx: u32) -> Option<(u32, u32)> {
    let n = p.len();
    if n < 0x200 || p[0] != b'M' || p[1] != b'Z' {
        return None;
    }
    let lf = rd32(p, 0x3C) as usize;
    if lf < 0x40 || lf + 0x108 > n || rd32(p, lf) != 0x4550 {
        return None;
    }
    let oh = lf + 24;
    let magic = rd16(p, oh);
    let sz_opt = rd16(p, lf + 20);
    let (num_dirs, dirs);
    if magic == 0x20B {
        if sz_opt < 112 {
            return None;
        }
        num_dirs = rd32(p, oh + 108);
        dirs = oh + 112;
    } else if magic == 0x10B {
        if sz_opt < 96 {
            return None;
        }
        num_dirs = rd32(p, oh + 92);
        dirs = oh + 96;
    } else {
        return None;
    }
    if idx >= num_dirs || idx >= 16 || dirs + (idx as usize + 1) * 8 > n {
        return None;
    }
    let rva = rd32(p, dirs + idx as usize * 8);
    let size = rd32(p, dirs + idx as usize * 8 + 4);
    if rva != 0 {
        Some((rva, size))
    } else {
        None
    }
}

pub fn parse_exports_rva(p: &[u8], pe: &PeInfo) -> Vec<ExpFn> {
    let n = p.len();
    let mut out: Vec<ExpFn> = Vec::new();
    let Some((dir_rva, dir_size)) = pe_data_dir(p, 0) else {
        return out;
    };
    let e = pe_rva_to_off(pe, n, dir_rva);
    if e == NO_OFF || e + 40 > n {
        return out;
    }
    let base = rd32(p, e + 16);
    let n_fn = rd32(p, e + 20);
    let n_names = rd32(p, e + 24);
    let a_fn = rd32(p, e + 28);
    let a_names = rd32(p, e + 32);
    let a_ord = rd32(p, e + 36);
    if n_fn > 200000 || n_names > 200000 {
        return out;
    }
    let fo = pe_rva_to_off(pe, n, a_fn);
    let no = pe_rva_to_off(pe, n, a_names);
    let oo = pe_rva_to_off(pe, n, a_ord);
    if fo == NO_OFF || fo + n_fn as usize * 4 > n {
        return out;
    }
    let mut named = vec![false; n_fn as usize];
    if no != NO_OFF && oo != NO_OFF && no + n_names as usize * 4 <= n && oo + n_names as usize * 2 <= n {
        let mut i = 0u32;
        while i < n_names && out.len() < 60000 {
            let ord = rd16(p, oo + i as usize * 2) as usize;
            i += 1;
            let ii = (i - 1) as usize;
            if ord >= n_fn as usize {
                continue;
            }
            let rva = rd32(p, fo + ord * 4);
            named[ord] = true;
            if rva == 0 || (rva >= dir_rva && rva < dir_rva.wrapping_add(dir_size)) {
                continue; // yönlendirme (forwarder)
            }
            let so = pe_rva_to_off(pe, n, rd32(p, no + ii * 4));
            out.push(ExpFn {
                name: if so == NO_OFF {
                    "?".to_string()
                } else {
                    read_cstr(p, so, 96)
                },
                rva,
            });
        }
    }
    let mut ord = 0u32;
    while ord < n_fn && out.len() < 60000 {
        if !named[ord as usize] {
            let rva = rd32(p, fo + ord as usize * 4);
            if !(rva == 0 || (rva >= dir_rva && rva < dir_rva.wrapping_add(dir_size))) {
                out.push(ExpFn {
                    name: format!("#{}", ord.wrapping_add(base)),
                    rva,
                });
            }
        }
        ord += 1;
    }
    out
}

pub fn parse_relocs(p: &[u8], pe: &PeInfo) -> Vec<RelocEnt> {
    let n = p.len();
    let mut out = Vec::new();
    let Some((rva, sz)) = pe_data_dir(p, 5) else { return out };
    let off = pe_rva_to_off(pe, n, rva);
    if off == NO_OFF {
        return out;
    }
    let end = n.min(off + sz as usize);
    let mut pos = off;
    while pos + 8 <= end && out.len() < 4_000_000 {
        let page = rd32(p, pos);
        let bsz = rd32(p, pos + 4) as usize;
        if bsz < 8 || pos + bsz > end {
            break;
        }
        let mut k = pos + 8;
        while k + 2 <= pos + bsz {
            let e = rd16(p, k);
            let ty = (e >> 12) as u8;
            if ty != 0 {
                out.push(RelocEnt {
                    rva: page.wrapping_add((e & 0xFFF) as u32),
                    typ: ty,
                });
            }
            k += 2;
        }
        pos += bsz;
    }
    out
}

#[derive(Default, Clone)]
pub struct HookDec {
    pub ok: bool,
    pub target: u64,
    pub kind: &'static str,
}

pub fn decode_hook(h: HANDLE, b: &[u8], addr: u64) -> HookDec {
    let mut d = HookDec::default();
    let g = |i: usize| b.get(i).copied().unwrap_or(0);
    let s32 = |o: usize| rd32(b, o) as i32 as i64 as u64;
    if g(0) == 0xE9 {
        d.target = addr.wrapping_add(5).wrapping_add(s32(1));
        d.kind = "jmp rel32";
        d.ok = true;
    } else if g(0) == 0xEB {
        d.target = addr.wrapping_add(2).wrapping_add(g(1) as i8 as i64 as u64);
        d.kind = "jmp short";
        d.ok = true;
    } else if g(0) == 0xE8 {
        d.target = addr.wrapping_add(5).wrapping_add(s32(1));
        d.kind = "call rel32";
        d.ok = true;
    } else if g(0) == 0xFF && (g(1) == 0x25 || g(1) == 0x15) {
        let slot = addr.wrapping_add(6).wrapping_add(s32(2));
        let mut vb = [0u8; 8];
        if rpm(h, slot, &mut vb) {
            d.target = u64::from_le_bytes(vb);
            d.kind = if g(1) == 0x25 { "jmp [rip+x]" } else { "call [rip+x]" };
            d.ok = true;
        }
    } else if (g(0) == 0x48 || g(0) == 0x49) && (0xB8..=0xBF).contains(&g(1)) {
        let reg = (g(1) - 0xB8) as i32 + if g(0) == 0x49 { 8 } else { 0 };
        let imm = rd64(b, 2);
        let (c0, c1, c2) = (g(10), g(11), g(12));
        let j = (reg < 8 && c0 == 0xFF && c1 == (0xE0 + reg) as u8)
            || (reg >= 8 && c0 == 0x41 && c1 == 0xFF && c2 == (0xE0 + reg - 8) as u8);
        let pr = (reg < 8 && c0 == (0x50 + reg) as u8 && c1 == 0xC3)
            || (reg >= 8 && c0 == 0x41 && c1 == (0x50 + reg - 8) as u8 && c2 == 0xC3);
        if j || pr {
            d.target = imm;
            d.kind = if j {
                "mov reg,imm64; jmp reg"
            } else {
                "mov reg,imm64; push; ret"
            };
            d.ok = true;
        }
    } else if g(0) == 0x68 && g(5) == 0xC3 {
        d.target = s32(1);
        d.kind = "push imm32; ret";
        d.ok = true;
    } else if g(0) == 0x68 && g(5) == 0xC7 && g(6) == 0x44 && g(7) == 0x24 && g(8) == 0x04 && g(13) == 0xC3 {
        d.target = ((rd32(b, 9) as u64) << 32) | rd32(b, 1) as u64;
        d.kind = "push lo; mov [rsp+4],hi; ret";
        d.ok = true;
    }
    d
}

pub fn looks_neutered(b: &[u8]) -> bool {
    let g = |i: usize| b.get(i).copied().unwrap_or(0);
    g(0) == 0xC3
        || g(0) == 0xCC
        || g(0) == 0xC2
        || (g(0) == 0x31 && g(1) == 0xC0 && g(2) == 0xC3)
        || (g(0) == 0x33 && g(1) == 0xC0 && g(2) == 0xC3)
        || (g(0) == 0x48 && (g(1) == 0x31 || g(1) == 0x33) && g(2) == 0xC0 && g(3) == 0xC3)
        || (g(0) == 0xB8 && g(5) == 0xC3)
        || (g(0) == 0x90 && g(1) == 0x90 && g(2) == 0x90 && g(3) == 0x90)
        || (g(0) == 0x0F && g(1) == 0x0B)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hk {
    Sys,
    Trusted,
    Unsigned,
    Unbacked,
    Unmapped,
}

#[derive(Clone)]
pub struct HookTgt {
    pub kind: Hk,
    pub reg: Option<Region>,
    pub path: String,
}

pub fn hk_name(k: Hk) -> &'static str {
    match k {
        Hk::Sys => "sistem modülü",
        Hk::Trusted => "güvenilir imzalı modül",
        Hk::Unsigned => "İMZASIZ/güvenilmeyen modül",
        Hk::Unbacked => "DOSYASIZ bellek",
        Hk::Unmapped => "boş/ayrılmamış bellek",
    }
}

struct HookState {
    hook_an: BTreeMap<String, Analysis>,
    note_count: BTreeMap<String, i32>,
    worst: Verdict,
}

impl Ctx {
    fn classify_path(&mut self, path: &str) -> Hk {
        let si = self.sigs.verify_cached(path);
        let lp = lower_w(path);
        let vendor = si.valid
            && !si.trusted
            && (is_under(&lp, &self.dirs.pf) || is_under(&lp, &self.dirs.pf86) || is_under(&lp, &self.dirs.prog_data));
        if self.in_sys_dir(&lp) && si.valid {
            Hk::Sys
        } else if (si.valid && si.trusted) || vendor {
            Hk::Trusted
        } else {
            Hk::Unsigned
        }
    }

    pub fn classify_addr(&mut self, t: &Target, a: u64) -> HookTgt {
        let mut r = HookTgt {
            kind: Hk::Unmapped,
            reg: None,
            path: String::new(),
        };
        if let Some(m) = t.mods.iter().find(|m| a >= m.base && a < m.base + m.size) {
            r.path = m.path.clone();
            if r.path.is_empty() {
                r.kind = Hk::Unbacked;
                return r;
            }
            r.kind = self.classify_path(&r.path.clone());
            return r;
        }
        r.reg = find_region(t, a).copied();
        match &r.reg {
            Some(rg) if rg.state == MEM_COMMIT_V => {
                if rg.typ == MEM_IMAGE_V {
                    let mn = mapped_name(&self.dev_map, t.h, rg.alloc_base);
                    if !mn.is_empty() && file_exists(&mn) {
                        r.path = mn.clone();
                        r.kind = self.classify_path(&mn);
                        return r;
                    }
                }
                r.kind = Hk::Unbacked;
            }
            _ => r.kind = Hk::Unmapped,
        }
        r
    }

    fn hook_report(
        &mut self,
        t: &Target,
        hs: &mut HookState,
        kind: &str,
        what: &str,
        tg: &HookTgt,
        tgt_addr: u64,
        chain: &str,
    ) {
        let key: String;
        if tg.kind == Hk::Unsigned {
            key = tg.path.clone();
            if !hs.hook_an.contains_key(&key) {
                let a = self.analyze_file(&tg.path);
                let b = match a {
                    Some(x) => (*x).clone(),
                    None => Analysis {
                        path: tg.path.clone(),
                        sig_text: "okunamadı".into(),
                        ..Default::default()
                    },
                };
                hs.hook_an.insert(key.clone(), b);
            }
        } else {
            let ab = tg.reg.map(|r| r.alloc_base).unwrap_or(tgt_addr);
            key = format!("<hook-hedefi 0x{:X}>", ab);
            if !hs.hook_an.contains_key(&key) {
                let mut b = Analysis {
                    path: key.clone(),
                    sig_text: "hook hedefi (dosyasız bellek)".into(),
                    ..Default::default()
                };
                if let Some(rg) = &tg.reg {
                    let mut mem = Vec::new();
                    let sz = (rg.base + rg.size - rg.alloc_base).min(4 << 20) as usize;
                    if sz != 0 && read_mem(t.h, rg.alloc_base, sz, &mut mem) {
                        let o = AnalyzeOpts {
                            auto_layout: true,
                            ..Default::default()
                        };
                        let mut x = Analysis::default();
                        analyze_buffer(&mem, &o, &mut x);
                        x.path = key.clone();
                        x.sig_text = "hook hedefi (dosyasız bellek)".into();
                        b = x;
                    }
                }
                hs.hook_an.insert(key.clone(), b);
            }
        }
        let cnt = hs.note_count.entry(key.clone()).or_insert(0);
        let first = *cnt == 0;
        *cnt += 1;
        if first {
            if let Some(base) = hs.hook_an.get_mut(&key) {
                add_ev(
                    base,
                    'H',
                    if tg.kind == Hk::Unsigned { 25 } else { 35 },
                    &format!(
                        "javaw içindeki sistem/imzalı API'ler bu hedefe yönlendirilmiş ({}): {}{}",
                        hk_name(tg.kind),
                        what,
                        chain
                    ),
                );
                decide(base);
            }
        }
        let base = Arc::new(hs.hook_an[&key].clone());
        let ix = self.register(kind, &key, Some(base.clone()), "", "");
        let f = &mut self.findings[ix];
        if f.notes.len() < 14 {
            f.notes.push(format!("{}{}", what, chain));
        }
        f.loaded = true;
        let better = match &f.an {
            None => true,
            Some(old) => base.verdict > old.verdict,
        };
        if better {
            f.an = Some(base.clone());
        }
        hs.worst = hs.worst.max(base.verdict);
    }

    pub fn phase_hooks(&mut self, t: &mut Target) {
        self.begin_phase(5, "API Hook kontrolü (inline + IAT)");
        let (summary, col) = self.phase_hooks_inner(t);
        self.end_phase_guard(&summary, col);
    }

    fn phase_hooks_inner(&mut self, t: &mut Target) -> (String, usize) {
        if t.wow64 {
            return ("atlandı: 32-bit süreç".into(), COL_YEL);
        }
        t.regs = enum_regions(t.h);
        {
            let fresh = self.list_modules(t.h);
            if !fresh.is_empty() {
                t.mods = fresh;
            }
        }
        if t.regs.is_empty() || t.mods.is_empty() {
            return ("atlandı (bellek haritası/modül listesi alınamadı)".into(), COL_YEL);
        }
        let (
            mut mods_checked,
            mut exports_checked,
            mut trusted_hooks,
            mut suspect,
            mut patches,
            mut iat_susp,
            mut hdr_diff,
            mut iat_checked,
        ) = (0, 0, 0, 0, 0, 0, 0, 0);
        let mut hs = HookState {
            hook_an: BTreeMap::new(),
            note_count: BTreeMap::new(),
            worst: Verdict::Clean,
        };
        let mut shown_lines: Vec<String> = Vec::new();
        let mut base_to_path: HashMap<String, String> = HashMap::new();
        for m in &t.mods {
            if !m.path.is_empty() {
                base_to_path.insert(lower_str(&base_name(&m.path)), m.path.clone());
            }
        }
        let mut jre_home = String::new();
        {
            let ex = lower_w(&t.exe);
            if let Some(k) = ex.rfind('\\') {
                let bin = &ex[..k];
                jre_home = match bin.rfind('\\') {
                    Some(k2) => bin[..k2].to_string(),
                    None => bin.to_string(),
                };
            }
            if jre_home.len() < 8 {
                jre_home.clear();
            }
        }
        let mods = t.mods.clone();
        let mut mem: Vec<u8> = Vec::new();
        let mut fb: Vec<u8> = Vec::new();
        for (hook_idx, m) in mods.iter().enumerate() {
            self.prog_set_n(hook_idx, mods.len());
            if m.path.is_empty() || m.size == 0 || m.size > (160 << 20) {
                continue;
            }
            let lp = lower_w(&m.path);
            let si = self.sigs.verify_cached(&m.path);
            let eligible = (self.in_sys_dir(&lp) && si.valid) || (si.valid && si.trusted);
            if !read_mem(t.h, m.base, m.size as usize, &mut mem) {
                continue;
            }
            let Some(mpe) = parse_pe(&mem, true).filter(|p| p.is64) else {
                continue;
            };
            let mod_name = base_name(&m.path);
            if eligible && read_file_all(&m.path, &mut fb, 160u64 << 20, false).0 {
                if let Some(fpe) = parse_pe(&fb, false).filter(|p| p.is64) {
                    if mpe.timestamp != fpe.timestamp || mpe.size_of_image != fpe.size_of_image {
                        hdr_diff += 1; // disk dosyası yüklendikten sonra değişmiş (güncelleme)
                    } else {
                        let exps = parse_exports_rva(&fb, &fpe);
                        let mut rel = parse_relocs(&fb, &fpe);
                        rel.sort_by_key(|r| r.rva);
                        let delta = m.base.wrapping_sub(fpe.image_base);
                        mods_checked += 1;
                        for ex in &exps {
                            if ex.rva as usize + 32 > mem.len() {
                                continue;
                            }
                            let fo = pe_rva_to_off(&fpe, fb.len(), ex.rva);
                            if fo == NO_OFF || fo + 32 > fb.len() {
                                continue;
                            }
                            let mut fw = [0u8; 32];
                            fw.copy_from_slice(&fb[fo..fo + 32]);
                            if delta != 0 && !rel.is_empty() {
                                let lo = ex.rva.saturating_sub(8);
                                let mut ix = rel.partition_point(|r| r.rva < lo);
                                while ix < rel.len() && rel[ix].rva < ex.rva + 32 {
                                    let r = rel[ix];
                                    ix += 1;
                                    if r.rva < ex.rva {
                                        continue;
                                    }
                                    let o = (r.rva - ex.rva) as usize;
                                    if r.typ == 10 && o + 8 <= 32 {
                                        let v = rd64(&fw, o).wrapping_add(delta);
                                        fw[o..o + 8].copy_from_slice(&v.to_le_bytes());
                                    } else if r.typ == 3 && o + 4 <= 32 {
                                        let v = rd32(&fw, o).wrapping_add(delta as u32);
                                        fw[o..o + 4].copy_from_slice(&v.to_le_bytes());
                                    }
                                }
                            }
                            exports_checked += 1;
                            let mb = &mem[ex.rva as usize..ex.rva as usize + 32];
                            if fw[..16] == mb[..16] {
                                continue;
                            }
                            let fa = m.base + ex.rva as u64;
                            let d = decode_hook(t.h, mb, fa);
                            let what = format!("{}!{}", mod_name, ex.name);
                            if d.ok {
                                let tg = self.classify_addr(t, d.target);
                                let mut chain = format!(" [{} -> 0x{:X}", d.kind, d.target);
                                let mut fin = tg.clone();
                                let mut fin_addr = d.target;
                                let mut hop = 0;
                                while hop < 3 && (fin.kind == Hk::Unbacked || fin.kind == Hk::Unmapped) {
                                    hop += 1;
                                    let mut nb = Vec::new();
                                    if !read_mem(t.h, fin_addr, 32, &mut nb) {
                                        break;
                                    }
                                    let d2 = decode_hook(t.h, &nb, fin_addr);
                                    if !d2.ok {
                                        break;
                                    }
                                    let t2 = self.classify_addr(t, d2.target);
                                    chain.push_str(&format!(" -> 0x{:X}", d2.target));
                                    fin_addr = d2.target;
                                    if t2.kind != Hk::Unbacked && t2.kind != Hk::Unmapped {
                                        chain.push_str(&format!(" ({})", base_name(&t2.path)));
                                        fin = t2;
                                        break;
                                    }
                                }
                                chain.push(']');
                                if fin.kind == Hk::Sys {
                                    continue; // import-optimizasyonu / API yönlendirmesi (Windows'un kendisi)
                                }
                                if fin.kind == Hk::Trusted {
                                    trusted_hooks += 1;
                                    if self.cfg.verbose {
                                        self.out(
                                            &format!(
                                                "  [i] güvenilir hook: {}{}  hedef: {} {}",
                                                what,
                                                chain,
                                                hk_name(fin.kind),
                                                base_name(&fin.path)
                                            ),
                                            COL_GRY,
                                        );
                                    }
                                    continue;
                                }
                                if fin.kind == Hk::Unsigned && fin.path == m.path {
                                    continue;
                                }
                                suspect += 1;
                                if shown_lines.len() < 6 {
                                    shown_lines.push(format!(
                                        "{} -> {}{}",
                                        what,
                                        hk_name(fin.kind),
                                        if fin.path.is_empty() {
                                            String::new()
                                        } else {
                                            format!(" {}", base_name(&fin.path))
                                        }
                                    ));
                                }
                                let tail = if fin.kind == Hk::Unsigned {
                                    format!(" -> {}", fin.path)
                                } else {
                                    " -> dosyasız bellek".to_string()
                                };
                                self.hook_report(
                                    t,
                                    &mut hs,
                                    "API HOOK (inline: sistem API'si başka yere yönlendirilmiş)",
                                    &format!("{} prologu hooklanmış{}", what, tail),
                                    &fin,
                                    fin_addr,
                                    &chain,
                                );
                            } else if looks_neutered(mb) {
                                patches += 1;
                                suspect += 1;
                                if shown_lines.len() < 6 {
                                    shown_lines.push(format!(
                                        "{} gövdesi etkisizleştirilmiş ({})",
                                        what,
                                        hex_bytes(&mb[..6])
                                    ));
                                }
                                let mut b = Analysis {
                                    path: m.path.clone(),
                                    sig_text: sig_text(&si),
                                    ..Default::default()
                                };
                                add_ev(
                                    &mut b,
                                    'H',
                                    35,
                                    &format!(
                                        "Sistem/imzalı modülün export fonksiyonu bellekte diskteki halinden FARKLI ve etkisizleştirilmiş ({}: {} <- disk: {}): API yaması (ETW/AMSI/tarama kaçırma)",
                                        what,
                                        hex_bytes(&mb[..8]),
                                        hex_bytes(&fw[..8])
                                    ),
                                );
                                decide(&mut b);
                                let bv = b.verdict;
                                let ix = self.register(
                                    "API YAMASI (export gövdesi değiştirilmiş)",
                                    &m.path,
                                    Some(Arc::new(b)),
                                    &format!("{} yamalı: {}", what, hex_bytes(&mb[..8])),
                                    "",
                                );
                                self.findings[ix].loaded = true;
                                hs.worst = hs.worst.max(bv);
                            }
                        }
                        if is_under(&lp, &jre_home) {
                            let mut diff_bytes: u64 = 0;
                            let mut first_rva: Vec<u32> = Vec::new();
                            for sc in &fpe.secs {
                                if sc.chars & 0x2000_0000 == 0 || sc.chars & 0x8000_0000 != 0 {
                                    continue; // yalnızca yürütülebilir ve yazılamaz bölümler
                                }
                                let len = sc.vsize.min(sc.raw_size);
                                if len == 0
                                    || sc.rva as u64 + len as u64 > mem.len() as u64
                                    || sc.raw_ptr as u64 + len as u64 > fb.len() as u64
                                {
                                    continue;
                                }
                                let len = len as usize;
                                let mut fc: Vec<u8> = fb[sc.raw_ptr as usize..sc.raw_ptr as usize + len].to_vec();
                                if delta != 0 && !rel.is_empty() {
                                    let mut ix = rel.partition_point(|r| r.rva < sc.rva);
                                    while ix < rel.len() && (rel[ix].rva as u64) < sc.rva as u64 + len as u64 {
                                        let r = rel[ix];
                                        ix += 1;
                                        let o = (r.rva - sc.rva) as usize;
                                        if r.typ == 10 && o + 8 <= len {
                                            let v = rd64(&fc, o).wrapping_add(delta);
                                            fc[o..o + 8].copy_from_slice(&v.to_le_bytes());
                                        } else if r.typ == 3 && o + 4 <= len {
                                            let v = rd32(&fc, o).wrapping_add(delta as u32);
                                            fc[o..o + 4].copy_from_slice(&v.to_le_bytes());
                                        }
                                    }
                                }
                                let mp = &mem[sc.rva as usize..sc.rva as usize + len];
                                for i in 0..len {
                                    if fc[i] != mp[i] {
                                        diff_bytes += 1;
                                        if first_rva.len() < 4 {
                                            first_rva.push(sc.rva + i as u32);
                                        }
                                    }
                                }
                            }
                            if diff_bytes >= 16 {
                                patches += 1;
                                suspect += 1;
                                let where_s = first_rva.iter().map(|&r| hex(r as u64)).collect::<Vec<_>>().join(", ");
                                if shown_lines.len() < 6 {
                                    shown_lines
                                        .push(format!("{} kod bölümü {} bayt diskten FARKLI", mod_name, diff_bytes));
                                }
                                let mut b = Analysis {
                                    path: m.path.clone(),
                                    sig_text: sig_text(&si),
                                    ..Default::default()
                                };
                                add_ev(
                                    &mut b,
                                    'H',
                                    35,
                                    &format!("JRE yerel kütüphanesi {}: yürütülebilir bölümde {} bayt diskteki halinden FARKLI (ilk RVA: {}): bellekte yamalanmış / module stomping (JVM davranışını değiştirme, sınıf gizleme, anti-tespit)", mod_name, diff_bytes, where_s),
                                );
                                decide(&mut b);
                                let bv = b.verdict;
                                let ix = self.register(
                                    "API YAMASI (JRE modülü kodu bellekte değiştirilmiş)",
                                    &m.path,
                                    Some(Arc::new(b)),
                                    &format!("{} bayt fark; ilk RVA: {}", diff_bytes, where_s),
                                    "",
                                );
                                self.findings[ix].loaded = true;
                                hs.worst = hs.worst.max(bv);
                            }
                        }
                    }
                }
            }
            if !mpe.imps.is_empty() {
                let mut cache: HashMap<u64, HookTgt> = HashMap::new();
                for im in &mpe.imps {
                    if im.slot_rva as usize + 8 > mem.len() {
                        continue;
                    }
                    let v = rd64(&mem, im.slot_rva as usize);
                    if v == 0 {
                        continue;
                    }
                    if v >= m.base && v < m.base + m.size {
                        continue; // kendi görüntüsü (delay-load thunk)
                    }
                    iat_checked += 1;
                    let tg = match cache.get(&v) {
                        Some(x) => x.clone(),
                        None => {
                            let x = self.classify_addr(t, v);
                            cache.insert(v, x.clone());
                            x
                        }
                    };
                    if tg.kind == Hk::Sys || tg.kind == Hk::Trusted || tg.kind == Hk::Unmapped {
                        continue;
                    }
                    if tg.kind == Hk::Unsigned {
                        if let Some(ex) = base_to_path.get(&lower_str(&im.dll)) {
                            if lower_w(ex) == lower_w(&tg.path) {
                                continue; // import edilen DLL'in kendisi
                            }
                        }
                    }
                    iat_susp += 1;
                    suspect += 1;
                    let what = format!("{} IAT[{}!{}]", mod_name, im.dll, im.func);
                    if shown_lines.len() < 6 {
                        shown_lines.push(format!(
                            "{} -> {}{}",
                            what,
                            hk_name(tg.kind),
                            if tg.path.is_empty() {
                                String::new()
                            } else {
                                format!(" {}", base_name(&tg.path))
                            }
                        ));
                    }
                    let tail = if tg.kind == Hk::Unsigned {
                        format!(" ({})", tg.path)
                    } else {
                        " (dosyasız bellek)".to_string()
                    };
                    self.hook_report(
                        t,
                        &mut hs,
                        "API HOOK (IAT: import tablosu başka yere yönlendirilmiş)",
                        &format!("{} -> 0x{:X}{}", what, v, tail),
                        &tg,
                        v,
                        "",
                    );
                }
            }
        }
        for l in &shown_lines {
            self.out(&format!("  [!] hook: {}", l), COL_YEL);
        }
        let summary = format!(
            "{} modül, {} export prolog + {} IAT girdisi karşılaştırıldı{}{}{}",
            mods_checked,
            exports_checked,
            iat_checked,
            if suspect != 0 {
                format!(
                    "  -> {} ŞÜPHELİ HOOK/YAMA ({} IAT, {} yama)",
                    suspect, iat_susp, patches
                )
            } else {
                "  temiz".to_string()
            },
            if trusted_hooks != 0 {
                format!("  | güvenilir overlay hook: {}", trusted_hooks)
            } else {
                String::new()
            },
            if hdr_diff != 0 {
                format!("  | sürüm farkı atlandı: {}", hdr_diff)
            } else {
                String::new()
            }
        );
        let col = if suspect != 0 {
            if hs.worst == Verdict::Confirmed {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutered() {
        assert!(looks_neutered(&[0xC3, 0, 0, 0, 0, 0]));
        assert!(looks_neutered(&[0x31, 0xC0, 0xC3, 0, 0, 0]));
        assert!(!looks_neutered(&[0x48, 0x89, 0x5C, 0x24, 0x08, 0x57]));
    }
    #[test]
    fn data_dir_garbage() {
        assert!(pe_data_dir(&[0u8; 64], 0).is_none());
    }
    #[test]
    fn relocs_empty() {
        let pe = PeInfo::default();
        assert!(parse_relocs(&[0u8; 16], &pe).is_empty());
        assert!(parse_exports_rva(&[0u8; 16], &pe).is_empty());
    }
}
