use crate::analysis::*;
use crate::analyze::analyze_buffer;
use crate::ctx::*;
use crate::pat_data::*;
use crate::patterns::*;
use crate::phases::*;
use crate::score::*;
use crate::util::*;
use crate::winutil::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

#[derive(Default, Clone)]
pub struct HeapAgg {
    pub count: i32,
    pub first: u64,
    pub reg: String,
}

pub struct MemHit {
    pub addr: u64,
    pub pat: i32,
    pub reg: usize,
    pub text: String,
    pub kimlik: bool,
    pub oyun_metni: bool,
    pub c_str: bool,
    pub kod_adi: bool,
}
pub struct PathHit {
    pub addr: u64,
    pub path: String,
    pub reg: usize,
}
pub struct PeBlob {
    pub addr: u64,
    pub img_size: u32,
    #[allow(dead_code)]
    pub reg: usize,
}
#[derive(Default)]
pub struct ScanRes {
    pub hits: Vec<MemHit>,
    pub paths: Vec<PathHit>,
    pub blobs: Vec<PeBlob>,
    pub seen_paths: HashSet<String>,
    pub cap_cat: Vec<i32>,
    pub bytes: u64,
    pub strings: u64,
    pub dict_found: BTreeMap<String, (i32, u64)>,
}

pub fn hit_is_ident(s: &[u8], st: usize, en: usize) -> bool {
    let n = s.len();
    if st == 0 && en == n {
        return true; // string TAM olarak kalıp
    }
    if contains(s, "\"text\"") || contains(s, "\"translate\"") || contains(s, "\"extra\"") {
        return false;
    }
    if s[st..en].contains(&b' ') {
        return false;
    }
    let sp = s.iter().filter(|&&c| c == b' ').count();
    if sp == 0 {
        return true;
    }
    let lsp = st > 0 && s[st - 1] == b' ';
    let rsp = en < n && s[en] == b' ';
    if sp >= 2 && (lsp || rsp) {
        return false;
    }
    true
}

pub fn hit_is_code_name(s: &[u8], st: usize, en: usize) -> bool {
    let n = s.len();
    if s.iter().any(|&c| c == b' ' || c == b'"' || c == b'{') {
        return false;
    }
    let (mut a, mut b) = (st, en);
    while a > 0 && (is_alnum(s[a - 1]) || s[a - 1] == b'_') {
        a -= 1;
    }
    while b < n && (is_alnum(s[b]) || s[b] == b'_') {
        b += 1;
    }
    let left = a > 0 && matches!(s[a - 1], b'.' | b'/' | b'$');
    let right = b < n && matches!(s[b], b'.' | b'/' | b'$');
    left || right
}

pub fn looks_java_array(b: &[u8], off: usize, sl: usize, wide: bool) -> bool {
    let n = b.len();
    let want = sl as u32;
    let want2 = (if wide { sl * 2 } else { sl }) as u32;
    for back in [4usize, 8] {
        if off < back || off + sl > n {
            continue;
        }
        let v = rd32(b, off - back);
        if v == want || v == want2 {
            return true;
        }
    }
    false
}

pub fn ends_ci(s: &[u8], suf: &str) -> bool {
    let m = suf.len();
    if s.len() < m {
        return false;
    }
    (0..m).all(|i| low_c(s[s.len() - m + i]) == suf.as_bytes()[i])
}

#[allow(clippy::too_many_arguments)]
pub fn process_chunk(
    ri: usize,
    base_addr: u64,
    b: &[u8],
    from: usize,
    to: usize,
    r: &mut ScanRes,
    cx: &mut StrCtx,
    dict: &HashMap<String, Vec<i32>>,
) {
    let db = get_db();
    let n = b.len();
    extract_strings(b, from, to, 5, |s, off, wide| {
        let sl = s.len();
        r.strings += 1;
        let jarr = looks_java_array(b, off, sl, wide);
        let cstr = if !wide {
            off + sl < n && b[off + sl] == 0
        } else {
            off + 2 * sl + 1 < n && b[off + 2 * sl] == 0 && b[off + 2 * sl + 1] == 0
        };
        if sl >= 8 {
            let mut p = s;
            if p.len() > 4 && p[0] == b'\\' && (p[1] == b'?' || p[1] == b'\\') && p[2] == b'?' && p[3] == b'\\' {
                p = &p[4..];
            }
            if p.len() >= 8 && is_al(p[0]) && p[1] == b':' && p[2] == b'\\' && ends_ci(p, ".dll") && r.paths.len() < 300
            {
                let ps = bs(p);
                let lps = lower_str(&ps);
                if !r.seen_paths.contains(&lps) {
                    r.seen_paths.insert(lps);
                    r.paths.push(PathHit {
                        addr: base_addr + off as u64,
                        path: ps,
                        reg: ri,
                    });
                }
            }
        }
        let ScanRes { hits, cap_cat, .. } = r;
        match_string(s, cx, true, |id, ms, me| {
            let cat = db.pats[id as usize].cat;
            let cap = if cat == C_MOD_WEAK || cat == C_CLIENT_B {
                500
            } else {
                2500
            };
            let c = &mut cap_cat[cat as usize];
            if *c < cap {
                *c += 1;
                hits.push(MemHit {
                    addr: base_addr + off as u64,
                    pat: id,
                    reg: ri,
                    text: bs(&s[..sl.min(160)]),
                    kimlik: hit_is_ident(s, ms, me),
                    kod_adi: hit_is_code_name(s, ms, me),
                    oyun_metni: jarr,
                    c_str: cstr,
                });
            }
        });
        if !dict.is_empty() && (6..=120).contains(&sl) {
            let key = bs(s);
            if dict.contains_key(&key) {
                let d = r.dict_found.entry(key).or_insert((0, 0));
                if d.0 == 0 {
                    d.1 = base_addr + off as u64;
                }
                d.0 += 1;
            }
        }
    });
    let mut i = from;
    while i < to && i + 0x200 < n {
        let lim = to.min(n - 0x200);
        let Some(off) = memchr::memchr(b'M', &b[i..lim]) else {
            break;
        };
        i += off;
        if b[i + 1] == b'Z' {
            let lf = rd32(b, i + 0x3C) as usize;
            if (0x40..=0x400).contains(&lf) && i + lf + 0x108 <= n && rd32(b, i + lf) == 0x4550 {
                let mach = rd16(b, i + lf + 4);
                let ns = rd16(b, i + lf + 6);
                let mg = rd16(b, i + lf + 24);
                if (mach == 0x8664 || mach == 0x14C) && (1..=96).contains(&ns) && (mg == 0x20B || mg == 0x10B) {
                    let isz = rd32(b, i + lf + 24 + 56);
                    if (0x1000..=(96u32 << 20)).contains(&isz) && r.blobs.len() < 40 {
                        r.blobs.push(PeBlob {
                            addr: base_addr + i as u64,
                            img_size: isz,
                            reg: ri,
                        });
                    }
                }
            }
        }
        i += 1;
    }
}

fn dump_bytes(dump_dir: &str, name: &str, d: &[u8]) {
    if dump_dir.is_empty() {
        return;
    }
    let _ = std::fs::write(format!("{}\\{}", dump_dir, name), d);
}

#[derive(Default)]
struct Cl {
    fam: BTreeSet<i32>,
    ca: BTreeSet<i32>,
    cb: BTreeSet<i32>,
    ms: BTreeSet<i32>,
    mw: BTreeSet<i32>,
    op: BTreeSet<i32>,
    sd: BTreeSet<i32>,
    net: BTreeSet<i32>,
    ms_code: BTreeSet<i32>,
    fa_code: BTreeSet<i32>,
    runs: BTreeSet<u64>,
    c_runs: BTreeSet<u64>,
    first: u64,
    reg: usize,
    managed: bool,
    sample: Vec<String>,
}

impl Ctx {
    fn scan_region(&mut self, t: &Target, ri: usize, r: &mut ScanRes, buf: &mut Vec<u8>, cx: &mut StrCtx) {
        let rg = t.regs[ri];
        const CHUNK: u64 = 4 << 20;
        const LEFT: u64 = 256;
        const RIGHT: u64 = 256 << 10;
        let mut off = 0u64;
        while off < rg.size {
            let start_read = if off > 0 { off - LEFT } else { 0 };
            let end_read = rg.size.min(off + CHUNK + RIGHT);
            let want = (end_read - start_read) as usize;
            buf.clear();
            if buf.try_reserve_exact(want).is_err() {
                return;
            }
            buf.resize(want, 0);
            if !rpm(t.h, rg.base + start_read, buf) {
                read_pagewise(t.h, rg.base + start_read, buf);
            }
            let span = CHUNK.min(rg.size - off);
            r.bytes += span;
            if self.mem_total != 0 {
                let f = 0.9 * r.bytes as f64 / self.mem_total as f64;
                self.prog_set(f);
            }
            let from = (off - start_read) as usize;
            process_chunk(
                ri,
                rg.base + start_read,
                buf,
                from,
                from + span as usize,
                r,
                cx,
                &self.dict,
            );
            off += CHUNK;
        }
    }

    pub fn phase_memory(&mut self, t: &mut Target) {
        self.begin_phase(6, "Bellek: string/PE/yol izi");
        let (summary, col) = self.phase_memory_inner(t);
        self.end_phase_guard(&summary, col);
    }

    fn phase_memory_inner(&mut self, t: &mut Target) -> (String, usize) {
        let start_idx = self.findings.len();
        t.regs = enum_regions(t.h);
        let mut r = ScanRes {
            cap_cat: vec![0; C_COUNT],
            ..Default::default()
        };
        let mut buf: Vec<u8> = Vec::new();
        let mut cx = StrCtx::default();
        let (mut total, mut scan_targets) = (0u64, 0u64);
        let scannable = |rg: &Region| {
            rg.state == MEM_COMMIT_V
                && rg.typ != MEM_IMAGE_V
                && (rg.protect & (0x01 | 0x100)) == 0
                && (rg.protect & 0xFF) != 0
        };
        for rg in &t.regs {
            if scannable(rg) {
                total += rg.size;
                scan_targets += 1;
            }
        }
        self.mem_total = total;
        self.out(
            &format!(
                "  Taranacak: {} bölge, {} (modül görüntüleri dosyadan ayrıca analiz edildi)",
                scan_targets,
                fmt_size(total)
            ),
            COL_DEF,
        );
        let t0 = self.tick();
        for ri in 0..t.regs.len() {
            if !scannable(&t.regs[ri]) {
                continue;
            }
            self.scan_region(t, ri, &mut r, &mut buf, &mut cx);
        }
        let el = (self.tick() - t0) as f64 / 1000.0;
        self.out(
            &format!(
                "  Tamamlandı: {} okundu, {} string çıkarıldı, {:.1} sn",
                fmt_size(r.bytes),
                r.strings,
                el
            ),
            COL_GRN,
        );
        self.prog_set(0.9);
        let db = get_db();
        for h in &r.hits {
            let pi = &db.pats[h.pat as usize];
            if !h.kimlik {
                continue;
            }
            if !(pi.cat == C_FAMILY
                || pi.cat == C_CLIENT_A
                || pi.cat == C_MOD_STRONG
                || pi.cat == C_OPT
                || pi.cat == C_SDSTR
                || pi.cat == C_GUICHEAT)
            {
                continue;
            }
            let g = self.heap_pats.entry(h.pat).or_default();
            if g.count == 0 {
                g.first = h.addr;
                g.reg = reg_desc(&t.regs[h.reg]);
            }
            g.count += 1;
        }

        let mut span: HashMap<u64, u64> = HashMap::new();
        for rg in &t.regs {
            if rg.state != 0x10000 {
                let sp = span.entry(rg.alloc_base).or_insert(0);
                *sp = (*sp).max(rg.base + rg.size - rg.alloc_base);
            }
        }
        const MANAGED_SPAN: u64 = 32 << 20;
        let mut cls: BTreeMap<(usize, u64, bool), Cl> = BTreeMap::new();
        let (mut prose_hits, mut _managed_hits) = (0usize, 0usize);
        for h in &r.hits {
            let pi = &db.pats[h.pat as usize];
            if !h.kimlik {
                prose_hits += 1; // cümle / sohbet metni: kümeye girmez
                continue;
            }
            let rg = &t.regs[h.reg];
            let managed = h.oyun_metni || span.get(&rg.alloc_base).copied().unwrap_or(0) >= MANAGED_SPAN;
            if managed {
                _managed_hits += 1;
            }
            let c = cls.entry((h.reg, h.addr >> 16, managed)).or_insert_with(|| Cl {
                first: u64::MAX,
                ..Default::default()
            });
            c.reg = h.reg;
            c.managed = managed;
            c.first = c.first.min(h.addr);
            match pi.cat {
                C_FAMILY => {
                    c.fam.insert(h.pat);
                }
                C_CLIENT_A => {
                    c.ca.insert(h.pat);
                }
                C_CLIENT_B => {
                    c.cb.insert(h.pat);
                }
                C_MOD_STRONG => {
                    c.ms.insert(h.pat);
                }
                C_MOD_WEAK => {
                    c.mw.insert(h.pat);
                }
                C_OPT => {
                    c.op.insert(h.pat);
                }
                C_SDSTR => {
                    c.sd.insert(h.pat);
                }
                C_NET => {
                    c.net.insert(h.pat);
                }
                _ => {}
            }
            let strong = pi.cat == C_FAMILY || pi.cat == C_CLIENT_A || pi.cat == C_MOD_STRONG || pi.cat == C_OPT;
            if strong {
                c.runs.insert(h.addr);
                if h.c_str && !h.oyun_metni {
                    c.c_runs.insert(h.addr);
                }
            }
            if h.kod_adi && pi.cat == C_MOD_STRONG {
                c.ms_code.insert(h.pat);
            }
            if h.kod_adi && (pi.cat == C_FAMILY || pi.cat == C_CLIENT_A) {
                c.fa_code.insert(h.pat);
            }
            if c.sample.len() < 6 {
                c.sample.push(trunc(&printable(&h.text), 60));
            }
        }
        let mut clusters = 0;
        for c in cls.values() {
            let mut sev = 0;
            let mut why = String::new();
            if !c.managed {
                let cr = c.c_runs.len();
                if !c.fam.is_empty() && (c.ms.len() + c.op.len() + c.ca.len() >= 1) && cr >= 2 {
                    sev = 3;
                    why = "bilinen hile ailesi imzası + modül/ayar stringleri aynı yerli bellek bölgesinde (ayrı C stringleri)".into();
                } else if !c.ca.is_empty() && (!c.ms.is_empty() || c.op.len() >= 2) && cr >= 2 {
                    sev = 3;
                    why = "hile istemci adı + modül/ayar stringleri aynı yerli bellek bölgesinde (ayrı C stringleri)"
                        .into();
                } else if !c.fam.is_empty() && cr >= 1 {
                    sev = 2;
                    why = "bilinen hile ailesi imzası yerli bellekte".into();
                } else if c.ms.len() >= 4 && cr >= 3 {
                    sev = 2;
                    why = format!(
                        "{} farklı güçlü hile modülü adı aynı 64KB yerli bellek bölgesinde (ayrı C stringleri)",
                        c.ms.len()
                    );
                } else if c.ms.len() >= 3 && c.op.len() >= 3 && cr >= 4 {
                    sev = 2;
                    why = "hile modülü + savaş ayar etiketleri kümesi (yerli bellek)".into();
                }
            } else {
                if !c.fa_code.is_empty() && c.ms_code.len() >= 4 && c.runs.len() >= 6 {
                    sev = 3;
                    why = format!("Java yığınında hile istemcisinin modül kaydı: istemci/aile adı + {} modül, paket/sınıf adı biçiminde", c.ms_code.len());
                } else if !c.fa_code.is_empty() && c.ms_code.len() >= 2 && c.runs.len() >= 3 {
                    sev = 2;
                    why = "Java yığınında hile istemcisi + modül adları (paket/sınıf biçimli)".into();
                }
            }
            if sev == 0 {
                continue;
            }
            clusters += 1;
            let rg = t.regs[c.reg];
            let mut labs: Vec<String> = Vec::new();
            for st in [&c.fam, &c.ca, &c.ms, &c.op, &c.sd, &c.net, &c.mw] {
                for &id in st {
                    labs.push(db.pats[id as usize].label.to_string());
                }
            }
            let mut f = Finding {
                kinds: vec!["HEAP KÜMESİ (bellek kalıntısı / çalışan hile metni)".to_string()],
                path: String::new(),
                an: None,
                notes: Vec::new(),
                remnants: Vec::new(),
                detail: Vec::new(),
                loaded: false,
                title: format!("bellek bölgesi {} ({})", addr_s(c.first), reg_desc(&rg)),
                v_override: Some(if sev == 3 { Verdict::Confirmed } else { Verdict::Suspect }),
                printed: false,
                printed_v: -99,
            };
            let vo = f.v_override.unwrap_or(Verdict::Suspect);
            f.detail
                .push("  +--[ BELLEK KÜMESİ ]-------------------------------------------------".into());
            f.detail.push(format!(
                "  | Adres     : {}   bölge: {}   tahsis tabanı: {}",
                addr_s(c.first),
                reg_desc(&rg),
                addr_s(rg.alloc_base)
            ));
            f.detail.push(format!(
                "  | Bellek    : {}",
                if c.managed {
                    "Java yığını (oyunun kendi nesneleri)"
                } else {
                    "yerli bellek (Java dışı tahsis)"
                }
            ));
            f.detail.push(format!("  | Stringler : {}", join_l(&labs, 16, ", ")));
            f.detail
                .push(format!("  | Örnekler  : {}", join_l(&c.sample, 6, " | ")));
            f.detail.push("  | Kaynak    : hiçbir diskteki dosyayla eşleşmedi -> dosya silinmiş (self-destruct/dosya silme) veya bellek-içi yükleme olabilir".into());
            f.detail
                .push(format!("  | KARAR     : {}  --  {}", verdict_name(vo), why));
            f.detail
                .push("  +----------------------------------------------------------------------".into());
            self.findings.push(f);
            self.out(
                &format!(
                    "  [!] BELLEK KÜMESİ {} -> {} : {}",
                    addr_s(c.first),
                    verdict_tag(vo),
                    why
                ),
                if sev == 3 { COL_RED } else { COL_YEL },
            );
        }
        if prose_hits != 0 {
            self.out(&format!("  [i] {} eşleşme cümle/sohbet metni içinde (\"... killaura ile banlandi\" gibi): hile kanıtı sayılmadı.", prose_hits), COL_GRY);
        }
        if clusters == 0 {
            self.out("  Heap stringlerinde hile kümesi yok.", COL_GRN);
        }

        self.prog_set(0.93);
        let mut injected = 0;
        for ph in &r.paths {
            let wp = norm_path(&ph.path);
            let lw = lower_w(&wp);
            if is_under(&lw, &self.dirs.sysroot) && !is_under(&lw, &format!("{}\\temp", self.dirs.sysroot)) {
                continue;
            }
            let rg = t.regs[ph.reg];
            let mut isolated = false;
            let mut nz = 0usize;
            if rg.typ == 0x20000
                && rg.size <= 0x10000
                && rg.alloc_base == rg.base
                && (rg.protect & (0x04 | 0x40)) != 0
                && ph.addr - rg.base < 256
            {
                let mut rb = Vec::new();
                if read_mem(t.h, rg.base, rg.size as usize, &mut rb) {
                    nz = rb.iter().filter(|&&c| c != 0).count();
                    isolated = nz <= 1200;
                }
            }
            let exists = file_exists(&wp);
            if exists {
                let Some(a) = self.analyze_file(&wp) else { continue };
                if a.verdict < Verdict::Suspect && !(isolated && a.s > 0) {
                    continue;
                }
                let mut b = (*a).clone();
                let known = self.find_idx.contains_key(&lower_w(&wp));
                if isolated {
                    add_ev(&mut b, 'H', 35, &format!("DLL yolu javaw içinde İZOLE küçük bellek tahsisinde ({}, {} dolu bayt): CreateRemoteThread+LoadLibrary enjeksiyonu izi", addr_s(ph.addr), nz));
                    decide(&mut b);
                    injected += 1;
                }
                let b = Arc::new(b);
                let kind = if isolated {
                    "ENJEKSİYON YOLU İZİ (izole bellek tahsisi) + DOSYA"
                } else {
                    "BELLEKTE DLL YOLU (dosya hile içeriyor)"
                };
                let fi = self.register(
                    kind,
                    &wp,
                    Some(b.clone()),
                    &format!("bellekte yol kalıntısı: {} ({})", addr_s(ph.addr), reg_desc(&rg)),
                    "",
                );
                let better = match &self.findings[fi].an {
                    None => true,
                    Some(old) => b.verdict > old.verdict,
                };
                if isolated || better {
                    self.findings[fi].an = Some(b.clone());
                }
                self.refresh_dict(fi);
                if isolated || !known {
                    self.out(
                        &format!(
                            "  [!] {}: {} -> {}",
                            if isolated {
                                "enjeksiyon yolu izi"
                            } else {
                                "bellekte hile DLL yolu"
                            },
                            ph.path,
                            verdict_tag(b.verdict)
                        ),
                        if b.verdict == Verdict::Confirmed {
                            COL_RED
                        } else {
                            COL_YEL
                        },
                    );
                }
            } else if isolated && in_user_drop_dir(&self.dirs, &wp) {
                let mut b = Analysis {
                    path: ph.path.clone(),
                    sig_text: "dosya silinmiş / bulunamadı".into(),
                    in_user_dir: true,
                    ..Default::default()
                };
                add_ev(&mut b, 'H', 35, &format!("Silinmiş DLL yolu ({}) javaw içinde izole bellek tahsisinde duruyor ({}): enjeksiyon sonrası dosya silinmiş olabilir", trunc(&ph.path, 90), addr_s(ph.addr)));
                decide(&mut b);
                injected += 1;
                let bv = b.verdict;
                self.register(
                    "ENJEKSİYON YOLU İZİ (dosya silinmiş)",
                    &wp,
                    Some(Arc::new(b)),
                    &format!("yol: {}", ph.path),
                    "",
                );
                self.out(
                    &format!("  [!] silinmiş DLL yolu izi: {} -> {}", ph.path, verdict_tag(bv)),
                    COL_YEL,
                );
            } else if self.cfg.verbose {
                self.out(
                    &format!(
                        "  [i] DLL yolu stringi: {}{}  [{}]",
                        ph.path,
                        if exists { "" } else { "  (dosya yok)" },
                        reg_desc(&rg)
                    ),
                    COL_GRY,
                );
            }
        }
        if injected == 0 {
            self.out("  İzole bellekte enjeksiyon yolu izi yok.", COL_GRN);
        }

        self.prog_set(0.96);
        let (mut blob_hits, mut blob_seen) = (0, 0);
        let mut seen_sha: BTreeSet<String> = BTreeSet::new();
        for pb in &r.blobs {
            let Some(rg) = find_region(t, pb.addr).copied() else {
                continue;
            };
            let avail = rg.base + rg.size - pb.addr;
            let sz = (pb.img_size as u64).min(avail) as usize;
            if sz < 0x1000 {
                continue;
            }
            let mut mem = Vec::new();
            if !read_mem(t.h, pb.addr, sz, &mut mem) {
                continue;
            }
            let mut a = Analysis::default();
            let o = AnalyzeOpts {
                auto_layout: true,
                ..Default::default()
            };
            analyze_buffer(&mem, &o, &mut a);
            blob_seen += 1;
            if seen_sha.contains(&a.sha) {
                continue;
            }
            seen_sha.insert(a.sha.clone());
            a.path = format!("<bellek PE {}>", addr_s(pb.addr));
            a.sig_text = "dosya yok - bellek kopyası".into();
            if !(a.s > 0 || a.t >= 25) {
                if self.cfg.verbose {
                    self.out(
                        &format!(
                            "  [i] bellekte PE {} ({}) - hile kanıtı yok (yerel kütüphane baytları olabilir)",
                            addr_s(pb.addr),
                            reg_desc(&rg)
                        ),
                        COL_GRY,
                    );
                }
                continue;
            }
            add_ev(
                &mut a,
                'H',
                40,
                &format!(
                    "Heap/özel bellekte PE imajli DLL kopyası ({}, {}): staging/manuel-map kalıntısı",
                    addr_s(pb.addr),
                    reg_desc(&rg)
                ),
            );
            decide(&mut a);
            dump_bytes(&self.cfg.dump_dir, &format!("memPE_{:X}.bin", pb.addr), &mem);
            blob_hits += 1;
            let ap = a.path.clone();
            let av = a.verdict;
            self.register(
                "BELLEKTE PE KOPYASI (manuel map / staging)",
                &ap,
                Some(Arc::new(a)),
                &format!("bölge {}", reg_desc(&rg)),
                "",
            );
            self.out(
                &format!(
                    "  [!] bellekte hile içerikli PE {} -> {}",
                    addr_s(pb.addr),
                    verdict_tag(av)
                ),
                if av == Verdict::Confirmed { COL_RED } else { COL_YEL },
            );
        }
        self.out(
            &format!(
                "  Bellekte {} PE gövdesi bulundu, {} tanesi hile içeriği taşıyor.",
                blob_seen, blob_hits
            ),
            if blob_hits != 0 { COL_YEL } else { COL_GRN },
        );

        self.head("STRING KAYNAK KORELASYONU (bellek <-> dosya)");
        let mut by_finding: BTreeMap<i32, Vec<(String, (i32, u64))>> = BTreeMap::new();
        for (k, v) in &r.dict_found {
            let Some(list) = self.dict.get(k) else { continue };
            for &fi in list {
                by_finding.entry(fi).or_default().push((k.clone(), *v));
            }
        }
        let mut linked = 0;
        for (fi, list) in &by_finding {
            let fi = *fi as usize;
            if list.len() < 2 && self.findings[fi].loaded {
                continue;
            }
            for e in list {
                if self.findings[fi].remnants.len() < 12 {
                    let rem = format!(
                        "\"{}\" x{}  ilk adres {}",
                        trunc(&printable(&e.0), 50),
                        e.1 .0,
                        addr_s(e.1 .1)
                    );
                    self.findings[fi].remnants.push(rem);
                }
            }
            let (loaded, has_an) = (self.findings[fi].loaded, self.findings[fi].an.is_some());
            let title = self.findings[fi].title.clone();
            if !loaded && list.len() >= 3 && has_an {
                let mut b = (**self.findings[fi].an.as_ref().unwrap_or(&Arc::new(Analysis::default()))).clone();
                add_ev(&mut b, 'H', 35, &format!("Bu dosyaya ait {} ayırt edici string javaw BELLEĞİNDE bulundu (modül artık yüklü değil): çalıştırılıp bellekten çıkarılmış (self-destruct) olabilir", list.len()));
                decide(&mut b);
                let bv = b.verdict;
                self.findings[fi].an = Some(Arc::new(b));
                linked += 1;
                self.out(
                    &format!(
                        "  [!] {} : {} string bellekte bulundu -> {}",
                        trunc(&title, 70),
                        list.len(),
                        verdict_tag(bv)
                    ),
                    if bv == Verdict::Confirmed { COL_RED } else { COL_YEL },
                );
            } else if loaded {
                self.out(
                    &format!(
                        "  [i] {} : {} string heap kopyası (modül yüklü)",
                        trunc(&title, 70),
                        list.len()
                    ),
                    COL_GRY,
                );
            }
        }
        if linked == 0 && by_finding.is_empty() {
            self.out("  Diskteki/yüklü şüphelilerle eşleşen heap kalıntısı yok.", COL_GRN);
        }

        {
            let mut agg: BTreeMap<String, (i32, u64, usize)> = BTreeMap::new();
            let shown = [C_FAMILY, C_CLIENT_A, C_MOD_STRONG, C_OPT, C_SDSTR, C_NET, C_GUICHEAT];
            for h in &r.hits {
                let pi = &db.pats[h.pat as usize];
                if !shown.contains(&pi.cat) {
                    continue;
                }
                let k = format!("{}: {}", CAT_NAME[pi.cat as usize], pi.label);
                let e = agg.entry(k).or_insert((0, 0, 0));
                if e.0 == 0 {
                    e.1 = h.addr;
                    e.2 = h.reg;
                }
                e.0 += 1;
            }
            if !agg.is_empty() {
                self.out("", COL_DEF);
                self.out("  Heap'te görülen hile-ifadeli stringler (kaynak DLL dosyası bulunamadı; tek başına kesin delil DEĞİLDİR: sohbet/sunucu mesajı/mod metni olabilir):", COL_YEL);
                let mut k = 0usize;
                for (key, v) in &agg {
                    let stop = k >= 30;
                    k += 1;
                    if stop {
                        self.out(&format!("   ... +{} satır daha", agg.len() - 30), COL_GRY);
                        break;
                    }
                    self.out(
                        &format!(
                            "   {:<52} x{:<4} ilk: {}  [{}]",
                            trunc(key, 52),
                            v.0,
                            addr_s(v.1),
                            reg_desc(&t.regs[v.2])
                        ),
                        COL_GRY,
                    );
                }
            } else {
                self.out("  Heap'te hile-ifadeli bağımsız string yok.", COL_GRN);
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
        let summary = format!(
            "{} okundu, {} string{}",
            fmt_size(r.bytes),
            r.strings,
            if flagged != 0 {
                format!("  -> {} İZ: heap kümesi/yol/PE", flagged)
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
        (summary, col)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ident_rules() {
        assert!(hit_is_ident(b"KillAura", 0, 8));
        assert!(!hit_is_ident(b"{\"text\":\"killaura\"}", 10, 18));
        assert!(!hit_is_ident(b"oyuncu killaura kullandi yine", 7, 15));
        assert!(hit_is_ident(b"a/b/KillAuraModule", 4, 12));
    }
    #[test]
    fn code_names() {
        assert!(hit_is_code_name(b"net/x/hacks/KillAuraHack", 13, 21));
        assert!(!hit_is_code_name(b"KillAura", 0, 8));
        assert!(!hit_is_code_name(b"a b.KillAura", 4, 12));
    }
    #[test]
    fn java_array() {
        let mut b = vec![0u8; 16];
        b[4..8].copy_from_slice(&5u32.to_le_bytes());
        b.extend_from_slice(b"hello");
        assert!(looks_java_array(&b, 8, 5, false));
        assert!(!looks_java_array(&b, 8, 6, false));
    }
    #[test]
    fn chunk_finds_hit_and_path() {
        let mut data = vec![0u8; 64];
        data.extend_from_slice(b"net/x/hacks/KillAuraHack\0");
        data.extend_from_slice(b"C:\\Users\\a\\evil.dll\0");
        let mut r = ScanRes {
            cap_cat: vec![0; C_COUNT],
            ..Default::default()
        };
        let mut cx = StrCtx::default();
        process_chunk(0, 0x1000, &data, 0, data.len(), &mut r, &mut cx, &HashMap::new());
        assert!(r.hits.iter().any(|h| h.kimlik && h.kod_adi && h.c_str));
        assert_eq!(r.paths.len(), 1);
    }
    #[test]
    fn ends() {
        assert!(ends_ci(b"A.DLL", ".dll"));
    }
}
