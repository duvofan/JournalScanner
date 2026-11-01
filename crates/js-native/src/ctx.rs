use crate::analysis::*;
use crate::analyze::render_analysis;
use crate::pat_data::*;
use crate::score::*;
use crate::util::*;
use crate::winutil::*;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

pub const COL_DEF: usize = 0;
pub const COL_RED: usize = 1;
pub const COL_GRN: usize = 2;
pub const COL_YEL: usize = 3;
pub const COL_CYN: usize = 4;
#[allow(dead_code)]
pub const COL_MAG: usize = 5;
pub const COL_GRY: usize = 6;
const COL_SEQ: [&str; 7] = [
    "\x1b[0m", "\x1b[91m", "\x1b[92m", "\x1b[93m", "\x1b[96m", "\x1b[95m", "\x1b[90m",
];

pub const PHASES: usize = 9;
pub const PHASE_NAMES: [&str; PHASES + 1] = [
    "",
    "Yüklü modül denetimi",
    "Gizli modül (VAD-PEB)",
    "Boşaltılmış modül kaydı (self-destruct)",
    "Unbacked Thread taraması",
    "API Hook kontrolü (inline + IAT)",
    "Bellek: string/PE/yol izi",
    "Handle / kernel nesne denetimi",
    "Disk taraması (içerik tabanlı)",
    "Korelasyon (disk <-> javaw izleri)",
];

#[derive(Default, Clone)]
pub struct Config {
    pub verbose: bool,
    pub no_disk: bool,
    pub full: bool,
    pub no_handles: bool,
    pub help: bool,
    pub no_hooks: bool,
    pub deep_threads: bool,
    pub pid: u32,
    pub log_path: String,
    pub dump_dir: String,
    pub analyze_one: String,
    pub roots: Vec<String>,
}

#[derive(Clone, Default)]
pub struct ProgStep {
    pub phase: usize,
    pub est: f64,
    pub actual: f64,
}

#[derive(Clone)]
pub struct Finding {
    pub kinds: Vec<String>,
    pub path: String,
    pub an: Option<Arc<Analysis>>,
    pub notes: Vec<String>,
    pub remnants: Vec<String>,
    pub detail: Vec<String>,
    pub loaded: bool,
    pub title: String,
    pub v_override: Option<Verdict>,
    pub printed: bool,
    pub printed_v: i32,
}

impl Finding {
    pub fn verd(&self) -> Verdict {
        if let Some(v) = self.v_override {
            v
        } else if let Some(a) = &self.an {
            a.verdict
        } else {
            Verdict::Info
        }
    }
}

pub struct Ctx {
    pub cfg: Config,
    pub h_out: isize,
    pub is_console: bool,
    pub vt: bool,
    pub log: Option<std::fs::File>,
    pub console_w: usize,
    pub quiet: bool,
    pub collect: bool,
    pub status_len: usize,
    pub deferred: Vec<(String, usize)>,
    pub steps: Vec<ProgStep>,
    pub step_cur: i64,
    pub step_active: bool,
    pub step_frac: f64,
    pub eta_smooth: f64,
    pub t0: Instant,
    pub run_start: u64,
    pub step_start: u64,
    pub last_draw: u64,
    pub last_pct: i32,
    pub prep_note: String,
    pub phase_no: usize,
    pub phase_title: String,
    pub phase_state: [i32; 16],
    pub dirs: Dirs,
    pub dev_map: Vec<(String, String)>,
    pub nt: NtFns,
    pub sigs: SigCache,
    pub findings: Vec<Finding>,
    pub find_idx: BTreeMap<String, usize>,
    pub an_cache: HashMap<String, Option<Arc<Analysis>>>,
    pub dict: HashMap<String, Vec<i32>>,
    pub printed_count: i32,
    pub card_count: i32,
    pub javaw_seen: i32,
    pub javaw_open_fail: i32,
    pub list_mod_err: u32,
    pub mod_finding: HashMap<u64, usize>,
    pub hid_flagged: i32,
    pub unloaded: Vec<crate::phases::UnloadRec>,
    pub heap_pats: BTreeMap<i32, crate::memscan::HeapAgg>,
    pub mem_total: u64,
    pub disk_items: Vec<crate::disk::DiskItem>,
    pub disk_stats: crate::disk::DiskStats,
    pub disk_work: f64,
    pub disk_roots_n: usize,
    pub disk_listed: bool,
}

impl Ctx {
    pub fn new(cfg: Config) -> Ctx {
        Ctx {
            cfg,
            h_out: 0,
            is_console: false,
            vt: false,
            log: None,
            console_w: 100,
            quiet: false,
            collect: false,
            status_len: 0,
            deferred: Vec::new(),
            steps: Vec::new(),
            step_cur: -1,
            step_active: false,
            step_frac: 0.0,
            eta_smooth: -1.0,
            t0: Instant::now(),
            run_start: 0,
            step_start: 0,
            last_draw: 0,
            last_pct: 0,
            prep_note: String::new(),
            phase_no: 0,
            phase_title: String::new(),
            phase_state: [0; 16],
            dirs: Dirs::default(),
            dev_map: Vec::new(),
            nt: NtFns::default(),
            sigs: SigCache::new(),
            findings: Vec::new(),
            find_idx: BTreeMap::new(),
            an_cache: HashMap::new(),
            dict: HashMap::new(),
            printed_count: 0,
            card_count: 0,
            javaw_seen: 0,
            javaw_open_fail: 0,
            list_mod_err: 0,
            mod_finding: HashMap::new(),
            hid_flagged: 0,
            unloaded: Vec::new(),
            heap_pats: BTreeMap::new(),
            mem_total: 0,
            disk_items: Vec::new(),
            disk_stats: Default::default(),
            disk_work: 0.0,
            disk_roots_n: 0,
            disk_listed: false,
        }
    }

    pub fn tick(&self) -> u64 {
        self.t0.elapsed().as_millis() as u64
    }

    pub fn init_console(&mut self) {
        use windows::Win32::System::Console::*;
        unsafe {
            let h = GetStdHandle(STD_OUTPUT_HANDLE).unwrap_or_default();
            self.h_out = h.0 as isize;
            let mut mode = CONSOLE_MODE(0);
            self.is_console = GetConsoleMode(h, &mut mode).is_ok();
            if self.is_console {
                let _ = SetConsoleOutputCP(65001);
                if SetConsoleMode(h, CONSOLE_MODE(mode.0 | 0x0004)).is_ok() {
                    self.vt = true;
                }
                let mut ci: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
                if GetConsoleScreenBufferInfo(h, &mut ci).is_ok() && ci.dwSize.X > 40 {
                    self.console_w = ci.dwSize.X as usize;
                }
            }
        }
    }

    pub fn raw_write(&self, s: &str) {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Console::WriteConsoleW;
        if s.is_empty() {
            return;
        }
        let h = HANDLE(self.h_out as *mut core::ffi::c_void);
        if self.is_console {
            let w: Vec<u16> = s.encode_utf16().collect();
            let mut off = 0;
            while off < w.len() {
                let c = (w.len() - off).min(8000);
                let mut wr = 0u32;
                unsafe {
                    let _ = WriteConsoleW(h, &w[off..off + c], Some(&mut wr), None);
                }
                off += c;
            }
        } else {
            let mut wr = 0u32;
            unsafe {
                let _ = windows::Win32::Storage::FileSystem::WriteFile(h, Some(s.as_bytes()), Some(&mut wr), None);
            }
        }
    }

    pub fn clear_status(&mut self) {
        if self.status_len != 0 && self.is_console {
            let t = format!("\r{}\r", " ".repeat(self.status_len));
            self.raw_write(&t);
        }
        self.status_len = 0;
    }

    pub fn status(&mut self, t: &str) {
        if !self.is_console {
            return;
        }
        self.clear_status();
        let lim = self.console_w.saturating_sub(2);
        let x: String = if t.len() > lim {
            String::from_utf8_lossy(&t.as_bytes()[..lim]).into_owned()
        } else {
            t.to_string()
        };
        self.raw_write(&format!("\r{}", x));
        self.status_len = x.len();
    }

    pub fn write_line(&mut self, line: &str, col: usize) {
        self.clear_status();
        let s = if self.vt && col != COL_DEF {
            format!("{}{}{}\n", COL_SEQ[col], line, COL_SEQ[0])
        } else {
            format!("{}\n", line)
        };
        self.raw_write(&s);
        if let Some(f) = self.log.as_mut() {
            let _ = f.write_all(line.as_bytes());
            let _ = f.write_all(b"\n");
            let _ = f.flush();
        }
    }

    pub fn out(&mut self, line: &str, col: usize) {
        if self.quiet && !self.cfg.verbose {
            return; // fazlar sessiz çalışır; yalnızca özet satırı ve sonuç gösterilir (ayrıntı: --verbose)
        }
        if self.collect {
            self.deferred.push((line.to_string(), col));
            return; // sonuçlar toplanıyor: ekrana sonda yazılır
        }
        self.write_line(line, col);
    }

    pub fn out_now(&mut self, line: &str, col: usize) {
        let q = self.quiet;
        self.quiet = false;
        self.out(line, col);
        self.quiet = q;
    }

    pub fn flush_deferred(&mut self) {
        let d = std::mem::take(&mut self.deferred);
        for (l, c) in d {
            self.write_line(&l, c);
        }
    }

    pub fn out_lines(&mut self, v: &[String]) {
        for l in v {
            let c = line_color(l);
            self.out_now(l, c);
        }
    }

    pub fn head(&mut self, t: &str) {
        self.out("", COL_DEF);
        self.out(
            "==============================================================================",
            COL_CYN,
        );
        self.out(&format!("  {}", t), COL_CYN);
        self.out(
            "==============================================================================",
            COL_CYN,
        );
    }

    pub fn prog_add(&mut self, phase: usize, est: f64) {
        self.steps.push(ProgStep {
            phase,
            est: est.max(0.05),
            actual: -1.0,
        });
    }

    fn prog_remaining(&self, elapsed: &mut f64) -> f64 {
        let now = self.tick();
        *elapsed = (now - self.run_start) as f64 / 1000.0;
        let (mut done_est, mut done_act) = (0.0, 0.0);
        for s in &self.steps {
            if s.actual >= 0.0 && s.est > 0.0 {
                done_est += s.est;
                done_act += s.actual;
            }
        }
        let k = if done_est > 0.5 {
            (done_act / done_est).max(0.25).min(4.0)
        } else {
            1.0
        }; // tahmin/gerçek düzeltme katsayısı
        let mut rem = 0.0;
        for (i, s) in self.steps.iter().enumerate() {
            if s.actual >= 0.0 {
                continue;
            }
            if i as i64 == self.step_cur && self.step_active {
                let e = (now - self.step_start) as f64 / 1000.0;
                let f = self.step_frac;
                if f >= 0.05 && e >= 0.5 {
                    rem += e * (1.0 - f) / f; // adımın kendi hızından
                } else {
                    rem += 0f64.max((s.est * k * (1.0 - f)).max(s.est * k - e));
                }
            } else {
                rem += s.est * k;
            }
        }
        rem
    }

    pub fn prog_draw(&mut self, force: bool) {
        if !self.is_console || !self.collect {
            return;
        }
        let now = self.tick();
        if !force && now - self.last_draw < 200 {
            return;
        }
        self.last_draw = now;
        let mut line = "  Sonuçlar alınıyor, lütfen bekleyin...".to_string();
        if self.steps.is_empty() {
            let note = if self.prep_note.is_empty() {
                String::new()
            } else {
                format!(" ({})", self.prep_note)
            };
            let t = format!("{}  hazırlanıyor{}", line, note);
            self.status(&t);
            return;
        }
        let mut el = 0.0;
        let rem = self.prog_remaining(&mut el);
        let p = if el + rem > 0.0 { el / (el + rem) } else { 0.0 };
        let mut pct = (p * 100.0) as i32;
        if pct > 99 {
            pct = 99;
        }
        if pct < self.last_pct {
            pct = self.last_pct;
        }
        self.last_pct = pct;
        self.eta_smooth = if self.eta_smooth < 0.0 {
            rem
        } else {
            self.eta_smooth * 0.7 + rem * 0.3
        };
        const W: i32 = 20;
        let fill = pct * W / 100;
        let bar = format!("[{}{}]", "#".repeat(fill as usize), "-".repeat((W - fill) as usize));
        let eta = if el < 1.5 && pct < 3 {
            "kalan süre hesaplanıyor".to_string()
        } else {
            format!("kalan ~{}", fmt_dur(self.eta_smooth))
        };
        line.push_str(&format!("  {}  %{}   {}", bar, pct, eta));
        if self.step_active && self.step_cur >= 0 {
            let ph = self.steps[self.step_cur as usize].phase;
            if (1..=PHASES).contains(&ph) {
                line.push_str(&format!("   ({}/{} {})", ph, PHASES, PHASE_NAMES[ph]));
            }
        }
        self.status(&line);
    }

    pub fn prog_start(&mut self) {
        self.collect = true;
        self.run_start = self.tick();
        self.prog_draw(true);
    }

    pub fn prog_begin(&mut self, phase: usize) {
        self.step_active = false;
        let n = self.steps.len() as i64;
        let mut i = self.step_cur + 1;
        while i < n {
            if self.steps[i as usize].phase == phase {
                for j in (self.step_cur + 1)..i {
                    self.steps[j as usize].actual = 0.0;
                    self.steps[j as usize].est = 0.0; // atlanan/çalışmayan adım: hesaptan çıkar
                }
                self.step_cur = i;
                self.step_active = true;
                self.step_frac = 0.0;
                self.step_start = self.tick();
                break;
            }
            i += 1;
        }
        self.prog_draw(true);
    }

    pub fn prog_set(&mut self, f: f64) {
        if !self.step_active {
            return;
        }
        let f = f.clamp(0.0, 1.0);
        if f > self.step_frac {
            self.step_frac = f;
        }
        self.prog_draw(false);
    }

    pub fn prog_set_n(&mut self, i: usize, n: usize) {
        self.prog_set(if n != 0 { i as f64 / n as f64 } else { 1.0 });
    }

    pub fn prog_end(&mut self) {
        if !self.step_active {
            return;
        }
        let a = (self.tick() - self.step_start) as f64 / 1000.0;
        let c = self.step_cur as usize;
        self.steps[c].actual = a;
        self.step_frac = 1.0;
        self.step_active = false;
        self.prog_draw(true);
    }

    pub fn prog_finish(&mut self) {
        let el = (self.tick() - self.run_start) as f64 / 1000.0;
        self.collect = false;
        self.clear_status();
        let t = format!(
            "  Sonuçlar alındı  [####################]  %100   (toplam süre: {})",
            fmt_dur(el)
        );
        self.write_line(&t, COL_GRN);
        self.write_line("", COL_DEF);
        self.flush_deferred();
    }

    pub fn begin_phase(&mut self, n: usize, title: &str) {
        self.phase_no = n;
        self.phase_title = title.to_string();
        self.quiet = true;
        self.prog_begin(n);
    }

    pub fn end_phase(&mut self, summary: &str, col: usize) {
        self.quiet = false;
        let mut t = self.phase_title.clone();
        if t.len() < 40 {
            t.push_str(&" ".repeat(40 - t.len()));
        }
        if (1..=PHASES).contains(&self.phase_no) {
            if !summary.starts_with("atlandı") {
                self.phase_state[self.phase_no] = 1;
            } else if self.phase_state[self.phase_no] == 0 {
                self.phase_state[self.phase_no] = 2;
            }
        }
        let line = format!("  [{}/{}] {} {}", self.phase_no, PHASES, t, summary);
        self.out_now(&line, col);
        self.prog_end();
    }

    pub fn end_phase_guard(&mut self, summary: &str, col: usize) {
        let s = if summary.is_empty() { "tamam" } else { summary };
        self.end_phase(s, col);
    }

    pub fn skip_phase(&mut self, n: usize, title: &str, why: &str) {
        self.phase_no = n;
        self.phase_title = title.to_string();
        self.end_phase(&format!("atlandı: {}", why), COL_YEL);
    }

    pub fn register(&mut self, kind: &str, path: &str, an: Option<Arc<Analysis>>, note: &str, title: &str) -> usize {
        let key = if path.is_empty() { String::new() } else { lower_w(path) };
        if !key.is_empty() {
            if let Some(&ix) = self.find_idx.get(&key) {
                let f = &mut self.findings[ix];
                if !f.kinds.iter().any(|k| k == kind) {
                    f.kinds.push(kind.to_string());
                }
                if !note.is_empty() {
                    f.notes.push(note.to_string());
                }
                if let Some(a) = an {
                    let better = match &f.an {
                        None => true,
                        Some(old) => a.verdict > old.verdict,
                    };
                    if better {
                        f.an = Some(a);
                    }
                }
                return ix;
            }
        }
        let f = Finding {
            kinds: vec![kind.to_string()],
            path: path.to_string(),
            an: an.clone(),
            notes: if note.is_empty() {
                Vec::new()
            } else {
                vec![note.to_string()]
            },
            remnants: Vec::new(),
            detail: Vec::new(),
            loaded: false,
            title: if title.is_empty() {
                path.to_string()
            } else {
                title.to_string()
            },
            v_override: None,
            printed: false,
            printed_v: -99,
        };
        self.findings.push(f);
        let idx = self.findings.len() - 1;
        if !key.is_empty() {
            self.find_idx.insert(key, idx);
        }
        if let Some(a) = an {
            if a.verdict != Verdict::Tool {
                for s in &a.dict_s {
                    self.dict.entry(s.clone()).or_default().push(idx as i32);
                }
            }
        }
        idx
    }

    pub fn refresh_dict(&mut self, idx: usize) {
        if let Some(a) = self.findings[idx].an.clone() {
            for s in &a.dict_s {
                let v = self.dict.entry(s.clone()).or_default();
                if !v.contains(&(idx as i32)) {
                    v.push(idx as i32);
                }
            }
        }
    }

    fn dump_finding(&self, i: usize, num: i32) {
        if self.cfg.dump_dir.is_empty() {
            return;
        }
        let f = &self.findings[i];
        let base = format!(
            "{:02}_{}",
            num,
            safe_name(if f.title.is_empty() { "bulgu" } else { &f.title })
        );
        let mut rep: Vec<String> = Vec::new();
        rep.push(format!("{}  --  {}", verdict_name(f.verd()), where_text(f)));
        rep.push(f.title.clone());
        for n in &f.notes {
            rep.push(format!("- {}", n));
        }
        for r in &f.remnants {
            rep.push(format!("* {}", r));
        }
        if !f.detail.is_empty() {
            rep.extend(f.detail.iter().cloned());
        } else if let Some(a) = &f.an {
            rep.extend(render_analysis(a));
        }
        write_text_file(&format!("{}\\{}.rapor.txt", self.cfg.dump_dir, base), &rep);
        if let Some(a) = &f.an {
            if !a.strs.is_empty() {
                let mut seen = std::collections::BTreeSet::new();
                let mut ss: Vec<String> = Vec::new();
                for st in &a.strs {
                    if seen.insert(st.clone()) {
                        ss.push(st.clone());
                    }
                }
                write_text_file(&format!("{}\\{}.stringler.txt", self.cfg.dump_dir, base), &ss);
            }
        }
    }

    pub fn print_card(&mut self, i: usize) {
        let v = self.findings[i].verd();
        self.findings[i].printed = true;
        self.findings[i].printed_v = v as i32;
        self.card_count += 1;
        let num = self.card_count;
        self.printed_count += 1;
        let dnum = self.printed_count;
        let col = if v == Verdict::Confirmed { COL_RED } else { COL_YEL };
        let f = self.findings[i].clone();
        let a = f.an.as_deref();
        let name = if !f.path.is_empty() && !f.path.starts_with('<') {
            base_name(&f.path)
        } else {
            f.title.clone()
        };
        self.out_now(
            "  ----------------------------------------------------------------------",
            col,
        );
        self.out_now(&format!("  [{}] {}   {}", num, verdict_name(v), name), col);
        let row = |this: &mut Ctx, k: &str, val: &str| {
            let mut kk = k.to_string();
            if kk.len() < 14 {
                kk.push_str(&" ".repeat(14 - kk.len()));
            }
            this.out_now(&format!("      {}: {}", kk, val), COL_DEF);
        };
        if !f.path.is_empty() && !f.path.starts_with('<') {
            row(self, "Yol", &f.path);
        }
        row(self, "Nerede", &where_text(&f));
        if let Some(a) = a {
            if a.size != 0 {
                row(self, "SHA-256", &a.sha);
            }
        }
        if let Some(a) = a {
            let mut parts: Vec<String> = Vec::new();
            let cl = &a.cat_labels;
            if !cl[C_FAMILY as usize].is_empty() {
                parts.push(format!("Aile: {}", join_l(&cl[C_FAMILY as usize], 3, ", ")));
            }
            if !cl[C_CLIENT_A as usize].is_empty() {
                parts.push(format!("İstemci: {}", join_l(&cl[C_CLIENT_A as usize], 4, ", ")));
            }
            let mut mods = cl[C_MOD_STRONG as usize].clone();
            mods.extend(cl[C_MOD_WEAK as usize].iter().cloned());
            if !mods.is_empty() {
                parts.push(format!("Modüller: {}", join_l(&mods, 8, ", ")));
            }
            if !cl[C_OPT as usize].is_empty() {
                parts.push(format!("Ayarlar: {}", join_l(&cl[C_OPT as usize], 6, ", ")));
            }
            if !parts.is_empty() {
                row(self, "Hile", &parts.join("  |  "));
            }
            if a.jv.analyzed && !a.jv.lib_only {
                let jv = &a.jv;
                if !jv.mod_name.is_empty() || !jv.mod_id.is_empty() {
                    let nm = if jv.mod_name.is_empty() {
                        &jv.mod_id
                    } else {
                        &jv.mod_name
                    };
                    let s = format!(
                        "{}{}{}  {} sınıf{}",
                        nm,
                        if jv.mod_ver.is_empty() {
                            String::new()
                        } else {
                            format!(" {}", jv.mod_ver)
                        },
                        if jv.loader.is_empty() {
                            String::new()
                        } else {
                            format!("  [{}]", jv.loader)
                        },
                        jv.third_party,
                        if jv.obfuscated { ", OBFUSCATE EDİLMİŞ" } else { "" }
                    );
                    row(self, "Mod", &s);
                } else if jv.obfuscated {
                    row(self, "Obfuscation", &jv.obf_note);
                }
                let mut bk = 0usize;
                for b in &jv.beh {
                    let stop = bk >= 8;
                    bk += 1;
                    if stop {
                        row(self, "", &format!("... +{} modül davranışı daha", jv.beh.len() - 8));
                        break;
                    }
                    let mut kk = if bk == 1 {
                        "Java davranış".to_string()
                    } else {
                        String::new()
                    };
                    if kk.len() < 14 {
                        kk.push_str(&" ".repeat(14 - kk.len()));
                    }
                    let t = format!(
                        "      {}: {}{}sınıf {}{}  <- {}",
                        kk,
                        b.module,
                        if b.sev >= 3 { "  [KESİN]  " } else { "  [şüpheli]  " },
                        trunc(&b.cls, 44),
                        if b.indirect { " (yardımcı sınıflar)" } else { "" },
                        trunc(&b.why, 120)
                    );
                    self.out_now(&t, if b.sev >= 3 { COL_RED } else { COL_YEL });
                }
                if jv.sd_confirmed || jv.sd_suspect {
                    row(
                        self,
                        "Java self-dstr",
                        &format!(
                            "seviye {} - {}",
                            jv.sd_level,
                            if jv.sd_confirmed {
                                "KESİN (kendini silme/değiştirme mantığı)"
                            } else {
                                "şüpheli"
                            }
                        ),
                    );
                    for (k, nn) in jv.sd_notes.iter().enumerate() {
                        if k >= 3 {
                            break;
                        }
                        row(self, "", &format!("- {}", trunc(nn, 150)));
                    }
                }
            }
            let mut gui: Vec<String> = cl[C_IMGUI as usize].clone();
            gui.extend(cl[C_HOOKLIB as usize].iter().cloned());
            if !gui.is_empty() {
                row(self, "GUI/Hook", &join_l(&gui, 6, ", "));
            }
            if a.pe.valid && !a.pe.pdb.is_empty() {
                row(self, "PDB", &trunc(&a.pe.pdb, 120));
            }
            if !a.keys.is_empty() {
                let mut kt: Vec<String> = Vec::new();
                for k in &a.keys {
                    let role = if k.exit_branch {
                        "SELF-DESTRUCT tetiği"
                    } else if k.near_unload {
                        "tetik/menu (olası)"
                    } else if k.api.contains("WM_KEYDOWN") {
                        "menu/GUI tuşu (olası)"
                    } else {
                        "tuş yoklama"
                    };
                    kt.push(format!("{} = {}", vk_name(k.vk), role));
                }
                row(self, "Tuşlar", &join_l(&kt, 6, "  ;  "));
            }
            if a.sd.level > 0 || a.sd.sd_str {
                row(
                    self,
                    "Self-destruct",
                    &format!("seviye {}/4 - {}", a.sd.level, a.sd.level_name),
                );
                for (k, n) in a.sd.notes.iter().enumerate() {
                    if k >= 3 {
                        break;
                    }
                    row(self, "", &format!("- {}", trunc(n, 150)));
                }
            }
            let mut ev = a.ev.clone();
            ev.sort_by(|x, y| y.w.cmp(&x.w)); // stable_sort
            for (k, e) in ev.iter().enumerate() {
                if k >= 5 {
                    break;
                }
                row(
                    self,
                    if k == 0 { "Kanıt" } else { "" },
                    &format!("[{} +{}] {}", e.cls, e.w, trunc(&e.text, 150)),
                );
            }
        }
        for (k, n) in f.notes.iter().enumerate() {
            if k >= 5 {
                break;
            }
            row(self, if k == 0 { "Not" } else { "" }, &trunc(n, 160));
        }
        if !f.remnants.is_empty() {
            row(
                self,
                "Bellek izi",
                &format!("{} ortak string javaw heap'inde:", f.remnants.len()),
            );
            for (k, r) in f.remnants.iter().enumerate() {
                if k >= 4 {
                    break;
                }
                row(self, "", &format!("* {}", r));
            }
        }
        if !f.detail.is_empty() {
            for l in &f.detail {
                if l.contains("+--[") || l.starts_with("  +----") {
                    continue;
                }
                self.out_now(l, COL_DEF);
            }
        }
        if self.cfg.verbose {
            if let Some(a) = a {
                let r = render_analysis(a);
                self.out_lines(&r);
            }
        }
        self.dump_finding(i, dnum);
    }

    pub fn print_new(&mut self, title: &str) -> i32 {
        let mut conf: Vec<usize> = Vec::new();
        let mut sus: Vec<usize> = Vec::new();
        for (i, f) in self.findings.iter().enumerate() {
            let v = f.verd();
            if f.printed && (v as i32) <= f.printed_v {
                continue;
            }
            if v == Verdict::Confirmed {
                conf.push(i);
            } else if v == Verdict::Suspect {
                sus.push(i);
            }
        }
        if conf.is_empty() && sus.is_empty() {
            return 0;
        }
        self.out_now("", COL_DEF);
        self.out_now(
            "==============================================================================",
            COL_CYN,
        );
        self.out_now(&format!("  {}", title), COL_CYN);
        self.out_now(
            "==============================================================================",
            COL_CYN,
        );
        for &i in &conf {
            self.print_card(i);
        }
        if !sus.is_empty() {
            self.out_now("", COL_DEF);
            self.out_now(
                &format!("  ŞÜPHELİ (kesin değil, elle doğrulayın): {}", sus.len()),
                COL_YEL,
            );
            let mut k = 0usize;
            for &i in &sus {
                self.findings[i].printed = true;
                self.findings[i].printed_v = Verdict::Suspect as i32;
                let skip = k >= 8;
                k += 1;
                if skip {
                    continue;
                }
                let f = self.findings[i].clone();
                let nm = if !f.path.is_empty() && !f.path.starts_with('<') {
                    f.path.clone()
                } else {
                    f.title.clone()
                };
                let why = why_of(&f);
                self.out_now(&format!("   [?] {}  --  {}", trunc(&nm, 90), trunc(&why, 100)), COL_YEL);
                self.printed_count += 1;
                let n = self.printed_count;
                self.dump_finding(i, n);
            }
            if sus.len() > 8 {
                self.out_now(&format!("   ... +{} daha (--verbose)", sus.len() - 8), COL_GRY);
            }
        }
        conf.len() as i32
    }
}

pub fn fmt_dur(sec: f64) -> String {
    if sec < 1.0 {
        return "1 sn'den az".to_string();
    }
    let s = (sec + 0.5) as i64;
    if s < 60 {
        format!("{} sn", s)
    } else if s < 3600 {
        format!("{} dk {:02} sn", s / 60, s % 60)
    } else {
        format!("{} sa {:02} dk", s / 3600, (s % 3600) / 60)
    }
}

pub fn line_color(l: &str) -> usize {
    let folded = crate::util::katla(l);
    let l = folded.as_str();
    if l.contains("+--[") {
        return COL_CYN;
    }
    if l.contains("** TETIKLEYICI") {
        return COL_RED;
    }
    if l.contains("[KESIN]   ") {
        return COL_RED;
    }
    if l.contains("[supheli] ") {
        return COL_YEL;
    }
    if l.contains("KARAR") {
        return if l.contains("KESIN HILE") {
            COL_RED
        } else if l.contains("SUPHELI") {
            COL_YEL
        } else {
            COL_GRN
        };
    }
    if l.contains("[S +") {
        return COL_YEL;
    }
    COL_DEF
}

pub fn verdict_tag(v: Verdict) -> &'static str {
    match v {
        Verdict::Confirmed => "[KESİN]",
        Verdict::Suspect => "[ŞÜPHELİ]",
        Verdict::Tool => "[ARAÇ]",
        Verdict::Info => "[BİLGİ]",
        Verdict::Clean => "[TEMİZ]",
    }
}

pub fn why_of(f: &Finding) -> String {
    if let Some(a) = &f.an {
        if !a.vreason.is_empty() {
            if a.vreason.starts_with("gizlenme/yükleyici i") {
                for e in &a.ev {
                    if e.cls == 'H' {
                        return e.text.clone(); // genel gerekçe yerine somut kanıt metni
                    }
                }
            }
            return a.vreason.clone();
        }
    }
    for l in &f.detail {
        if let Some(k) = l.find("KARAR") {
            if let Some(d) = l[k..].find("--") {
                let r = &l[k + d + 2..];
                return r.trim_start_matches(' ').to_string();
            }
        }
    }
    f.notes.first().cloned().unwrap_or_default()
}

pub fn kind_has(f: &Finding, k: &str) -> bool {
    f.kinds.iter().any(|x| x.contains(k))
}

pub fn where_text(f: &Finding) -> String {
    let mut w: Vec<&str> = Vec::new();
    let has = |k: &str| kind_has(f, k);
    if has("YÜKLÜ MODÜL") {
        w.push("javaw İÇİNDE AKTİF (kod şu an çalışıyor)");
    }
    if has("GİZLİ MODÜL") {
        w.push("javaw içinde GİZLİ (PEB'den silinmiş / manuel map)");
    }
    if has("BOŞALTILMIŞ MODÜL KAYDI") {
        w.push("javaw'dan BOŞALTILMIŞ = SELF-DESTRUCT KANITI (ntdll unload kaydıyla doğrulandı)");
    } else if has("BOŞALTILMIŞ MODÜL") {
        w.push("javaw unload kaydında hile adli modül");
    }
    if has("ENJEKSİYON YOLU") {
        w.push("javaw belleğinde enjeksiyon yolu izi");
    }
    if has("BELLEKTE DLL YOLU") {
        w.push("javaw belleğinde DLL yolu kalıntısı");
    }
    if has("BELLEKTE PE") {
        w.push("javaw heap'inde PE kopyası");
    }
    if has("MODÜL DIŞI THREAD") {
        w.push("javaw içinde modül-dışı thread");
    }
    if has("HEAP KÜMESİ") {
        w.push("javaw heap'inde hile stringleri");
    }
    if has("JVM AJANI") {
        w.push("JVM ajanı olarak yüklenmiş");
    }
    if has("UNBACKED THREAD") {
        w.push("javaw içinde DOSYASIZ (unbacked) bellekte çalışan thread");
    }
    if has("UNBACKED BELLEK") {
        w.push("javaw içinde dosyasız yürütülebilir bellek bölgesi (hile/JVM içeriği taşıyor)");
    }
    if has("YENİDEN ADLANDIRILMIŞ") {
        w.push("Minecraft JVM'i java/javaw.exe adını taşımıyor (yeniden adlandırılmış: hedef gizleme)");
    }
    if has("YETİM THREAD") {
        w.push("javaw'da başlangıç kodu bellekten silinmiş thread = SELF-DESTRUCT artığı");
    }
    if has("API HOOK") {
        w.push("javaw içindeki sistem API'si HOOKLANMIŞ");
    }
    if has("API YAMASI") {
        w.push("javaw içindeki sistem API'sinin gövdesi YAMALANMIŞ");
    }
    if has("AÇIK HANDLE") {
        w.push("javaw bu dosyayı açıyor");
    }
    if has("KERNEL NESNESI") {
        w.push("javaw kernel nesnesi");
    }
    if has("DİSK DOSYASI") {
        w.push("diskte");
    }
    if w.is_empty() {
        w.push(if f.kinds.is_empty() { "?" } else { &f.kinds[0] });
    }
    w.join("  |  ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dur() {
        assert_eq!(fmt_dur(0.5), "1 sn'den az");
        assert_eq!(fmt_dur(75.0), "1 dk 15 sn");
        assert_eq!(fmt_dur(3700.0), "1 sa 01 dk");
    }
    #[test]
    fn colors() {
        assert_eq!(line_color("  +--[ x ]--"), COL_CYN);
        assert_eq!(line_color("  | KARAR : KESIN HILE"), COL_RED);
        assert_eq!(line_color("hello"), COL_DEF);
    }
    #[test]
    fn where_default() {
        let f = Finding {
            kinds: vec!["DİSK DOSYASI".into()],
            path: String::new(),
            an: None,
            notes: vec![],
            remnants: vec![],
            detail: vec![],
            loaded: false,
            title: String::new(),
            v_override: None,
            printed: false,
            printed_v: -99,
        };
        assert_eq!(where_text(&f), "diskte");
        assert_eq!(why_of(&f), "");
    }
}
