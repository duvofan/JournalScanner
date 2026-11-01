use crate::api::{goster, uslice, utail};
use crate::app::App;
use crate::model::{Page, PAGES};
use crate::pages::{state_text, verdict_tag};
use js_core::browser::BrowserScan;
use js_core::client::ClientResult;
use js_core::devices::DeviceResult;
use js_core::disk::{DiskResult, DiskScanner, DiskStats};
use js_core::dllscan::DllScanResult;
use js_core::events::EventResult;
use js_core::jar::ScanResult;
use js_core::journal::JournalScan;
use js_core::logs::LogScan;
use js_core::prefetch::PrefetchResult;
use js_core::report::Report;
use js_core::util::StopFlag;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::Sender;

#[derive(Clone)]
pub struct Tx {
    tx: Sender<Msg>,
    ctx: egui::Context,
    uyandi: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

const KARE_ARALIGI: std::time::Duration = std::time::Duration::from_millis(50);

impl Tx {
    pub fn new(tx: Sender<Msg>, ctx: egui::Context) -> Self {
        Tx {
            tx,
            ctx,
            uyandi: Default::default(),
        }
    }
    pub fn send(&self, m: Msg) {
        let _ = self.tx.send(m);
        if !self.uyandi.swap(true, std::sync::atomic::Ordering::AcqRel) {
            self.ctx.request_repaint_after(KARE_ARALIGI);
        }
    }
    pub fn uyandi_sifirla(&self) {
        self.uyandi.store(false, std::sync::atomic::Ordering::Release);
    }
    fn nav(&self, p: Page, t: impl Into<String>, tag: char) {
        self.send(Msg::Nav(p, t.into(), tag));
    }
}

pub struct ModOut {
    pub jar: Vec<ScanResult>,
    pub err: String,
    pub dirs: Vec<String>,
}

pub enum Msg {
    Nav(Page, String, char),
    Desc(String),
    ModProgress {
        i: i32,
        total: i32,
        name: String,
    },
    DiskProgress {
        txt: String,
        cur: String,
        files: i64,
        flagged: i64,
        archives: i64,
        est_total: i64,
        eta_secs: f64,
    },
    DiskFound(Box<ScanResult>),
    ModFound(Box<ScanResult>),
    Mod(Box<ModOut>),
    Log(Box<LogScan>),
    Dev(Box<DeviceResult>),
    Evt(Box<(EventResult, PrefetchResult)>),
    Client(Box<ClientResult>),
    Dll(Box<DllScanResult>),
    Browser(Box<BrowserScan>),
    Journal(Box<JournalScan>),
    Disk(Box<(DiskResult, Report)>),
}

pub fn guard_ui<T>(f: impl FnOnce() -> T) -> Option<T> {
    catch_unwind(AssertUnwindSafe(f)).ok()
}

fn panic_msg(e: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = e.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = e.downcast_ref::<String>() {
        s.clone()
    } else {
        "bilinmeyen hata".to_string()
    }
}

fn guarded<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(panic_msg)
}

fn spawn16(f: impl FnOnce() + Send + 'static) {
    let _ = std::thread::Builder::new().stack_size(16 << 20).spawn(f);
}

fn client_state(tx: &Tx, r: &ClientResult) {
    if r.rank > 0 {
        let first = r.verdict.split(' ').next().unwrap_or("");
        tx.nav(
            Page::Client,
            format!("× {}", goster(first)),
            crate::theme::rank_tag(r.rank),
        );
    } else if !r.minecraft.is_empty() {
        tx.nav(Page::Client, format!("√ {} çalışıyor", r.minecraft.len()), 't');
    } else {
        tx.nav(Page::Client, "oyun açık değil", 'n');
    }
}

fn client_job(tx: &Tx, stop: &StopFlag) -> ClientResult {
    let prog = |m: &str| tx.send(Msg::Desc(uslice(m, 150)));
    let r = match guarded(|| js_core::client::scan_active_clients(Some(&prog), None, Some(stop))) {
        Ok(r) => r,
        Err(e) => {
            let mut r = ClientResult::default();
            r.errors.push(format!("Aktif client tarama hatası: {}", e));
            r
        }
    };
    client_state(tx, &r);
    r
}

fn mod_task(tx: &Tx, mods_dir: &str) -> (Vec<ScanResult>, String, Vec<String>) {
    let mut jar: Vec<ScanResult> = Vec::new();
    let mut mod_err = String::new();
    let mut dirs: Vec<String> = Vec::new();
    let r = guarded(|| {
        if js_core::util::is_dir(mods_dir) {
            dirs.push(mods_dir.to_string());
        }
        dirs.extend(js_core::logs::auto_mod_dirs(mods_dir));
        if dirs.is_empty() {
            return Some(format!("Mods klasörü bulunamadı: {}", mods_dir));
        }
        let files: Vec<String> = dirs.iter().flat_map(|d| js_core::jar::candidate_files(d)).collect();
        let cb = |i: i32, total: i32, name: &str| {
            tx.send(Msg::ModProgress {
                i,
                total,
                name: name.to_string(),
            });
            tx.nav(Page::Mod, format!("» {}/{}", i, total), 'i');
        };
        let found = |_i: usize, r: &ScanResult| tx.send(Msg::ModFound(Box::new(r.clone())));
        jar.extend(js_core::jar::scan_files_cb(&files, Some(&cb), 0, Some(&found)));
        None
    });
    match r {
        Ok(Some(e)) => {
            mod_err = e;
            tx.nav(Page::Mod, "klasör yok", 's');
            dirs.clear();
        }
        Ok(None) => {
            let ranks: Vec<i32> = jar.iter().map(|r| r.rank).collect();
            let (t, c) = state_text(&ranks, "√ temiz");
            tx.nav(Page::Mod, t, c);
            if !js_core::util::is_dir(mods_dir) {
                mod_err = format!("Seçili mods klasörü yok ({}); başlatıcı klasörleri tarandı.", mods_dir);
            }
        }
        Err(e) => {
            mod_err = format!("Mod tarama hatası: {}", e);
            tx.nav(Page::Mod, "hata", 'k');
        }
    }
    (jar, mod_err, dirs)
}

fn event_task(tx: &Tx, app_stop: &StopFlag) -> (EventResult, PrefetchResult) {
    let ev = match guarded(|| js_core::events::scan_ntfs_events(5)) {
        Ok(e) => e,
        Err(e) => EventResult {
            error: format!("Olay günlüğü hatası: {}", e),
            ..Default::default()
        },
    };
    if !ev.error.is_empty() && ev.findings.is_empty() {
        tx.nav(Page::Evt, "erişim yok", 'n');
    } else if !ev.findings.is_empty() {
        tx.nav(Page::Evt, format!("× {} kayıt", ev.findings.len()), 'y');
    } else {
        tx.nav(Page::Evt, "√ kayıt yok", 't');
    }
    let pf = match guarded(|| js_core::prefetch::scan_prefetch(Some(&ev), Some(app_stop))) {
        Ok(p) => p,
        Err(e) => PrefetchResult {
            error: format!("Prefetch hatası: {}", e),
            ..Default::default()
        },
    };
    if !pf.error.is_empty() && pf.findings.is_empty() {
        tx.nav(Page::Pf, "erişim yok", 'n');
    } else {
        let r: Vec<i32> = pf
            .findings
            .iter()
            .map(|f| match f.category.as_str() {
                "KESIN_HILE" => 3,
                "YASAKLI_ISLEV" => 2,
                _ => 1,
            })
            .collect();
        let (t, c) = state_text(&r, "√ temiz");
        tx.nav(Page::Pf, t, c);
    }
    (ev, pf)
}

fn log_task(tx: &Tx, mods_dir: &str) -> LogScan {
    match guarded(|| js_core::logs::scan_logs(5, mods_dir, None, None, 0.0)) {
        Ok(l) => {
            let r: Vec<i32> = l.results.iter().map(|x| x.rank).collect();
            let (t, c) = state_text(&r, "√ temiz");
            tx.nav(Page::Log, t, c);
            l
        }
        Err(e) => {
            let mut l = LogScan::default();
            l.errors.push(format!("Log tarama hatası: {}", e));
            tx.nav(Page::Log, "hata", 'k');
            l
        }
    }
}

fn dev_task(tx: &Tx) -> DeviceResult {
    match guarded(|| js_core::devices::scan_devices(5, None)) {
        Ok(d) => {
            if !d.supported {
                tx.nav(Page::Dev, "yalnız Windows", 'n');
            } else {
                tx.nav(
                    Page::Dev,
                    format!("BT {} | USB {}", d.bluetooth.len(), d.usb.len()),
                    'i',
                );
            }
            d
        }
        Err(e) => {
            let mut d = DeviceResult::default();
            d.errors.push(format!("Bluetooth/USB tarama hatası: {}", e));
            tx.nav(Page::Dev, "hata", 'k');
            d
        }
    }
}

impl App {
    fn phase(&mut self, title: &str) {
        self.status_title = (title.to_string(), 'x');
        self.status_desc = (String::new(), 'n');
    }

    pub fn learn_commit(&mut self, added: i32, what: &str) {
        if added <= 0 {
            return;
        }
        guard_ui(js_core::learn::learn_save);
        self.learn_refresh();
        self.set_foot(
            format!("Hafıza: {} - {} yeni kayıt (toplam {})", what, added, self.learn_n),
            't',
        );
    }

    pub fn running_names(&self) -> Vec<&'static str> {
        [
            (self.mod_running, "Mod taraması"),
            (self.evt_running, "Olay / Prefetch taraması"),
            (self.log_running, "Log taraması"),
            (self.dev_running, "Bluetooth / USB taraması"),
            (self.client_running, "Aktif Client taraması"),
            (self.disk_running, "Disk taraması"),
            (self.dll_running, "DLL / String taraması"),
            (self.brow_running, "Tarayıcı geçmişi taraması"),
            (self.jrnl_running, "Journal geçmişi taraması"),
        ]
        .into_iter()
        .filter_map(|(r, n)| r.then_some(n))
        .collect()
    }

    pub fn running_count(&self) -> usize {
        self.running_names().len()
    }

    fn done_status(&mut self, title: &str, desc: String) {
        let names = self.running_names();
        match names.len() {
            0 => {
                self.status_title = (title.to_string(), 'x');
                self.status_desc = (desc, 'n');
            }
            1 => {
                self.status_title = (format!("{} sürüyor", names[0]), 'x');
                self.status_desc = (String::new(), 'n');
            }
            _ => {}
        }
    }

    pub fn is_running(&self, p: Page) -> bool {
        match p {
            Page::Sum => self.running_count() > 0,
            Page::Mod => self.mod_running,
            Page::Disk => self.disk_running,
            Page::Log => self.log_running,
            Page::Client => self.client_running,
            Page::Dev => self.dev_running,
            Page::Pf | Page::Evt => self.evt_running,
            Page::Dll | Page::Str => self.dll_running,
            Page::Brow => self.brow_running,
            Page::Jrnl => self.jrnl_running,
        }
    }

    pub fn has_data(&self, p: Page) -> bool {
        match p {
            Page::Sum => self.verdict.is_some(),
            Page::Mod => self.has_mod,
            Page::Disk => self.has_disk,
            Page::Log => self.has_logs,
            Page::Client => self.has_client,
            Page::Dev => self.has_dev,
            Page::Pf | Page::Evt => self.has_prefetch,
            Page::Dll | Page::Str => self.has_dll,
            Page::Brow => self.has_browser,
            Page::Jrnl => self.has_journal,
        }
    }

    pub fn any_scanned(&self) -> bool {
        PAGES.iter().any(|&p| p != Page::Sum && self.has_data(p))
    }

    pub fn has_stop(&self, p: Page) -> bool {
        matches!(
            p,
            Page::Disk | Page::Client | Page::Pf | Page::Evt | Page::Dll | Page::Str | Page::Brow | Page::Jrnl
        )
    }

    pub fn start_page(&mut self, p: Page) {
        match p {
            Page::Sum => self.start_all(),
            Page::Mod => self.start_mod_scan(),
            Page::Disk => self.start_disk_scan(),
            Page::Log => self.start_log_scan(),
            Page::Client => self.start_client_scan(),
            Page::Dev => self.start_dev_scan(),
            Page::Pf | Page::Evt => self.start_event_scan(),
            Page::Dll | Page::Str => self.start_dll_scan(),
            Page::Brow => self.start_browser_scan(),
            Page::Jrnl => self.start_journal_scan(),
        }
    }

    pub fn stop_page(&mut self, p: Page) {
        match p {
            Page::Disk => self.disk_stop.set(),
            Page::Client => self.client_stop.set(),
            Page::Pf | Page::Evt => self.app_stop.set(),
            Page::Dll | Page::Str => self.dll_stop.set(),
            Page::Brow => self.brow_stop.set(),
            Page::Jrnl => self.jrnl_stop.set(),
            _ => return,
        }
        self.set_foot("Durduruluyor...", 'x');
    }

    pub fn start_all(&mut self) {
        self.start_mod_scan();
        self.start_event_scan();
        self.start_log_scan();
        self.start_dev_scan();
        self.start_client_scan();
        self.start_disk_scan();
        self.start_dll_scan();
        self.start_browser_scan();
        self.start_journal_scan();
        self.set_foot("", 'n');
    }

    pub fn drain_msgs(&mut self) {
        self.tx.uyandi_sifirla();
        let mut kuyruk: Vec<Msg> = Vec::new();
        while let Ok(m) = self.rx.try_recv() {
            kuyruk.push(m);
        }
        let son_mod = kuyruk.iter().rposition(|m| matches!(m, Msg::ModProgress { .. }));
        let mut live_dirty = false;
        let mut mod_dirty = false;
        let son_disk = kuyruk.iter().rposition(|m| matches!(m, Msg::DiskProgress { .. }));
        for (k, m) in kuyruk.into_iter().enumerate() {
            match &m {
                Msg::ModProgress { .. } if Some(k) != son_mod => continue,
                Msg::DiskProgress { .. } if Some(k) != son_disk => continue,
                _ => {}
            }
            match m {
                Msg::Nav(p, t, c) => self.nav_set_now(p, &t, c),
                Msg::Desc(s) => self.status_desc = (s, 'n'),
                Msg::ModProgress { i, total, name } => {
                    self.prog = i as f32 / total.max(1) as f32;
                    self.status_title = (format!("Mod analizi  {} / {}", i, total), 'x');
                    self.status_desc = (uslice(&name, 90), 'n');
                }
                Msg::DiskProgress {
                    txt,
                    cur,
                    files,
                    flagged,
                    archives,
                    est_total,
                    eta_secs,
                } => {
                    self.disk_ui = crate::app::DiskUi {
                        files,
                        est_total,
                        eta_secs,
                        flagged,
                        archives,
                    };
                    self.lbl_disk = (txt, 'n');
                    self.nav_set_now(Page::Disk, &format!("» {}", crate::app::fmt_n(files)), 'i');
                    if self.running_count() <= 1 {
                        self.status_title = (format!("Disk taraması  -  {} dosya, {} bulgu", files, flagged), 'x');
                        let d = if cur.chars().count() > 123 {
                            format!("...{}", utail(&cur, 120))
                        } else {
                            cur
                        };
                        self.status_desc = (d, 'n');
                    }
                }
                Msg::DiskFound(r) => {
                    if self.disk_running {
                        live_dirty |= self.disk_found(*r);
                    }
                }
                Msg::ModFound(r) => {
                    if self.mod_running {
                        mod_dirty |= self.mod_found(*r);
                    }
                }
                Msg::Mod(o) => self.on_mod(*o),
                Msg::Log(l) => self.on_logs(*l),
                Msg::Dev(d) => self.on_devices(*d),
                Msg::Evt(b) => self.on_events(*b),
                Msg::Client(r) => self.on_client(*r),
                Msg::Dll(r) => self.on_dll(*r),
                Msg::Browser(r) => self.on_browser(*r),
                Msg::Journal(r) => self.on_journal(*r),
                Msg::Disk(b) => {
                    let (d, rep) = *b;
                    self.on_disk(d, rep);
                    live_dirty = false;
                }
            }
        }
        if live_dirty {
            self.ld[Page::Disk.idx()].refresh();
        }
        if mod_dirty {
            self.ld[Page::Mod.idx()].refresh();
        }
    }

    pub fn mod_found(&mut self, r: ScanResult) -> bool {
        let idx = self.jar_results.len();
        let pos = self.order.len();
        let v = if r.official_fabric && r.rank == 0 {
            "Resmî Fabric".to_string()
        } else if r.trusted_infra && r.rank == 0 {
            "Altyapı (Mixin)".to_string()
        } else if r.server_plugin && r.rank == 0 {
            "Sunucu eklentisi".to_string()
        } else {
            r.verdict.clone()
        };
        let path = if r.file.is_empty() {
            r.name.clone()
        } else {
            r.file.clone()
        };
        self.ld[Page::Mod.idx()].rows.push(crate::model::TRow::new(
            pos.to_string(),
            "",
            r.name.clone(),
            v,
            path,
            crate::theme::rank_tag(r.rank),
        ));
        self.jar_results.push(r);
        self.order.push(idx);
        self.recount();
        true
    }

    pub fn recount(&mut self) {
        use std::collections::BTreeMap;
        let mut mc: BTreeMap<char, i32> = BTreeMap::from([('k', 0), ('y', 0), ('s', 0), ('t', 0)]);
        for r in &self.jar_results {
            *mc.entry(crate::theme::rank_tag(r.rank)).or_insert(0) += 1;
        }
        self.counts.insert("mod".into(), mc);
        let mut lc: BTreeMap<char, i32> = BTreeMap::from([('k', 0), ('y', 0), ('s', 0)]);
        for r in &self.logs.results {
            *lc.entry(crate::theme::rank_tag(r.rank)).or_insert(0) += 1;
        }
        lc.remove(&'t');
        self.counts.insert("log".into(), lc);
        let mut pc: BTreeMap<char, i32> = BTreeMap::from([('k', 0), ('y', 0), ('s', 0)]);
        for f in &self.prefetch.findings {
            *pc.entry(crate::pages::pf_tag(&f.category)).or_insert(0) += 1;
        }
        self.counts.insert("pf".into(), pc);
        self.update_counts();
    }

    pub fn disk_found(&mut self, r: ScanResult) -> bool {
        if !self.disk_seen.insert(r.file.clone()) {
            return false;
        }
        let n = self.disk_live.len();
        let tag = crate::theme::rank_tag(r.rank);
        let mut txt = crate::pages::short_label(&r.file);
        if r.file.contains("(jar'a paketlenmemiş") {
            txt += "  (açık sınıflar)";
        }
        self.ld[Page::Disk.idx()].rows.push(crate::model::TRow::new(
            format!("L{}", n),
            "",
            txt,
            r.verdict.clone(),
            r.file.clone(),
            tag,
        ));
        self.disk_live.push(r);
        let mut c: std::collections::BTreeMap<char, i32> = std::collections::BTreeMap::new();
        for x in &self.disk_live {
            let t = crate::theme::rank_tag(x.rank);
            if t != 't' {
                *c.entry(t).or_insert(0) += 1;
            }
        }
        self.counts.insert("disk".into(), c);
        self.update_counts();
        true
    }

    fn on_mod(&mut self, out: ModOut) {
        self.mod_running = false;
        self.jar_results = out.jar;
        self.mod_err = out.err;
        self.mod_dirs = out.dirs;
        self.has_mod = true;
        guard_ui(|| self.render_mod());
        self.rebuild_report();
        let mut n = 0;
        for r in &self.jar_results {
            n += guard_ui(|| js_core::learn::learn_from_result(r, "Mod Taramasi")).unwrap_or(0);
        }
        self.learn_commit(n, "mod");
        if !self.mod_err.is_empty() {
            let e = self.mod_err.clone();
            self.set_foot(e, 'k');
        } else {
            let mut s = String::from("Mod taraması tamam.");
            if self.mod_dirs.len() > 1 {
                s += &format!(" ({} mods klasörü)", self.mod_dirs.len());
            }
            self.set_foot(s, 't');
        }
        self.done_status("Mod taraması tamam", String::new());
    }

    fn on_logs(&mut self, l: LogScan) {
        self.log_running = false;
        self.logs = l;
        self.has_logs = true;
        guard_ui(|| self.render_logs());
        self.rebuild_report();
        self.set_foot("Log taraması tamam.", 't');
        self.done_status("Log taraması tamam", String::new());
    }

    fn on_devices(&mut self, d: DeviceResult) {
        self.dev_running = false;
        self.dev = d;
        self.has_dev = true;
        guard_ui(|| self.render_devices());
        self.rebuild_report();
        self.set_foot("Bluetooth / USB taraması tamam.", 't');
        self.done_status("Bluetooth / USB taraması tamam", String::new());
    }

    fn on_events(&mut self, b: (EventResult, PrefetchResult)) {
        self.evt_running = false;
        let (ev, pf) = b;
        self.event_result = ev;
        self.prefetch = pf;
        self.has_prefetch = true;
        guard_ui(|| {
            self.render_prefetch();
            self.render_events();
        });
        self.rebuild_report();
        let mut n = 0;
        for f in &self.prefetch.findings {
            if let Some(sr) = &f.scan_result {
                n += guard_ui(|| js_core::learn::learn_from_result(sr, "Prefetch")).unwrap_or(0);
            }
        }
        self.learn_commit(n, "prefetch");
        self.set_foot("Olay / Prefetch taraması tamam.", 't');
        self.done_status("Olay / Prefetch taraması tamam", String::new());
    }

    fn on_client(&mut self, r: ClientResult) {
        self.client_running = false;
        let v = r.verdict.clone();
        self.client = r;
        self.has_client = true;
        guard_ui(|| self.render_client());
        self.rebuild_report();
        self.done_status("Aktif Client taraması tamam", format!("Karar: {}", goster(&v)));
    }

    pub fn rebuild_report(&mut self) {
        let rep = guard_ui(|| {
            let mut rep = js_core::report::build_report(
                &self.jar_results,
                &self.event_result,
                &self.mods_dir,
                self.has_prefetch.then_some(&self.prefetch),
                self.has_logs.then_some(&self.logs),
                self.has_dev.then_some(&self.dev),
                self.has_client.then_some(&self.client),
            );
            let d = &self.mod_dirs;
            if d.len() > 1
                || (d.len() == 1 && js_core::util::path_norm(&d[0]) != js_core::util::path_norm(&self.mods_dir))
            {
                rep.full += "\nTaranan mods klasörleri:\n";
                for x in d {
                    rep.full += &format!("  - {}\n", x);
                }
            }
            rep
        });
        if let Some(rep) = rep {
            self.sum_lines = rep.full.split('\n').map(str::to_string).collect();
            self.full_report = rep.full;
            let (txt, tag) = match rep.verdict.as_str() {
                "KESIN HILE" => ("× KESİN", 'k'),
                "YASAKLI ISLEV" => ("× YASAKLI", 'y'),
                "SUPHELI" => ("! ŞÜPHELİ", 's'),
                _ => ("√ temiz", 't'),
            };
            self.nav_set_now(Page::Sum, txt, tag);
            self.verdict = Some(rep.verdict);
        }
        self.recount();
    }

    fn on_dll(&mut self, r: DllScanResult) {
        self.dll_running = false;
        let (ran, err, kesin, supheli, verdict, active) = (
            r.ran,
            r.error.clone(),
            r.kesin,
            r.supheli,
            r.verdict.clone(),
            r.javaw_active,
        );
        self.dll = r;
        self.has_dll = true;
        guard_ui(|| {
            self.render_dll();
            self.render_strings();
        });
        let mut n = 0;
        for f in &self.dll.findings {
            n += guard_ui(|| js_core::learn::learn_from_dll(f)).unwrap_or(0);
        }
        self.learn_commit(n, "DLL / String Scanner");
        let (st, col) = if !ran && !err.is_empty() {
            (err.clone(), 'k')
        } else {
            (
                format!("{} kesin · {} şüpheli · Karar: {}", kesin, supheli, goster(&verdict)),
                verdict_tag(&verdict),
            )
        };
        self.lbl_dll = (st, col);
        let desc = if ran {
            format!(
                "Karar: {}{}",
                goster(&verdict),
                if active { "  (javaw aktif)" } else { "" }
            )
        } else {
            err.clone()
        };
        self.done_status("DLL / yerel modül taraması tamam", desc);
        self.set_foot(if ran { "DLL taraması tamam.".to_string() } else { err }, col);
    }

    fn on_browser(&mut self, r: BrowserScan) {
        self.brow_running = false;
        let b = r;
        let (ran, err, verdict) = (b.ran, b.error.clone(), b.verdict.clone());
        let st = format!(
            "{} dosya okundu · {} kesin · {} yasaklı · {} şüpheli · {} bilgi · Karar: {}",
            b.files_checked,
            b.kesin,
            b.yasakli,
            b.supheli,
            b.info,
            goster(&verdict)
        );
        self.browser = b;
        self.has_browser = true;
        guard_ui(|| self.render_browser());
        let (st, col) = if !ran && !err.is_empty() {
            (err.clone(), 'k')
        } else {
            (st, verdict_tag(&verdict))
        };
        self.lbl_brow = (st, col);
        let desc = if ran {
            format!("Karar: {}", goster(&verdict))
        } else {
            err.clone()
        };
        self.done_status("Tarayıcı geçmişi taraması tamam", desc);
        self.set_foot(
            if ran {
                "Tarayıcı geçmişi taraması tamam.".to_string()
            } else {
                err
            },
            col,
        );
    }

    fn on_journal(&mut self, r: JournalScan) {
        self.jrnl_running = false;
        let j = r;
        let (ran, err, verdict) = (j.ran, j.error.clone(), j.verdict.clone());
        let st = format!(
            "{} dosya (USN {}, Recent {}) · {} okundu · {} kesin · {} yasaklı · {} şüpheli · {} bilgi · Karar: {}",
            j.entries,
            j.from_usn,
            j.from_recent,
            j.files_checked,
            j.kesin,
            j.yasakli,
            j.supheli,
            j.info,
            goster(&verdict)
        );
        self.journal = j;
        self.has_journal = true;
        guard_ui(|| self.render_journal());
        let (st, col) = if !ran && !err.is_empty() {
            (err.clone(), 'k')
        } else {
            (st, verdict_tag(&verdict))
        };
        self.lbl_jrnl = (st, col);
        let desc = if ran {
            format!("Karar: {}", goster(&verdict))
        } else {
            err.clone()
        };
        self.done_status("Journal geçmişi taraması tamam", desc);
        self.set_foot(
            if ran {
                "Journal geçmişi taraması tamam.".to_string()
            } else {
                err
            },
            col,
        );
    }

    fn on_disk(&mut self, d: DiskResult, rep: Report) {
        let sel_path = {
            let l = &self.ld[Page::Disk.idx()];
            l.rows
                .iter()
                .find(|r| r.iid == l.selected && r.iid.starts_with('L'))
                .map(|r| r.v2.clone())
        };
        self.disk_live.clear();
        self.disk_seen.clear();
        self.disk_t0 = None;
        self.disk = d;
        self.has_disk = true;
        self.disk_full_report = rep.full;
        let v = rep.verdict;
        self.disk_running = false;
        guard_ui(|| self.render_disk(&v));
        if let Some(sp) = sel_path {
            let iid = self.ld[Page::Disk.idx()]
                .rows
                .iter()
                .find(|r| r.v2 == sp)
                .map(|r| r.iid.clone());
            if let Some(iid) = iid {
                self.table_select(Page::Disk, &iid);
            }
        }
        let mut n = 0;
        for r in &self.disk.results {
            n += guard_ui(|| js_core::learn::learn_from_result(r, "Disk Taramasi")).unwrap_or(0);
        }
        self.learn_commit(n, "disk");
        self.set_foot("Disk taraması tamam.", 't');
        self.done_status(&format!("Disk taraması bitti - karar: {}", goster(&v)), String::new());
    }

    pub fn start_mod_scan(&mut self) {
        if self.mod_running {
            return;
        }
        self.mod_running = true;
        self.prog = 0.0;
        self.has_mod = false;
        self.jar_results.clear();
        self.order.clear();
        {
            let l = &mut self.ld[Page::Mod.idx()];
            l.rows.clear();
            l.selected.clear();
            l.detail.clear();
            l.refresh();
        }
        self.recount();
        self.nav_set_now(Page::Mod, "» taranıyor", 'i');
        self.phase("Mod taraması başladı");
        let mods_dir = self.mods_dir.trim().to_string();
        let tx = self.tx.clone();
        spawn16(move || {
            let (jar, err, dirs) = mod_task(&tx, &mods_dir);
            tx.send(Msg::Mod(Box::new(ModOut { jar, err, dirs })));
        });
    }

    pub fn start_log_scan(&mut self) {
        if self.log_running {
            return;
        }
        self.log_running = true;
        self.nav_set_now(Page::Log, "» taranıyor", 'i');
        self.phase("Log taraması başladı");
        let mods_dir = self.mods_dir.trim().to_string();
        let tx = self.tx.clone();
        spawn16(move || {
            let l = log_task(&tx, &mods_dir);
            tx.send(Msg::Log(Box::new(l)));
        });
    }

    pub fn start_dev_scan(&mut self) {
        if self.dev_running {
            return;
        }
        self.dev_running = true;
        self.nav_set_now(Page::Dev, "» taranıyor", 'i');
        self.phase("Bluetooth / USB taraması başladı");
        let tx = self.tx.clone();
        spawn16(move || {
            let d = dev_task(&tx);
            tx.send(Msg::Dev(Box::new(d)));
        });
    }

    pub fn start_event_scan(&mut self) {
        if self.evt_running {
            return;
        }
        self.evt_running = true;
        self.app_stop.clear();
        self.nav_set_now(Page::Evt, "» taranıyor", 'i');
        self.nav_set_now(Page::Pf, "» taranıyor", 'i');
        self.phase("Olay / Prefetch taraması başladı");
        let tx = self.tx.clone();
        let stop = self.app_stop.clone();
        spawn16(move || {
            let r = event_task(&tx, &stop);
            tx.send(Msg::Evt(Box::new(r)));
        });
    }

    pub fn start_client_scan(&mut self) {
        if self.client_running {
            return;
        }
        self.client_running = true;
        self.client_stop.clear();
        self.nav_set_now(Page::Client, "» taranıyor", 'i');
        self.phase("Aktif Client taraması başladı");
        let tx = self.tx.clone();
        let stop = self.client_stop.clone();
        spawn16(move || {
            let r = client_job(&tx, &stop);
            tx.send(Msg::Client(Box::new(r)));
        });
    }

    pub fn start_dll_scan(&mut self) {
        if self.dll_running {
            return;
        }
        self.dll_running = true;
        self.dll_stop.clear();
        self.nav_set_now(Page::Dll, "» taranıyor", 'i');
        self.nav_set_now(Page::Str, "» taranıyor", 'i');
        self.lbl_dll = (String::new(), 'n');
        self.lbl_str = (String::new(), 'n');
        self.phase("DLL / String taraması başladı");
        let tx = self.tx.clone();
        let stop = self.dll_stop.clone();
        spawn16(move || {
            let prog = |m: &str| tx.send(Msg::Desc(uslice(m, 150)));
            let r = guarded(|| js_core::dllscan::scan_dll(&[], false, Some(&prog), Some(&stop))).unwrap_or_else(|e| {
                DllScanResult {
                    error: format!("DLL tarama hatası: {}", e),
                    ..Default::default()
                }
            });
            tx.send(Msg::Dll(Box::new(r)));
        });
    }

    pub fn start_browser_scan(&mut self) {
        if self.brow_running {
            return;
        }
        self.brow_running = true;
        self.brow_stop.clear();
        self.nav_set_now(Page::Brow, "» taranıyor", 'i');
        self.lbl_brow = (String::new(), 'n');
        self.phase("Tarayıcı geçmişi taraması başladı");
        let tx = self.tx.clone();
        let stop = self.brow_stop.clone();
        spawn16(move || {
            let prog = |m: &str| tx.send(Msg::Desc(uslice(m, 150)));
            let r = guarded(|| js_core::browser::scan_browsers(0, Some(&prog), Some(&stop))).unwrap_or_else(|e| {
                BrowserScan {
                    error: format!("Tarayıcı tarama hatası: {}", e),
                    ..Default::default()
                }
            });
            tx.send(Msg::Browser(Box::new(r)));
        });
    }

    pub fn start_journal_scan(&mut self) {
        if self.jrnl_running {
            return;
        }
        self.jrnl_running = true;
        self.jrnl_stop.clear();
        self.nav_set_now(Page::Jrnl, "» taranıyor", 'i');
        self.lbl_jrnl = (String::new(), 'n');
        self.phase("Journal geçmişi taraması başladı");
        let tx = self.tx.clone();
        let stop = self.jrnl_stop.clone();
        spawn16(move || {
            let prog = |m: &str| tx.send(Msg::Desc(uslice(m, 150)));
            let r = guarded(|| js_core::journal::scan_journal(5, Some(&prog), Some(&stop))).unwrap_or_else(|e| {
                JournalScan {
                    error: format!("Journal tarama hatası: {}", e),
                    ..Default::default()
                }
            });
            tx.send(Msg::Journal(Box::new(r)));
        });
    }

    pub fn start_disk_scan(&mut self) {
        if self.disk_running {
            return;
        }
        self.disk_running = true;
        self.disk_stop.clear();
        self.nav_set_now(Page::Disk, "» başladı", 'i');
        self.ld[Page::Disk.idx()].set_rows(Vec::new());
        self.ld[Page::Disk.idx()].selected.clear();
        self.ld[Page::Disk.idx()].detail.clear();
        self.disk_live.clear();
        self.disk_seen.clear();
        self.disk_ui = crate::app::DiskUi {
            eta_secs: -1.0,
            ..Default::default()
        };
        self.disk_t0 = Some(std::time::Instant::now());
        self.lbl_disk = (String::new(), 'n');
        self.phase("Disk taraması başladı");
        let full = self.disk_full;
        let tx = self.tx.clone();
        let stop = self.disk_stop.clone();
        spawn16(move || {
            let r = guarded(|| {
                let roots = js_core::disk::default_roots(if full { "full" } else { "user" });
                let ptx = tx.clone();
                let progress: js_core::disk::DiskProgress = Box::new(move |st: &DiskStats, cur: &str| {
                    ptx.send(Msg::DiskProgress {
                        txt: format!(
                            "{} dosya  |  {} arşiv açıldı  |  {} bulgu",
                            st.files, st.archives, st.flagged
                        ),
                        cur: cur.to_string(),
                        files: st.files,
                        flagged: st.flagged,
                        archives: st.archives,
                        est_total: st.est_total,
                        eta_secs: st.eta_secs,
                    });
                });
                let mut ds = DiskScanner::new(roots, Some(progress), Some(stop), 0, Vec::new());
                let ftx = tx.clone();
                ds.set_on_found(Box::new(move |r: &ScanResult| {
                    ftx.send(Msg::DiskFound(Box::new(r.clone())));
                }));
                ds.run()
            });
            let d = r.unwrap_or_else(|e| DiskResult {
                error: e,
                stopped: true,
                ..Default::default()
            });
            let rep = guarded(|| js_core::report::build_disk_report(&d)).unwrap_or_default();
            tx.send(Msg::Disk(Box::new((d, rep))));
        });
    }
}
