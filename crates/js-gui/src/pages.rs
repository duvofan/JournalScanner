use crate::api::{self, basename, goster, rank_verdict, rtail, uslice};
use crate::app::{App, CItem, DItem};
use crate::model::{Page, TRow};
use crate::theme::{rank_tag, verdict_color};
use js_core::jar::ScanResult;
use js_core::report as rep;
use std::collections::BTreeMap;

fn sep(c: char, n: usize) -> String {
    c.to_string().repeat(n)
}

pub fn state_text(ranks: &[i32], clean: &str) -> (String, char) {
    let mut n = 0;
    let mut worst = 0;
    for &r in ranks {
        if r > 0 {
            n += 1;
            worst = worst.max(r);
        }
    }
    if n == 0 {
        (clean.to_string(), 't')
    } else {
        (
            format!("× {} bulgu", n),
            if worst == 3 {
                'k'
            } else if worst == 2 {
                'y'
            } else {
                's'
            },
        )
    }
}

pub fn pf_tag(category: &str) -> char {
    match category {
        "KESIN_HILE" => 'k',
        "YASAKLI_ISLEV" => 'y',
        _ => 's',
    }
}

pub fn dll_overview_lines(d: &js_core::dllscan::DllScanResult) -> Vec<String> {
    let mut l = vec!["DLL / YEREL MODÜL TARAMASI".to_string(), sep('=', 70), String::new()];
    if !d.ran && !d.error.is_empty() {
        l.push(format!("[HATA] {}", d.error));
        if !d.have_tool {
            l.push("Yönetici olarak çalıştırıp tekrar deneyin.".into());
        }
        return l;
    }
    l.extend(d.overview.iter().cloned());
    if !d.error.is_empty() {
        l.push(String::new());
        l.push(format!("[NOT] {}", d.error));
    }
    l
}

pub fn str_overview_lines(d: &js_core::dllscan::DllScanResult) -> Vec<String> {
    let mut l = vec![
        "STRING SCANNER - JAVAW BELLEĞİ".to_string(),
        sep('=', 70),
        String::new(),
    ];
    if !d.ran && !d.error.is_empty() {
        l.push(format!("[HATA] {}", d.error));
        l.push("Yönetici olarak çalıştırıp tekrar deneyin.".into());
        return l;
    }
    if !d.javaw_active && d.javaw_no_access {
        l.push("Minecraft (javaw) çalışıyor ama belleğine erişilemedi.".into());
        l.push("Yönetici olarak çalıştırıp yeniden tarayın.".into());
        return l;
    }
    if !d.javaw_active {
        l.push("Çalışan Minecraft (javaw) bulunamadı. Oyun açıkken yeniden tarayın.".into());
        return l;
    }
    l.extend(d.mem_overview.iter().cloned());
    l.push(String::new());
    l.push("Bulgu yoksa javaw belleğinde hile metni kümesi bulunamadı.".into());
    l
}

impl App {
    pub fn fill(&mut self, p: Page, lines: Vec<String>) {
        match p {
            Page::Sum => self.sum_lines = lines,
            Page::Evt => self.evt_lines = lines,
            _ => self.ld[p.idx()].detail = lines,
        }
    }

    pub fn table_select(&mut self, p: Page, iid: &str) {
        let l = &mut self.ld[p.idx()];
        l.selected = iid.to_string();
        if l.shown_index_of(iid).is_some() {
            l.scroll_to_selected = true;
            self.on_select(p, iid);
        }
    }

    pub fn on_select(&mut self, p: Page, iid: &str) {
        if let Some(lines) = self.detail_lines(p, iid) {
            self.fill(p, lines);
        }
    }

    pub fn set_rows(&mut self, p: Page, rows: Vec<TRow>) {
        self.ld[p.idx()].set_rows(rows);
    }

    pub fn nav_set_now(&mut self, p: Page, text: &str, tag: char) {
        self.nav_state[p.idx()] = text.to_string();
        self.nav_tag[p.idx()] = tag;
    }

    pub fn update_counts(&mut self) {
        let mut tot = [0i32; 3];
        for src in self.counts.values() {
            for (i, k) in ['k', 'y', 's'].iter().enumerate() {
                tot[i] += src.get(k).copied().unwrap_or(0);
            }
        }
        let t = self.counts.get("mod").and_then(|m| m.get(&'t')).copied().unwrap_or(0);
        self.cnt_vals = [
            (tot[0] + tot[1] + tot[2] + t).to_string(),
            tot[0].to_string(),
            tot[1].to_string(),
            tot[2].to_string(),
            t.to_string(),
        ];
    }

    pub fn detail_lines(&self, p: Page, iid: &str) -> Option<Vec<String>> {
        match p {
            Page::Mod => {
                let i: usize = iid.parse().unwrap_or(usize::MAX);
                let r = &self.jar_results[*self.order.get(i)?];
                let mut l = rep::mod_lines(r, "");
                l.extend(mixin_extra(r));
                Some(l)
            }
            Page::Pf => {
                let i: usize = iid.parse().unwrap_or(usize::MAX);
                self.prefetch
                    .findings
                    .get(i)
                    .map(|f| rep::prefetch_finding_lines(f, ""))
            }
            Page::Log => {
                let i: usize = iid.split('.').next().unwrap_or("").parse().unwrap_or(usize::MAX);
                self.logs.results.get(i).map(|r| rep::log_result_lines(r, ""))
            }
            Page::Client => Some(self.client_detail(iid)),
            Page::Dll => Some(
                self.dll
                    .findings
                    .iter()
                    .find(|f| f.id == iid)
                    .map(|f| f.detail.clone())
                    .unwrap_or_else(|| dll_overview_lines(&self.dll)),
            ),
            Page::Str => Some(
                self.dll
                    .findings
                    .iter()
                    .find(|f| f.id == iid)
                    .map(|f| f.detail.clone())
                    .unwrap_or_else(|| str_overview_lines(&self.dll)),
            ),
            Page::Brow => Some(
                self.browser
                    .hits
                    .iter()
                    .find(|h| h.id == iid)
                    .map(js_core::browser::browser_hit_lines)
                    .unwrap_or_else(|| js_core::browser::browser_overview_lines(&self.browser)),
            ),
            Page::Jrnl => Some(
                self.journal
                    .hits
                    .iter()
                    .find(|h| h.id == iid)
                    .map(js_core::journal::journal_hit_lines)
                    .unwrap_or_else(|| js_core::journal::journal_overview_lines(&self.journal)),
            ),
            Page::Dev => self.dev_detail(iid),
            Page::Disk => {
                if let Some(n) = iid.strip_prefix('L') {
                    return n
                        .parse::<usize>()
                        .ok()
                        .and_then(|i| self.disk_live.get(i))
                        .map(|r| rep::mod_lines(r, ""));
                }
                let i: usize = iid.split('.').next().unwrap_or("").parse().unwrap_or(usize::MAX);
                let nres = self.disk.results.len();
                if i < nres {
                    Some(rep::mod_lines(&self.disk.results[i], ""))
                } else {
                    self.disk.text_hits.get(i - nres).map(|h| rep::text_hit_lines(h, ""))
                }
            }
            _ => None,
        }
    }

    fn client_detail(&self, iid: &str) -> Vec<String> {
        let cr = &self.client;
        let Some(ci) = self.c_items.get(iid) else {
            return Vec::new();
        };
        let mut l: Vec<String>;
        match *ci {
            CItem::Proc(mi) => l = js_core::client::client_lines(&cr.minecraft[mi], ""),
            CItem::Finding(mi, fi) => {
                let f = &cr.minecraft[mi].findings[fi];
                l = vec![
                    format!("[{}] {}", goster(&rank_verdict(f.rank)), f.title),
                    format!("  {}", f.detail),
                ];
                if !f.path.is_empty() {
                    l.push(format!("  Yol: {}", f.path));
                }
                if let Some(res) = &f.result {
                    l.push(String::new());
                    l.extend(rep::mod_lines(res, ""));
                }
            }
            CItem::Jar(mi, ji) => {
                let j = &cr.minecraft[mi].jars[ji];
                l = vec![
                    format!("{}  [{}]", j.path, goster(&j.verdict)),
                    format!("  Rol: {}", j.role),
                    "  Kod okundu; hile / yasaklı işlev bulunmadı.".into(),
                ];
            }
            CItem::Other(oi) => {
                let o = &cr.other_java[oi];
                l = vec![
                    format!("[{}] Minecraft dışı Java süreci PID {}", goster(&o.verdict), o.pid),
                    format!("  {}", o.exe),
                    format!("  Giriş: {}", if o.main.is_empty() { "-" } else { &o.main }),
                    format!("  Komut satırı: {}", o.cmdline),
                    String::new(),
                ];
                for h in &o.hits {
                    l.extend(rep::mod_lines(h, ""));
                    l.push(String::new());
                }
            }
            CItem::Inj(ii) => {
                let inj = &cr.injectors[ii];
                l = vec![
                    format!(
                        "[{}] Çalışan program Java'ya (Minecraft) kod enjekte edebiliyor / gizli kod taşıyor",
                        goster(&rank_verdict(inj.rank))
                    ),
                    format!("  PID  : {}", inj.pid),
                    format!("  Dosya: {}", inj.path),
                    format!("  {}", inj.detail),
                    format!("  Kanıt: {}", inj.evidence.join(", ")),
                ];
                if let Some(res) = &inj.result {
                    l.push(String::new());
                    l.extend(rep::mod_lines(res, ""));
                }
            }
            CItem::Info => {
                l = vec!["AKTİF CLIENT".into(), sep('=', 60), String::new()];
                l.extend(js_core::client::active_lines(cr));
            }
        }
        l
    }

    fn dev_detail(&self, iid: &str) -> Option<Vec<String>> {
        let dr = &self.dev;
        let it = self.d_items.get(iid)?;
        let mut notes: Vec<String> = dr.notes.iter().map(|n| format!("  Not: {}", n)).collect();
        notes.extend(dr.errors.iter().map(|e| format!("  Hata: {}", e)));
        let l = match *it {
            DItem::Group(g) => {
                let mut l = self.dev_head.clone();
                let body = match g {
                    1 => js_core::devices::bt_lines(dr, true),
                    2 => js_core::devices::bt_file_lines(dr, true),
                    _ => js_core::devices::usb_lines(dr, true),
                };
                l.extend(body);
                if !notes.is_empty() {
                    l.push(String::new());
                    l.extend(notes);
                }
                l
            }
            DItem::Bt(i) => {
                let one = js_core::devices::DeviceResult {
                    days: dr.days,
                    bluetooth: vec![dr.bluetooth[i].clone()],
                    ..Default::default()
                };
                js_core::devices::bt_lines(&one, false)
            }
            DItem::Usb(i) => {
                let one = js_core::devices::DeviceResult {
                    days: dr.days,
                    usb: vec![dr.usb[i].clone()],
                    ..Default::default()
                };
                js_core::devices::usb_lines(&one, false)
            }
            DItem::BtRun(i) => {
                let r = &dr.bt_file_runs[i];
                vec![
                    "Bluetooth Dosya Aktarımı sihirbazı (fsquirt.exe) çalıştırıldı".into(),
                    format!("  Zaman : {}", api::fmt_dt(Some(r.time))),
                    format!("  Kaynak: {}", r.source),
                    format!("  Kayıt : {}", r.path),
                ]
            }
            DItem::BtFile(i) => {
                let f = &dr.bt_files[i];
                vec![
                    "Bluetooth ile alınan dosya".into(),
                    format!("  Yol   : {}", f.path),
                    format!("  Tarih : {}", api::fmt_dt(Some(f.time))),
                    format!("  Boyut : {} bayt", f.size),
                ]
            }
        };
        Some(l)
    }

    pub fn render_prefetch(&mut self) {
        let mut rows = Vec::new();
        for (i, f) in self.prefetch.findings.iter().enumerate() {
            let tag = pf_tag(&f.category);
            let mut name = f.exe.clone();
            let mut path = String::new();
            if let Some(first) = f.files.first() {
                path = first.split("  ->").next().unwrap_or("").to_string();
                name += &format!("  ›  {}", rtail(&path.replace('\\', "/"), '/'));
            }
            rows.push(TRow::new(i.to_string(), "", name, api::cat_tr(&f.category), path, tag));
        }
        let none = rows.is_empty();
        self.set_rows(Page::Pf, rows);
        self.recount();
        if !none {
            self.table_select(Page::Pf, "0");
        } else {
            let mut l = vec!["PREFETCH (.pf) ANALİZİ".to_string(), sep('=', 60), String::new()];
            l.extend(rep::prefetch_lines(&self.prefetch));
            self.fill(Page::Pf, l);
        }
    }

    pub fn render_logs(&mut self) {
        let mut rows = Vec::new();
        for (i, r) in self.logs.results.iter().enumerate() {
            let tag = rank_tag(r.rank);
            let who = r.info.user.clone().unwrap_or_default();
            let name = format!(
                "{}{}",
                r.name,
                if who.is_empty() {
                    String::new()
                } else {
                    format!("  ({})", who)
                }
            );
            rows.push(TRow::new(
                i.to_string(),
                "",
                name,
                r.verdict.clone(),
                r.file.clone(),
                tag,
            ));
            for (j, s) in r.same_session.iter().enumerate() {
                rows.push(TRow::new(
                    format!("{}.{}", i, j),
                    i.to_string(),
                    format!("└ aynı oturum: {}", basename(s)),
                    r.verdict.clone(),
                    s.clone(),
                    tag,
                ));
            }
        }
        let none = self.logs.results.is_empty();
        self.set_rows(Page::Log, rows);
        self.recount();
        if !none {
            self.table_select(Page::Log, "0");
        } else {
            let mut l = vec![
                "LOG TARAMASI".to_string(),
                format!("Son {} gün", self.logs.days),
                sep('=', 70),
                String::new(),
            ];
            l.extend(rep::log_lines(&self.logs));
            self.fill(Page::Log, l);
        }
    }

    pub fn render_client(&mut self) {
        self.c_items.clear();
        let mut rows = Vec::new();
        let mut cnt: BTreeMap<char, i32> = BTreeMap::from([('k', 0), ('y', 0), ('s', 0)]);
        let cr = &self.client;
        if cr.minecraft.is_empty() {
            rows.push(TRow::new(
                "none",
                "",
                "Şu an çalışan Minecraft yok",
                "-",
                "Oyun açıkken yeniden tarayın.",
                'n',
            ));
            self.c_items.insert("none".into(), CItem::Info);
        }
        for (i, m) in cr.minecraft.iter().enumerate() {
            let pid = format!("p{}", i);
            let ver = if m.mc_version.is_empty() { "?" } else { &m.mc_version };
            let ldr = if m.loader.is_empty() {
                "bilinmeyen yükleyici"
            } else {
                &m.loader
            };
            rows.push(TRow::new(
                pid.clone(),
                "",
                format!("PID {}  -  Minecraft {}  -  {}", m.pid, ver, ldr),
                m.verdict.clone(),
                m.exe.clone(),
                rank_tag(m.rank),
            ));
            self.c_items.insert(pid.clone(), CItem::Proc(i));
            let dash = |s: &str| if s.is_empty() { "-".to_string() } else { s.to_string() };
            let mut info: Vec<(&str, String, String)> = vec![
                ("Oyuncu", dash(&m.player), String::new()),
                (
                    "Sürüm / profil",
                    format!("{}  ({})", dash(&m.mc_version), dash(&m.version_arg)),
                    String::new(),
                ),
                (
                    "Yükleyici",
                    format!(
                        "{}{}",
                        dash(&m.loader),
                        if m.loader_version.is_empty() {
                            String::new()
                        } else {
                            format!("  [{}]", m.loader_version)
                        }
                    ),
                    String::new(),
                ),
                (
                    "Başlatıcı",
                    if m.launcher.is_empty() {
                        "belirlenemedi".into()
                    } else {
                        m.launcher.clone()
                    },
                    m.ancestors.first().map(|a| a.path.clone()).unwrap_or_default(),
                ),
                ("Oyun klasörü", dash(&m.game_dir), m.game_dir.clone()),
                ("Oyun jar'ı", dash(&m.game_jar_state), m.game_jar.clone()),
            ];
            if !m.java_home.is_empty() {
                info.push(("Java (JRE)", m.java_home.clone(), m.java_home.clone()));
            }
            for (j, (k, v, path)) in info.iter().enumerate() {
                let iid = format!("{}.i{}", pid, j);
                rows.push(TRow::new(
                    iid.clone(),
                    pid.clone(),
                    *k,
                    uslice(v, 60),
                    if path.is_empty() { v.clone() } else { path.clone() },
                    'i',
                ));
                self.c_items.insert(iid, CItem::Proc(i));
            }
            let mut fs: Vec<usize> = (0..m.findings.len()).collect();
            fs.sort_by(|&a, &b| m.findings[b].rank.cmp(&m.findings[a].rank));
            for (j, &fi) in fs.iter().enumerate() {
                let f = &m.findings[fi];
                let iid = format!("{}.f{}", pid, j);
                let t = rank_tag(f.rank);
                rows.push(TRow::new(
                    iid.clone(),
                    pid.clone(),
                    f.title.clone(),
                    rank_verdict(f.rank),
                    f.path.clone(),
                    t,
                ));
                self.c_items.insert(iid, CItem::Finding(i, fi));
                *cnt.entry(t).or_insert(0) += 1;
            }
            for (j, jr) in m.jars.iter().enumerate() {
                if jr.rank > 0 {
                    continue;
                }
                let iid = format!("{}.j{}", pid, j);
                rows.push(TRow::new(
                    iid.clone(),
                    pid.clone(),
                    format!("{}: {}", jr.role, basename(&jr.path)),
                    jr.verdict.clone(),
                    jr.path.clone(),
                    't',
                ));
                self.c_items.insert(iid, CItem::Jar(i, j));
            }
        }
        for (i, o) in cr.other_java.iter().enumerate() {
            if o.rank == 0 {
                continue;
            }
            let iid = format!("o{}", i);
            rows.push(TRow::new(
                iid.clone(),
                "",
                format!("Java süreci PID {} (Minecraft dışı)", o.pid),
                o.verdict.clone(),
                o.exe.clone(),
                rank_tag(o.rank),
            ));
            self.c_items.insert(iid, CItem::Other(i));
            *cnt.entry(rank_tag(o.rank)).or_insert(0) += 1;
        }
        for (i, inj) in cr.injectors.iter().enumerate() {
            let iid = format!("x{}", i);
            rows.push(TRow::new(
                iid.clone(),
                "",
                format!("Enjektör / gizli kod çalışıyor: PID {}", inj.pid),
                rank_verdict(inj.rank),
                inj.path.clone(),
                rank_tag(inj.rank),
            ));
            self.c_items.insert(iid, CItem::Inj(i));
            *cnt.entry(rank_tag(inj.rank)).or_insert(0) += 1;
        }
        let first = if self.client.minecraft.is_empty() { "none" } else { "p0" };
        self.counts.insert("client".into(), cnt);
        self.set_rows(Page::Client, rows);
        self.table_select(Page::Client, first);
        self.update_counts();
    }

    pub fn render_dll(&mut self) {
        let d = &self.dll;
        let mut rows = Vec::new();
        let (mut kk, mut ss) = (0, 0);
        let mut first = String::new();
        for f in &d.findings {
            if js_core::dllscan::dll_finding_is_memory(f) {
                continue;
            }
            let loc = if f.path.is_empty() {
                f.r#where.clone()
            } else {
                f.path.clone()
            };
            rows.push(TRow::new(
                f.id.clone(),
                "",
                f.name.clone(),
                f.verdict.clone(),
                loc,
                f.tag,
            ));
            if first.is_empty() {
                first = f.id.clone();
            }
            match f.tag {
                'k' => kk += 1,
                's' => ss += 1,
                _ => {}
            }
        }
        let (ran, err_empty) = (d.ran, d.error.is_empty());
        let none = rows.is_empty();
        let ov = dll_overview_lines(d);
        self.set_rows(Page::Dll, rows);
        if !none {
            self.table_select(Page::Dll, &first);
        } else {
            self.fill(Page::Dll, ov);
        }
        if !ran && !err_empty {
            self.nav_set_now(Page::Dll, "erişim yok", 'n');
        } else if kk > 0 {
            self.nav_set_now(Page::Dll, &format!("× {} kesin", kk), 'k');
        } else if ss > 0 {
            self.nav_set_now(Page::Dll, &format!("! {} şüpheli", ss), 's');
        } else if ran {
            self.nav_set_now(Page::Dll, "√ temiz", 't');
        }
    }

    pub fn render_strings(&mut self) {
        let d = &self.dll;
        let mut rows = Vec::new();
        let (mut kk, mut ss) = (0, 0);
        let mut first = String::new();
        for f in &d.findings {
            if !js_core::dllscan::dll_finding_is_memory(f) {
                continue;
            }
            let loc = if f.path.is_empty() {
                f.r#where.clone()
            } else {
                f.path.clone()
            };
            rows.push(TRow::new(
                f.id.clone(),
                "",
                f.name.clone(),
                f.verdict.clone(),
                loc,
                f.tag,
            ));
            if first.is_empty() {
                first = f.id.clone();
            }
            match f.tag {
                'k' => kk += 1,
                's' => ss += 1,
                _ => {}
            }
        }
        let (ran, err, active, noacc) = (d.ran, d.error.clone(), d.javaw_active, d.javaw_no_access);
        let none = rows.is_empty();
        let ov = str_overview_lines(d);
        self.set_rows(Page::Str, rows);
        if !none {
            self.table_select(Page::Str, &first);
        } else {
            self.fill(Page::Str, ov);
        }
        if !ran && !err.is_empty() {
            self.nav_set_now(Page::Str, "erişim yok", 'n');
        } else if kk > 0 {
            self.nav_set_now(Page::Str, &format!("× {} kesin", kk), 'k');
        } else if ss > 0 {
            self.nav_set_now(Page::Str, &format!("! {} şüpheli", ss), 's');
        } else if ran && !active && noacc {
            self.nav_set_now(Page::Str, "erişim yok (yönetici)", 'n');
        } else if ran && !active {
            self.nav_set_now(Page::Str, "oyun açık değil", 'n');
        } else if ran {
            self.nav_set_now(Page::Str, "√ temiz", 't');
        }
        let (lb, lc): (String, char) = if !ran && !err.is_empty() {
            (format!("String taraması çalışmadı: {}", err), 'k')
        } else if kk > 0 {
            (
                format!("Bitti: javaw belleğinde {} KESİN hile metni kümesi bulundu.", kk),
                'k',
            )
        } else if ss > 0 {
            (
                format!("Bitti: javaw belleğinde {} şüpheli metin kümesi (elle doğrulayın).", ss),
                'n',
            )
        } else if active {
            (
                "Bitti: javaw belleği tarandı - hile metni kümesi bulunamadı.".into(),
                't',
            )
        } else if noacc {
            (
                "javaw çalışıyor ama belleğine erişilemedi - YÖNETİCİ olarak çalıştırın.".into(),
                'k',
            )
        } else {
            (
                "javaw (oyun) açık değil - oyun açıkken taramayı yeniden başlatın.".into(),
                'n',
            )
        };
        self.lbl_str = (lb, lc);
    }

    pub fn render_browser(&mut self) {
        let b = &self.browser;
        let mut rows = Vec::new();
        for h in &b.hits {
            let loc = if h.kind == "indirme" {
                format!(
                    "{}{}",
                    h.file_path,
                    if h.file_exists {
                        ""
                    } else if h.in_recycle {
                        "  (silinmiş - Geri Dönüşüm Kutusu'nda)"
                    } else {
                        "  (cihazda YOK)"
                    }
                )
            } else {
                h.url.clone()
            };
            let name = format!(
                "{}{}",
                if h.kind == "indirme" {
                    "[indirme] "
                } else {
                    "[ziyaret] "
                },
                h.title
            );
            rows.push(TRow::new(h.id.clone(), "", name, h.verdict.clone(), loc, h.tag));
        }
        let first = b.hits.first().map(|h| h.id.clone());
        let (ran, err, kesin, yasakli, supheli, info) = (b.ran, b.error.clone(), b.kesin, b.yasakli, b.supheli, b.info);
        self.set_rows(Page::Brow, rows);
        match first {
            Some(id) => self.table_select(Page::Brow, &id),
            None => {
                let l = js_core::browser::browser_overview_lines(&self.browser);
                self.fill(Page::Brow, l)
            }
        }
        self.scan_nav(Page::Brow, ran, &err, [kesin, yasakli, supheli, info]);
    }

    pub fn render_journal(&mut self) {
        let j = &self.journal;
        let mut rows = Vec::new();
        for h in &j.hits {
            let suffix = if h.exists {
                ""
            } else if h.in_recycle {
                "  (silinmiş - Geri Dönüşüm Kutusu'nda)"
            } else {
                "  (cihazda YOK)"
            };
            rows.push(TRow::new(
                h.id.clone(),
                "",
                format!("[{}] {}", h.action, h.name),
                h.verdict.clone(),
                format!("{}{}", h.path, suffix),
                h.tag,
            ));
        }
        let first = j.hits.first().map(|h| h.id.clone());
        let (ran, err, kesin, yasakli, supheli, info) = (j.ran, j.error.clone(), j.kesin, j.yasakli, j.supheli, j.info);
        self.set_rows(Page::Jrnl, rows);
        match first {
            Some(id) => self.table_select(Page::Jrnl, &id),
            None => {
                let l = js_core::journal::journal_overview_lines(&self.journal);
                self.fill(Page::Jrnl, l)
            }
        }
        self.scan_nav(Page::Jrnl, ran, &err, [kesin, yasakli, supheli, info]);
    }

    fn scan_nav(&mut self, p: Page, ran: bool, err: &str, c: [i32; 4]) {
        let [kesin, yasakli, supheli, info] = c;
        if !ran && !err.is_empty() {
            self.nav_set_now(p, "erişim yok", 'n');
        } else if kesin > 0 {
            self.nav_set_now(p, &format!("× {} kesin", kesin), 'k');
        } else if yasakli > 0 {
            self.nav_set_now(p, &format!("× {} yasaklı", yasakli), 'y');
        } else if supheli > 0 {
            self.nav_set_now(p, &format!("! {} şüpheli", supheli), 's');
        } else if ran {
            let t = if info > 0 {
                format!("√ temiz ({} bilgi)", info)
            } else {
                "√ temiz".to_string()
            };
            self.nav_set_now(p, &t, 't');
        }
    }

    pub fn render_devices(&mut self) {
        self.d_items.clear();
        let dr = &self.dev;
        let days = dr.days;
        self.dev_head = vec![
            "BLUETOOTH / USB".to_string(),
            format!("Son {} gün", days),
            sep('=', 70),
            String::new(),
        ];
        let mut items: Vec<(String, DItem)> = Vec::new();
        let mut rows = Vec::new();
        rows.push(TRow::new(
            "g_bt",
            "",
            format!("1) BLUETOOTH  -  {} aygıt", dr.bluetooth.len()),
            format!("son {} gün", days),
            "",
            'g',
        ));
        items.push(("g_bt".into(), DItem::Group(1)));
        for (i, b) in dr.bluetooth.iter().enumerate() {
            let iid = format!("bt.{}", i);
            let when = b.last_connected.or(b.first_install);
            let desc = format!(
                "{}  |  {}  |  {}{}",
                api::fmt_dt(when),
                b.mac,
                b.r#type,
                if b.category.is_empty() {
                    String::new()
                } else {
                    format!("  |  {}", b.category)
                }
            );
            rows.push(TRow::new(
                iid.clone(),
                "g_bt",
                b.name.clone(),
                if b.new_in_period {
                    "YENİ EŞLEŞTİ"
                } else {
                    "Bağlandı"
                },
                desc,
                'i',
            ));
            items.push((iid, DItem::Bt(i)));
        }
        rows.push(TRow::new(
            "g_bf",
            "",
            format!(
                "   Bluetooth dosya aktarımı  -  {} iz",
                dr.bt_file_runs.len() + dr.bt_files.len()
            ),
            format!("son {} gün", days),
            "",
            'g',
        ));
        items.push(("g_bf".into(), DItem::Group(2)));
        for (i, r) in dr.bt_file_runs.iter().enumerate() {
            let iid = format!("bf.r{}", i);
            rows.push(TRow::new(
                iid.clone(),
                "g_bf",
                "Bluetooth Dosya Aktarımı çalıştırıldı",
                "Çalıştırıldı",
                format!("{}  |  {}", api::fmt_dt(Some(r.time)), r.source),
                's',
            ));
            items.push((iid, DItem::BtRun(i)));
        }
        for (i, f) in dr.bt_files.iter().enumerate() {
            let iid = format!("bf.f{}", i);
            rows.push(TRow::new(
                iid.clone(),
                "g_bf",
                basename(&f.path),
                "Alınan dosya",
                f.path.clone(),
                's',
            ));
            items.push((iid, DItem::BtFile(i)));
        }
        let present = dr.usb.iter().filter(|u| u.present).count();
        rows.push(TRow::new(
            "g_usb",
            "",
            format!("2) USB AYGITLARI  -  {} aygıt ({} şu an takılı)", dr.usb.len(), present),
            format!("son {} gün", days),
            "",
            'g',
        ));
        items.push(("g_usb".into(), DItem::Group(3)));
        for (i, u) in dr.usb.iter().enumerate() {
            let iid = format!("usb.{}", i);
            let state = if u.present {
                "TAKILI"
            } else if u.new_in_period {
                "YENİ TAKILDI"
            } else {
                "Çıkarılmış"
            };
            let last = u.last_arrival.or(u.first_install);
            let desc = format!(
                "{}  |  {}  |  VID {} PID {}",
                api::fmt_dt(last),
                u.functions.join(", "),
                u.vid,
                u.pid
            );
            rows.push(TRow::new(
                iid.clone(),
                "g_usb",
                u.name.clone(),
                state,
                desc,
                if u.present { 'i' } else { 'n' },
            ));
            items.push((iid, DItem::Usb(i)));
        }
        self.d_items = items.into_iter().collect();
        self.set_rows(Page::Dev, rows);
        self.table_select(Page::Dev, "g_bt");
    }

    pub fn render_disk(&mut self, verdict: &str) {
        let shown_verdict = goster(verdict);
        let d = &self.disk;
        self.lbl_disk = (
            format!(
                "{}{} dosya · {} arşiv · {:.0} sn · Karar: {}",
                if d.stopped { "Durduruldu · " } else { "" },
                d.stats.files,
                d.stats.archives,
                d.duration,
                shown_verdict
            ),
            verdict_tag(verdict),
        );
        let mut ranks: Vec<i32> = d.results.iter().map(|r| r.rank).collect();
        ranks.extend(std::iter::repeat_n(1, d.text_hits.len()));
        let (txt, tag) = state_text(&ranks, "√ temiz");
        let mut c: BTreeMap<char, i32> = BTreeMap::from([('k', 0), ('y', 0), ('s', d.text_hits.len() as i32)]);
        for r in &d.results {
            *c.entry(rank_tag(r.rank)).or_insert(0) += 1;
        }
        c.remove(&'t');
        let mut rows = Vec::new();
        for (i, it) in d.results.iter().enumerate() {
            let tag = rank_tag(it.rank);
            let mut txt = short_label(&it.file);
            if it.file.contains("(jar'a paketlenmemiş") {
                txt += "  (açık sınıflar)";
            }
            rows.push(TRow::new(
                i.to_string(),
                "",
                txt,
                it.verdict.clone(),
                it.file.clone(),
                tag,
            ));
            for (j, a) in it.also_at.iter().enumerate() {
                rows.push(TRow::new(
                    format!("{}.{}", i, j),
                    i.to_string(),
                    format!("└ kopya: {}", short_label(a)),
                    it.verdict.clone(),
                    a.clone(),
                    tag,
                ));
            }
        }
        for (k, h) in d.text_hits.iter().enumerate() {
            rows.push(TRow::new(
                (d.results.len() + k).to_string(),
                "",
                short_label(&h.file),
                "SUPHELI",
                h.file.clone(),
                's',
            ));
        }
        let none = rows.is_empty();
        let overview = if none { rep::disk_lines(d) } else { Vec::new() };
        self.nav_set_now(Page::Disk, &txt, tag);
        self.counts.insert("disk".into(), c);
        self.update_counts();
        self.set_rows(Page::Disk, rows);
        if !none {
            self.table_select(Page::Disk, "0");
        } else {
            self.fill(Page::Disk, overview);
        }
    }

    pub fn render_mod(&mut self) {
        let mut order: Vec<usize> = (0..self.jar_results.len()).collect();
        order.sort_by(|&a, &b| {
            let (ra, rb) = (&self.jar_results[a], &self.jar_results[b]);
            if ra.rank != rb.rank {
                return rb.rank.cmp(&ra.rank);
            }
            ra.name.to_lowercase().cmp(&rb.name.to_lowercase())
        });
        self.order = order;
        let mut rows = Vec::new();
        for (i, &ri) in self.order.iter().enumerate() {
            let r: &ScanResult = &self.jar_results[ri];
            let v = if r.official_fabric && r.rank == 0 {
                "Resmî Fabric".to_string()
            } else if r.trusted_infra && r.rank == 0 {
                "Altyapı (Mixin)".to_string()
            } else if r.server_plugin && r.rank == 0 {
                "Sunucu eklentisi".to_string()
            } else {
                r.verdict.clone()
            };
            rows.push(TRow::new(
                i.to_string(),
                "",
                r.name.clone(),
                v,
                if r.file.is_empty() {
                    r.name.clone()
                } else {
                    r.file.clone()
                },
                rank_tag(r.rank),
            ));
        }
        let none = self.order.is_empty();
        self.set_rows(Page::Mod, rows);
        self.recount();
        if !none {
            self.table_select(Page::Mod, "0");
        } else {
            let l = if self.mod_err.is_empty() {
                "Mods klasöründe mod dosyası bulunamadı.".to_string()
            } else {
                self.mod_err.clone()
            };
            self.fill(Page::Mod, vec![l]);
        }
    }

    pub fn render_events(&mut self) {
        let mut ev = vec![
            "OLAY GÖRÜNTÜLEYİCİSİ".to_string(),
            "Microsoft-Windows-Ntfs/Operational  |  Olay 500 / 501  |  son 5 gün".to_string(),
            sep('=', 70),
            String::new(),
        ];
        ev.extend(api::event_lines(&self.event_result));
        self.evt_lines = ev;
    }
}

pub fn verdict_tag(v: &str) -> char {
    let c = verdict_color(v);
    if c == crate::theme::BAD {
        'k'
    } else if c == crate::theme::WARN {
        'y'
    } else if c == crate::theme::SUS {
        's'
    } else {
        't'
    }
}

fn mixin_extra(r: &ScanResult) -> Vec<String> {
    let mut l = Vec::new();
    if r.rank == 0 && !r.mixins.is_empty() {
        l.push(String::new());
        l.push("Mixin listesi:".into());
        for m in &r.mixins {
            l.push(format!("  {} -> {}", m.cls, m.targets.join(", ")));
        }
    }
    l
}

pub fn short_label(label0: &str) -> String {
    let label = label0.split("  (jar'a").next().unwrap_or("");
    let parts: Vec<&str> = label.split(" !/ ").collect();
    let p0 = parts[0];
    let mut first = basename(p0.trim_end_matches(['/', '\\']));
    if first.is_empty() {
        first = p0.to_string();
    }
    if parts.len() == 1 {
        return first;
    }
    let last = parts[parts.len() - 1];
    format!("{}  ›  {}", first, rtail(&last.replace('\\', "/"), '/'))
}
