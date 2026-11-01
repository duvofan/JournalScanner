use crate::api::{self, goster, utail};
use crate::dash::{detail_view, short_path, St};
use crate::icons::{self, page_icon, Icon};
use crate::model::{ListDetail, Page, TRow, PAGES};
use crate::scans::{Msg, Tx};
use crate::theme::{self, mix, tag_color};
use crate::widgets;
use egui::{Align, Color32, FontId, Layout, RichText, Sense, Stroke, TextStyle, Vec2};
use egui_extras::{Column, TableBuilder};
use js_core::browser::BrowserScan;
use js_core::client::ClientResult;
use js_core::devices::DeviceResult;
use js_core::disk::DiskResult;
use js_core::dllscan::DllScanResult;
use js_core::events::EventResult;
use js_core::jar::ScanResult;
use js_core::journal::JournalScan;
use js_core::logs::LogScan;
use js_core::prefetch::PrefetchResult;
use js_core::util::StopFlag;
use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
pub enum CItem {
    Info,
    Proc(usize),
    Finding(usize, usize),
    Jar(usize, usize),
    Other(usize),
    Inj(usize),
}

#[derive(Clone, Copy, Debug)]
pub enum DItem {
    Group(u8),
    Bt(usize),
    Usb(usize),
    BtRun(usize),
    BtFile(usize),
}

#[derive(Clone, Copy, Default)]
pub struct DiskUi {
    pub files: i64,
    pub est_total: i64,
    pub eta_secs: f64,
    pub flagged: i64,
    pub archives: i64,
}

pub struct App {
    pub tx: Tx,
    pub rx: Receiver<Msg>,
    pub is_admin: bool,
    pub show_about: bool,
    pub icon_small: Option<egui::TextureHandle>,
    pub icon_big: Option<egui::TextureHandle>,
    pub gh_tex: Option<egui::TextureHandle>,
    pub confirm_clear: bool,
    pub learn_n: usize,

    pub page: Page,
    pub ld: Vec<ListDetail>,
    pub sum_lines: Vec<String>,
    pub evt_lines: Vec<String>,
    pub nav_state: Vec<String>,
    pub nav_tag: Vec<char>,

    pub status_title: (String, char),
    pub status_desc: (String, char),
    pub foot: (String, char),
    pub prog: f32,
    pub counts: BTreeMap<String, BTreeMap<char, i32>>,
    pub cnt_vals: [String; 5],
    pub verdict: Option<String>,
    pub mods_dir: String,
    pub disk_full: bool,
    pub lbl_disk: (String, char),
    pub lbl_dll: (String, char),
    pub lbl_str: (String, char),
    pub lbl_brow: (String, char),
    pub lbl_jrnl: (String, char),

    pub has_mod: bool,
    pub mod_err: String,
    pub mod_dirs: Vec<String>,
    pub jar_results: Vec<ScanResult>,
    pub order: Vec<usize>,
    pub event_result: EventResult,
    pub prefetch: PrefetchResult,
    pub has_prefetch: bool,
    pub logs: LogScan,
    pub has_logs: bool,
    pub dev: DeviceResult,
    pub has_dev: bool,
    pub client: ClientResult,
    pub has_client: bool,
    pub disk: DiskResult,
    pub has_disk: bool,
    pub disk_live: Vec<ScanResult>,
    pub disk_seen: std::collections::HashSet<String>,
    pub disk_ui: DiskUi,
    pub disk_t0: Option<Instant>,
    pub dll: DllScanResult,
    pub has_dll: bool,
    pub browser: BrowserScan,
    pub has_browser: bool,
    pub journal: JournalScan,
    pub has_journal: bool,
    pub full_report: String,
    pub disk_full_report: String,
    pub c_items: HashMap<String, CItem>,
    pub d_items: HashMap<String, DItem>,
    pub dev_head: Vec<String>,

    pub mod_running: bool,
    pub log_running: bool,
    pub dev_running: bool,
    pub evt_running: bool,
    pub disk_running: bool,
    pub client_running: bool,
    pub dll_running: bool,
    pub brow_running: bool,
    pub jrnl_running: bool,
    pub disk_stop: Arc<StopFlag>,
    pub client_stop: Arc<StopFlag>,
    pub app_stop: Arc<StopFlag>,
    pub dll_stop: Arc<StopFlag>,
    pub brow_stop: Arc<StopFlag>,
    pub jrnl_stop: Arc<StopFlag>,
    pub shot: crate::shot::Shot,
    pub dev_select: bool,
}

pub enum TAct {
    Select(String),
    Copy(String),
    OpenFolder(String),
    ClearScroll,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::setup(&cc.egui_ctx);
        let (txs, rx) = std::sync::mpsc::channel();
        let md = {
            let base = std::env::var("APPDATA").unwrap_or_else(|_| std::env::var("USERPROFILE").unwrap_or_default());
            format!("{}\\.minecraft\\mods", base)
        };
        let mut app = App {
            tx: Tx::new(txs, cc.egui_ctx.clone()),
            rx,
            is_admin: is_admin(),
            show_about: false,
            icon_small: png_texture(&cc.egui_ctx, "icon_small", include_bytes!("../assets/icon.png"), 52),
            icon_big: png_texture(&cc.egui_ctx, "icon_big", include_bytes!("../assets/icon.png"), 96),
            gh_tex: png_texture(&cc.egui_ctx, "github", include_bytes!("../assets/github.png"), 0),
            confirm_clear: false,
            learn_n: 0,
            page: Page::Sum,
            ld: PAGES.iter().map(|_| ListDetail::default()).collect(),
            sum_lines: Vec::new(),
            evt_lines: Vec::new(),
            nav_state: PAGES.iter().map(|_| String::new()).collect(),
            nav_tag: PAGES.iter().map(|_| 'n').collect(),
            status_title: ("Hazır.".into(), 'x'),
            status_desc: (String::new(), 'n'),
            foot: (String::new(), 'n'),
            prog: 0.0,
            counts: BTreeMap::new(),
            cnt_vals: std::array::from_fn(|_| "0".to_string()),
            verdict: None,
            mods_dir: md,
            disk_full: true,
            lbl_disk: (String::new(), 'n'),
            lbl_dll: (String::new(), 'n'),
            lbl_str: (String::new(), 'n'),
            lbl_brow: (String::new(), 'n'),
            lbl_jrnl: (String::new(), 'n'),
            has_mod: false,
            mod_err: String::new(),
            mod_dirs: Vec::new(),
            jar_results: Vec::new(),
            order: Vec::new(),
            event_result: EventResult::default(),
            prefetch: PrefetchResult::default(),
            has_prefetch: false,
            logs: LogScan::default(),
            has_logs: false,
            dev: DeviceResult::default(),
            has_dev: false,
            client: ClientResult::default(),
            has_client: false,
            disk: DiskResult::default(),
            has_disk: false,
            disk_live: Vec::new(),
            disk_seen: Default::default(),
            disk_ui: DiskUi::default(),
            disk_t0: None,
            dll: DllScanResult::default(),
            has_dll: false,
            browser: BrowserScan::default(),
            has_browser: false,
            journal: JournalScan::default(),
            has_journal: false,
            full_report: String::new(),
            disk_full_report: String::new(),
            c_items: HashMap::new(),
            d_items: HashMap::new(),
            dev_head: Vec::new(),
            mod_running: false,
            log_running: false,
            dev_running: false,
            evt_running: false,
            disk_running: false,
            client_running: false,
            dll_running: false,
            brow_running: false,
            jrnl_running: false,
            disk_stop: Arc::new(StopFlag::new()),
            client_stop: Arc::new(StopFlag::new()),
            app_stop: Arc::new(StopFlag::new()),
            dll_stop: Arc::new(StopFlag::new()),
            brow_stop: Arc::new(StopFlag::new()),
            jrnl_stop: Arc::new(StopFlag::new()),
            shot: crate::shot::Shot::from_env(),
            dev_select: std::env::var_os("JS_GUI_SELECT").is_some(),
        };
        for p in PAGES {
            app.nav_set_now(p, "taranmadı", 'n');
        }
        crate::scans::guard_ui(js_core::learn::learn_load);
        app.learn_refresh();
        if std::env::var_os("JS_GUI_AUTOSTART").is_some() {
            app.start_all();
        }
        if let Some(p) = std::env::var("JS_GUI_PAGE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .and_then(|i| PAGES.get(i))
        {
            app.page = *p;
        }
        app
    }

    pub fn learn_refresh(&mut self) {
        self.learn_n = crate::scans::guard_ui(api::learn_count).unwrap_or(0);
    }

    pub fn set_foot(&mut self, s: impl Into<String>, tag: char) {
        self.foot = (s.into(), tag);
    }

    pub fn copy_text(&mut self, ctx: &egui::Context, s: &str) {
        ctx.copy_text(s.to_string());
        self.set_foot(format!("Panoya kopyalandı: {}", utail(s, 90)), 'x');
    }

    pub fn open_folder(&mut self, p: &str) {
        if p.is_empty() {
            return;
        }
        let outer = p
            .split(" !/ ")
            .next()
            .unwrap_or("")
            .split("  (")
            .next()
            .unwrap_or("")
            .to_string();
        let path = std::path::Path::new(&outer);
        if path.is_file() {
            use std::os::windows::process::CommandExt;
            let _ = std::process::Command::new("explorer.exe")
                .raw_arg(format!("/select,\"{}\"", outer))
                .spawn();
        } else if path.is_dir() {
            let _ = std::process::Command::new("explorer.exe").arg(&outer).spawn();
        } else {
            self.set_foot(
                format!(
                    "Dosya artık yerinde değil (ya da bir dosya yolu değil): {}",
                    utail(&outer, 90)
                ),
                'y',
            );
        }
    }

    fn browse(&mut self) {
        if let Some(p) = rfd::FileDialog::new().set_title("Mods klasörünü seç").pick_folder() {
            self.mods_dir = p.to_string_lossy().into_owned();
        }
    }

    fn save_report(&mut self) {
        if !self.any_scanned() {
            self.set_foot("Kaydedilecek sonuç yok.", 'x');
            return;
        }
        let ad = format!(
            "journalscanner_rapor_{}.html",
            js_core::util::fmt_local(js_core::util::now_epoch(), "%Y%m%d_%H%M")
        );
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(&ad)
            .add_filter("HTML raporu (*.html)", &["html", "htm"])
            .add_filter("CSV tablosu (*.csv)", &["csv"])
            .add_filter("JSON verisi (*.json)", &["json"])
            .add_filter("Metin (*.txt)", &["txt"])
            .save_file()
        else {
            return;
        };
        let mut data = self.full_report.clone();
        if !self.disk_full_report.is_empty() {
            data += &format!("\n\n{}", self.disk_full_report);
        }
        if self.has_dll {
            data += "\n\n";
            for l in crate::pages::str_overview_lines(&self.dll) {
                data += &l;
                data += "\n";
            }
            for f in &self.dll.findings {
                if self.is_memory(f) {
                    data += "\n";
                    for l in &f.detail {
                        data += l;
                        data += "\n";
                    }
                }
            }
            if !self.dll.full_log.is_empty() {
                data += &format!("\n\n{}", self.dll.full_log);
            }
        }
        if self.has_browser {
            data += "\n\n";
            for l in js_core::browser::browser_overview_lines(&self.browser) {
                data += &l;
                data += "\n";
            }
            for h in &self.browser.hits {
                data += "\n";
                for l in js_core::browser::browser_hit_lines(h) {
                    data += &l;
                    data += "\n";
                }
            }
        }
        if self.has_journal {
            data += "\n\n";
            for l in js_core::journal::journal_overview_lines(&self.journal) {
                data += &l;
                data += "\n";
            }
            for h in &self.journal.hits {
                data += "\n";
                for l in js_core::journal::journal_hit_lines(h) {
                    data += &l;
                    data += "\n";
                }
            }
        }
        let bicim = crate::export::Bicim::uzantidan(&path);
        let path = if path.extension().is_none() {
            path.with_extension("html")
        } else {
            path
        };
        let genel_etiket = match self.verdict.as_deref() {
            Some(v) if v.starts_with("KESIN") => 'k',
            Some(v) if v.starts_with("YASAKLI") => 'y',
            Some(v) if v.starts_with("SUPHELI") => 's',
            Some(v) if v.starts_with("TEMIZ") => 't',
            _ => 'n',
        };
        let rapor = crate::export::Rapor {
            surum: env!("CARGO_PKG_VERSION"),
            tarih: js_core::util::fmt_local(js_core::util::now_epoch(), "%d.%m.%Y %H:%M:%S"),
            genel_karar: self.verdict.as_deref().map(js_core::report::goster),
            genel_etiket,
            sayilar: self.cnt_vals.clone(),
            sekmeler: PAGES
                .iter()
                .filter(|p| p.has_list())
                .map(|p| crate::export::Sekme {
                    ad: p.name(),
                    basliklar: p.heads(),
                    satirlar: &self.ld[p.idx()].rows,
                })
                .collect(),
            metin: data,
        };
        let bytes = crate::export::uret(&rapor, bicim);
        let p = path.to_string_lossy().into_owned();
        match std::fs::write(&path, bytes) {
            Ok(()) => self.set_foot(format!("Rapor kaydedildi: {}", p), 'x'),
            Err(_) => self.set_foot(format!("Rapor kaydedilemedi: {}", p), 'k'),
        }
    }

    pub fn is_memory(&self, f: &js_core::dllscan::DllFinding) -> bool {
        js_core::dllscan::dll_finding_is_memory(f)
    }

    fn save_learn_list(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name("yeni_hile_listesi.txt")
            .add_filter("Metin (*.txt)", &["txt"])
            .save_file()
        else {
            return;
        };
        let mut data = String::new();
        for l in crate::scans::guard_ui(js_core::learn::learn_export_lines).unwrap_or_default() {
            data += &l;
            data += "\r\n";
        }
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(data.as_bytes());
        let p = path.to_string_lossy().into_owned();
        if std::fs::write(&path, bytes).is_ok() {
            self.set_foot(
                format!("Yeni hile listesi kaydedildi ({} kayıt): {}", self.learn_n, p),
                'x',
            );
        } else {
            self.set_foot(format!("Liste kaydedilemedi: {}", p), 'k');
        }
    }

    fn clear_learn(&mut self) {
        self.confirm_clear = false;
        if crate::scans::guard_ui(js_core::learn::learn_clear).unwrap_or(false) {
            self.set_foot("Hafıza temizlendi.", 'x');
        } else {
            self.set_foot(format!("Hafıza temizlenemedi: {}", api::learn_path()), 'k');
        }
        self.learn_refresh();
    }

    fn show_page(&mut self, p: Page) {
        self.page = p;
    }

    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        egui::menu::bar(ui, |ui| {
            ui.menu_button("Tarama", |ui| {
                if ui.button("Tüm taramaları başlat").clicked() {
                    self.start_all();
                    ui.close_menu();
                }
                ui.separator();
                for (ad, p) in [
                    ("Mod", Page::Mod),
                    ("Log", Page::Log),
                    ("Aktif Client", Page::Client),
                    ("Bluetooth / USB", Page::Dev),
                    ("Prefetch + Olay Görüntüleyicisi", Page::Pf),
                    ("DLL / Yerel Modül + String Scanner", Page::Dll),
                    ("Disk", Page::Disk),
                    ("Tarayıcı geçmişi", Page::Brow),
                    ("Journal geçmişi", Page::Jrnl),
                ] {
                    if ui.add_enabled(!self.is_running(p), egui::Button::new(ad)).clicked() {
                        self.show_page(p);
                        self.start_page(p);
                        ui.close_menu();
                    }
                }
                ui.separator();
                if ui.button("Mods klasörü seç...").clicked() {
                    ui.close_menu();
                    self.browse();
                }
            });
            ui.menu_button("Dosya", |ui| {
                if ui.button("Raporu dışa aktar...").clicked() {
                    ui.close_menu();
                    self.save_report();
                }
                if ui
                    .button(format!("Yeni hile listesini kaydet ({} kayıt)...", self.learn_n))
                    .clicked()
                {
                    ui.close_menu();
                    self.save_learn_list();
                }
                if ui.button("Hafızayı temizle...").clicked() {
                    ui.close_menu();
                    if self.learn_n == 0 {
                        self.set_foot("Hafıza zaten boş.", 'x');
                    } else {
                        self.confirm_clear = true;
                    }
                }
                ui.separator();
                if ui.button("Çıkış").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("Görünüm", |ui| {
                for p in PAGES {
                    if ui.radio(self.page == p, p.name()).clicked() {
                        self.show_page(p);
                        ui.close_menu();
                    }
                }
            });
            ui.menu_button("Bilgi", |ui| {
                if ui.button("Bilgi").clicked() {
                    self.show_about = true;
                    ui.close_menu();
                }
            });
        });
    }

    fn about_window(&mut self, ctx: &egui::Context) {
        const KISILER: [(&str, &str, &str); 2] = [
            ("Jestron", "Ana geliştirici, fikir", "https://github.com/jesthub25"),
            ("duvo", "Rust portu", "https://github.com/duvofan"),
        ];
        const KAYNAK: &str = "https://github.com/duvofan/JournalScanner";
        let mut kapat = ctx.input(|i| i.key_pressed(egui::Key::Escape));
        egui::Window::new("Bilgi")
            .title_bar(false)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .frame(widgets::dialog_frame())
            .show(ctx, |ui| {
                ui.set_width(400.0);
                ui.spacing_mut().item_spacing = Vec2::new(10.0, 6.0);
                ui.horizontal(|ui| {
                    if let Some(t) = &self.icon_big {
                        ui.add(egui::Image::new(egui::load::SizedTexture::new(t.id(), [48.0, 48.0])));
                    }
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.label(RichText::new("JournalScanner").size(20.0).strong().color(theme::TEXT));
                        ui.label(
                            RichText::new(concat!("v", env!("CARGO_PKG_VERSION")))
                                .monospace()
                                .size(12.5)
                                .color(theme::FAINT),
                        );
                    });
                });
                ui.add_space(8.0);
                widgets::card(12).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new("bilgi_izgara")
                        .num_columns(2)
                        .spacing([18.0, 7.0])
                        .show(ui, |ui| {
                            let anahtar = |ui: &mut egui::Ui, t: &str| {
                                ui.label(RichText::new(t).size(12.5).color(theme::FAINT));
                            };
                            let deger = |ui: &mut egui::Ui, t: &str| {
                                ui.label(RichText::new(t).monospace().size(12.5).color(theme::TEXT));
                            };
                            anahtar(ui, "Sürüm");
                            deger(ui, env!("CARGO_PKG_VERSION"));
                            ui.end_row();
                            anahtar(ui, "Derleme");
                            deger(ui, env!("JS_DERLEME"));
                            ui.end_row();
                            anahtar(ui, "Arayüz");
                            deger(ui, "egui (OpenGL)");
                            ui.end_row();
                            anahtar(ui, "Lisans");
                            deger(ui, "MIT");
                            ui.end_row();
                            anahtar(ui, "Kaynak kod");
                            if ui
                                .link(
                                    RichText::new("github.com/duvofan/JournalScanner")
                                        .monospace()
                                        .size(12.5),
                                )
                                .on_hover_text(KAYNAK)
                                .clicked()
                            {
                                ctx.open_url(egui::OpenUrl::new_tab(KAYNAK));
                            }
                            ui.end_row();
                        });
                });
                ui.add_space(8.0);
                widgets::section_label(ui, "EMEĞİ GEÇENLER");
                for (ad, rol, url) in KISILER {
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(Vec2::splat(32.0), Sense::hover());
                        ui.painter().circle_filled(r.center(), 16.0, theme::SURFACE2);
                        ui.painter().text(
                            r.center(),
                            egui::Align2::CENTER_CENTER,
                            ad.chars().next().unwrap_or('?'),
                            FontId::proportional(14.0),
                            theme::SUB,
                        );
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 0.0;
                            ui.label(RichText::new(ad).strong().color(theme::TEXT));
                            ui.label(RichText::new(rol).size(12.0).color(theme::SUB));
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let tikla = match &self.gh_tex {
                                Some(t) => ui
                                    .add(
                                        egui::ImageButton::new(egui::load::SizedTexture::new(t.id(), [20.0, 20.0]))
                                            .frame(false),
                                    )
                                    .on_hover_text(url)
                                    .clicked(),
                                None => ui.link(url).clicked(),
                            };
                            if tikla {
                                ctx.open_url(egui::OpenUrl::new_tab(url));
                            }
                        });
                    });
                }
                ui.add_space(8.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(ui.available_width(), 30.0),
                    Layout::right_to_left(Align::Center),
                    |ui| {
                        if widgets::ghost_button(ui, "Kapat").clicked() {
                            kapat = true;
                        }
                    },
                );
            });
        if kapat {
            self.show_about = false;
        }
    }

    fn footer(&mut self, ui: &mut egui::Ui) {
        let n = self.running_count();
        let done = n == 0 && self.any_scanned();
        let frac = if n == 0 {
            Some(if done { 1.0 } else { 0.0 })
        } else if n == 1 && self.mod_running {
            Some(self.prog.clamp(0.0, 1.0))
        } else {
            None
        };
        let c = if done { theme::OK } else { theme::ACCENT };
        let bar_w = 140.0;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            let w = (ui.available_width() - bar_w - 16.0).max(80.0);
            ui.allocate_ui_with_layout(Vec2::new(w, 18.0), Layout::left_to_right(Align::Center), |ui| {
                if n > 0 {
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                    widgets::spinner(ui, r.center(), 12.0, theme::ACCENT_HI);
                }
                let (txt, col) = if n >= 2 {
                    (format!("{} tarama sürüyor", n), theme::TEXT)
                } else if n == 0 && !self.foot.0.is_empty() {
                    let fc = match self.foot.1 {
                        'x' | 'n' => theme::SUB,
                        t => tag_color(t),
                    };
                    (self.foot.0.clone(), fc)
                } else {
                    let mut t = self.status_title.0.clone();
                    if !self.status_desc.0.is_empty() {
                        t += &format!("  ·  {}", self.status_desc.0);
                    }
                    let tc = if self.status_title.1 == 'x' {
                        theme::SUB
                    } else {
                        tag_color(self.status_title.1)
                    };
                    (t, tc)
                };
                ui.add(egui::Label::new(RichText::new(txt).size(12.0).color(col)).truncate());
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                widgets::progress_bar(ui, bar_w, 3.0, frac, c);
            });
        });
    }

    fn nav_list(&mut self, ui: &mut egui::Ui) {
        ui.spacing_mut().item_spacing.y = 1.0;
        ui.horizontal(|ui| {
            if let Some(t) = &self.icon_small {
                ui.add(egui::Image::new(egui::load::SizedTexture::new(t.id(), [28.0, 28.0])));
            }
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.label(RichText::new("JournalScanner").font(theme::sb(14.5)).color(theme::TEXT));
                ui.label(
                    RichText::new(concat!("v", env!("CARGO_PKG_VERSION")))
                        .size(11.0)
                        .color(theme::FAINT),
                );
            });
        });
        ui.add_space(14.0);
        widgets::section_label(ui, "TARAMALAR");
        ui.add_space(4.0);
        for p in PAGES {
            let w = ui.available_width();
            let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, 34.0), Sense::click());
            let sel = self.page == p;
            let hv = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.12);
            let sv = ui.ctx().animate_bool_with_time(resp.id.with("s"), sel, 0.15);
            let base = mix(
                mix(theme::SIDEBAR, theme::SURFACE2, hv),
                mix(theme::SIDEBAR, theme::ACCENT, 0.14),
                sv,
            );
            ui.painter().rect_filled(rect, 8.0, base);
            if sv > 0.01 {
                let bar = egui::Rect::from_min_size(
                    rect.left_top() + Vec2::new(0.0, 8.0),
                    Vec2::new(3.0, rect.height() - 16.0),
                );
                ui.painter().rect_filled(bar, 2.0, theme::ACCENT.gamma_multiply(sv));
            }
            let nc = mix(mix(theme::SUB, theme::TEXT, hv), theme::TEXT, sv);
            let ic = mix(mix(theme::MUTED, theme::SUB, hv), theme::ACCENT_HI, sv);
            icons::paint(
                ui.painter(),
                egui::pos2(rect.left() + 22.0, rect.center().y),
                16.0,
                page_icon(p),
                ic,
            );
            let rc = egui::pos2(rect.right() - 16.0, rect.center().y);
            let right_edge = match self.status_of(p) {
                St::Running => {
                    widgets::spinner(ui, rc, 13.0, theme::ACCENT_HI);
                    rc.x - 12.0
                }
                St::Clean => {
                    icons::paint(ui.painter(), rc, 14.0, Icon::Check, theme::OK);
                    rc.x - 12.0
                }
                St::Found(n, t) => {
                    let col = tag_color(t);
                    let mut x = rect.right() - 12.0;
                    if n > 0 {
                        let g = ui
                            .painter()
                            .layout_no_wrap(n.to_string(), FontId::proportional(11.5), col);
                        let pw = (g.size().x + 12.0).max(22.0);
                        let pr = egui::Rect::from_min_size(
                            egui::pos2(rect.right() - 8.0 - pw, rect.center().y - 9.0),
                            Vec2::new(pw, 18.0),
                        );
                        ui.painter().rect_filled(pr, 9.0, mix(base, col, 0.18));
                        ui.painter().galley(
                            egui::pos2(pr.center().x - g.size().x / 2.0, pr.center().y - g.size().y / 2.0),
                            g,
                            col,
                        );
                        x = pr.left() - 6.0;
                    }
                    widgets::dot_at(ui, egui::pos2(x - 3.0, rect.center().y), 3.5, col);
                    x - 10.0
                }
                St::Idle | St::Note(_) => {
                    widgets::dot_at(ui, rc, 2.0, theme::FAINT.gamma_multiply(0.6));
                    rc.x - 8.0
                }
            };
            widgets::text_at(
                ui,
                rect.left() + 40.0,
                rect.center().y,
                right_edge - rect.left() - 40.0,
                p.name(),
                FontId::proportional(13.5),
                nc,
            );
            if resp.clicked() {
                self.show_page(p);
            }
        }
    }

    fn nav_bottom(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.spacing_mut().item_spacing.y = 7.0;
        widgets::section_label(ui, "MODS KLASÖRÜ");
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            let w = ui.available_width() - 38.0 - 16.0;
            ui.add(
                egui::TextEdit::singleline(&mut self.mods_dir)
                    .desired_width(w)
                    .margin(egui::Margin::symmetric(8, 5))
                    .font(FontId::proportional(12.5)),
            );
            if widgets::small_button(ui, "…").on_hover_text("Klasör seç").clicked() {
                self.browse();
            }
        });
        let hepsi = self.running_count() < 9;
        ui.spacing_mut().item_spacing.y = 7.0;
        let start = ui
            .with_layout(Layout::top_down_justified(Align::Center), |ui| {
                ui.add_enabled_ui(hepsi, |ui| {
                    widgets::button_w(
                        ui,
                        Some(Icon::Play),
                        "Tüm taramaları başlat",
                        widgets::Kind::Primary,
                        true,
                    )
                })
                .inner
            })
            .inner;
        if start.clicked() {
            self.start_all();
        }
        let save = ui
            .with_layout(Layout::top_down_justified(Align::Center), |ui| {
                widgets::button_w(ui, Some(Icon::File), "Raporu kaydet", widgets::Kind::Ghost, true)
            })
            .inner;
        if save.clicked() {
            self.save_report();
        }
        if !self.is_admin {
            let r = ui
                .horizontal(|ui| {
                    widgets::dot(ui, theme::SUS);
                    ui.add(
                        egui::Label::new(RichText::new("Yönetici izni yok").size(12.0).color(theme::SUS))
                            .sense(Sense::hover()),
                    )
                })
                .inner;
            r.on_hover_text("Bellek, olay günlüğü ve disk taramaları için yönetici izni gerekir.");
        }
    }

    fn label_tag(&self, p: Page) -> (&str, char) {
        let (s, t) = match p {
            Page::Disk => &self.lbl_disk,
            Page::Dll => &self.lbl_dll,
            Page::Str => &self.lbl_str,
            Page::Brow => &self.lbl_brow,
            Page::Jrnl => &self.lbl_jrnl,
            _ => return ("", 'n'),
        };
        (s.as_str(), *t)
    }

    fn is_empty_view(&self, p: Page) -> bool {
        if self.has_data(p) {
            return false;
        }
        !(matches!(p, Page::Mod | Page::Disk) && self.is_running(p))
    }

    fn scan_controls(&mut self, ui: &mut egui::Ui, p: Page) {
        let run = self.is_running(p);
        let label = if run {
            "Taranıyor…"
        } else if self.has_data(p) {
            "Yeniden tara"
        } else {
            "Tara"
        };
        if ui
            .add_enabled_ui(!run, |ui| {
                widgets::button(ui, Some(Icon::Search), label, widgets::Kind::Primary)
            })
            .inner
            .clicked()
        {
            self.start_page(p);
        }
        if self.has_stop(p)
            && ui
                .add_enabled_ui(run, |ui| widgets::ghost_button(ui, "Durdur"))
                .inner
                .clicked()
        {
            self.stop_page(p);
        }
    }

    fn page_header(&mut self, ui: &mut egui::Ui, p: Page) -> bool {
        let mut copy = false;
        let empty = self.is_empty_view(p);
        let controls = !empty || self.is_running(p);
        ui.horizontal(|ui| {
            widgets::title_icon(ui, page_icon(p));
            ui.label(RichText::new(p.name()).font(theme::sb(21.0)).color(theme::TEXT));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| match p {
                Page::Disk => {
                    self.scan_controls(ui, p);
                    let run = self.disk_running;
                    ui.add_enabled_ui(!run, |ui| {
                        let mut s = if self.disk_full { 0 } else { 1 };
                        if widgets::segmented(ui, &mut s, &["Tüm sürücüler", "Hızlı (kullanıcı klasörleri)"]) {
                            self.disk_full = s == 0;
                        }
                    });
                }
                Page::Sum => {
                    if !empty {
                        copy = widgets::small_button(ui, "Metni kopyala").clicked();
                    }
                }
                Page::Evt => {
                    if controls {
                        self.scan_controls(ui, p);
                    }
                    if !empty {
                        copy = widgets::small_button(ui, "Metni kopyala").clicked();
                    }
                }
                _ => {
                    if controls {
                        self.scan_controls(ui, p);
                    }
                }
            });
        });
        let (txt, tag) = self.label_tag(p);
        if !txt.is_empty() && !(p == Page::Disk && self.disk_running) {
            let c = if tag == 'n' { theme::SUB } else { tag_color(tag) };
            ui.add(egui::Label::new(RichText::new(txt).size(12.5).color(c)));
        }
        copy
    }

    fn empty_state(&mut self, ui: &mut egui::Ui, p: Page) {
        let run = self.is_running(p);
        let h = ui.available_height();
        ui.vertical_centered(|ui| {
            ui.add_space((h * 0.26).max(24.0));
            let (r, _) = ui.allocate_exact_size(Vec2::splat(72.0), Sense::hover());
            ui.painter()
                .circle_filled(r.center(), 36.0, mix(theme::BG, theme::ACCENT, 0.10));
            if run {
                widgets::spinner(ui, r.center(), 28.0, theme::ACCENT_HI);
            } else {
                icons::paint(ui.painter(), r.center(), 30.0, page_icon(p), theme::ACCENT_HI);
            }
            ui.add_space(6.0);
            if run {
                ui.label(RichText::new("Taranıyor…").size(15.0).color(theme::SUB));
            } else {
                ui.label(
                    RichText::new("Bu kategori henüz taranmadı.")
                        .size(15.0)
                        .color(theme::SUB),
                );
                ui.add_space(6.0);
                if widgets::button(ui, Some(Icon::Search), "Tara", widgets::Kind::Primary).clicked() {
                    self.start_page(p);
                }
            }
        });
    }

    fn disk_card(&self, ui: &mut egui::Ui) {
        let st = &self.disk_ui;
        let elapsed = self.disk_t0.map_or(0.0, |t| t.elapsed().as_secs_f64());
        widgets::card(14).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 8.0;
            ui.horizontal(|ui| {
                let head = if st.est_total > 0 {
                    format!("{} / ~{} dosya", fmt_n(st.files), fmt_n(st.est_total))
                } else {
                    format!("{} dosya", fmt_n(st.files))
                };
                ui.label(RichText::new(head).size(15.0).strong().color(theme::TEXT));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if st.eta_secs < 0.0 || st.est_total <= 0 {
                        ui.label(
                            RichText::new("Kalan süre: hesaplanıyor…")
                                .size(12.5)
                                .color(theme::FAINT),
                        );
                    } else {
                        ui.label(
                            RichText::new(fmt_dur(st.eta_secs))
                                .size(13.0)
                                .strong()
                                .color(theme::TEXT),
                        );
                        ui.label(RichText::new("Kalan süre:").size(12.5).color(theme::SUB));
                    }
                });
            });
            let frac = (st.est_total > 0).then(|| (st.files as f32 / st.est_total as f32).min(0.99));
            widgets::progress_bar(ui, ui.available_width(), 6.0, frac, theme::ACCENT);
            let rate = if elapsed > 1.0 { st.files as f64 / elapsed } else { 0.0 };
            ui.label(
                RichText::new(format!(
                    "{} dosya/sn  ·  {} arşiv açıldı  ·  {} bulgu  ·  geçen süre {}",
                    fmt_n(rate as i64),
                    fmt_n(st.archives),
                    fmt_n(st.flagged),
                    fmt_dur(elapsed)
                ))
                .size(12.0)
                .color(theme::SUB),
            );
        });
    }

    fn filter_row(&mut self, ui: &mut egui::Ui, p: Page) {
        let boxes = p.verdict_boxes();
        let l = &mut self.ld[p.idx()];
        let mut apply = false;
        let mut changed = false;
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = Vec2::new(8.0, 8.0);
            let r = ui.add(
                egui::TextEdit::singleline(&mut l.edit)
                    .desired_width(230.0)
                    .margin(egui::Margin::symmetric(10, 6))
                    .hint_text("Ara…"),
            );
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                apply = true;
            }
            let mut c = l.col;
            if widgets::segmented(ui, &mut c, &["Ad", "Karar", "Yol"]) {
                l.col = c;
                apply = true;
            }
            if widgets::small_button(ui, "Ara").clicked() {
                apply = true;
            }
            if (!l.edit.is_empty() || !l.query.is_empty()) && widgets::small_button(ui, "Temizle").clicked() {
                l.edit.clear();
                apply = true;
            }
            if boxes {
                ui.add_space(6.0);
                let names = ["Kesin", "Yasaklı", "Şüpheli", "Temiz"];
                let cols = [theme::BAD, theme::WARN, theme::SUS, theme::OK];
                for k in 0..4 {
                    if widgets::chip(ui, names[k], cols[k], l.verdicts[k]).clicked() {
                        l.verdicts[k] = !l.verdicts[k];
                        changed = true;
                    }
                }
            }
            ui.label(
                RichText::new(format!("{} / {} satır", l.shown.len(), l.rows.len()))
                    .size(12.0)
                    .color(theme::FAINT),
            );
        });
        if apply {
            l.query = l.edit.clone();
            l.default_col = l.col;
        }
        if apply || changed {
            l.refresh();
        }
    }

    fn table(&self, ui: &mut egui::Ui, p: Page) -> Vec<TAct> {
        let l = &self.ld[p.idx()];
        let heads = p.heads();
        let mut acts = Vec::new();
        ui.spacing_mut().item_spacing.x = 0.0;
        let mut tb = TableBuilder::new(ui)
            .id_salt(("tbl", p))
            .striped(false)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::initial(340.0).at_least(80.0).clip(true))
            .column(Column::initial(130.0).at_least(60.0).clip(true))
            .column(Column::remainder().at_least(120.0).clip(true))
            .min_scrolled_height(0.0);
        if l.scroll_to_selected {
            if let Some(k) = l.shown_index_of(&l.selected) {
                tb = tb.scroll_to_row(k, Some(Align::Center));
            }
            acts.push(TAct::ClearScroll);
        }
        tb.header(32.0, |mut h| {
            for t in heads {
                h.col(|ui| {
                    ui.add_space(10.0);
                    ui.label(RichText::new(t).font(theme::sb(11.5)).color(theme::FAINT));
                    let r = ui.max_rect();
                    ui.painter()
                        .hline(r.x_range(), r.bottom(), Stroke::new(1.0_f32, theme::BORDER));
                });
            }
        })
        .body(|body| {
            body.rows(32.0, l.shown.len(), |mut row| {
                let k = row.index();
                let (ri, depth) = l.shown[k];
                let r: &TRow = &l.rows[ri];
                row.set_selected(r.iid == l.selected);
                let col = tag_color(r.tag);
                row.col(|ui| {
                    ui.add_space(10.0 + depth as f32 * 16.0);
                    let tc = match r.tag {
                        'n' => theme::SUB,
                        't' => mix(theme::TEXT, theme::SUB, 0.4),
                        _ => theme::TEXT,
                    };
                    let mut t = RichText::new(&r.text).color(tc);
                    if r.tag == 'g' {
                        t = t.strong();
                    }
                    ui.add(egui::Label::new(t).truncate().selectable(false));
                });
                row.col(|ui| {
                    ui.add_space(6.0);
                    let shown = goster(&r.v1);
                    let badge = matches!(r.tag, 'k' | 'y' | 's' | 't')
                        || (matches!(r.tag, 'i' | 'n') && r.v1.chars().count() <= 24 && !shown.is_empty());
                    if badge {
                        let bc = if r.tag == 'n' { theme::SUB } else { col };
                        widgets::badge(ui, &shown, bc, theme::SURFACE);
                    } else {
                        ui.add(
                            egui::Label::new(RichText::new(shown).color(theme::SUB))
                                .truncate()
                                .selectable(false),
                        );
                    }
                });
                row.col(|ui| {
                    ui.add_space(6.0);
                    let tip = r.v2.clone();
                    let short = short_path(&r.v2);
                    let resp = ui.add(
                        egui::Label::new(RichText::new(short.as_str()).monospace().size(12.0).color(theme::MUTED))
                            .truncate()
                            .selectable(false)
                            .sense(Sense::hover()),
                    );
                    if short != tip {
                        resp.on_hover_text(tip);
                    }
                });
                let resp = row.response();
                if resp.clicked() {
                    acts.push(TAct::Select(r.iid.clone()));
                }
                if resp.double_clicked() {
                    acts.push(TAct::OpenFolder(r.v2.clone()));
                }
                resp.context_menu(|ui| {
                    if ui.button("Değeri / yolu kopyala").clicked() {
                        acts.push(TAct::Select(r.iid.clone()));
                        acts.push(TAct::Copy(r.v2.clone()));
                        ui.close_menu();
                    }
                    if ui.button("Klasörünü aç (dosya seçili)").clicked() {
                        acts.push(TAct::Select(r.iid.clone()));
                        acts.push(TAct::OpenFolder(r.v2.clone()));
                        ui.close_menu();
                    }
                });
            });
        });
        acts
    }

    fn apply_acts(&mut self, ctx: &egui::Context, p: Page, acts: Vec<TAct>) {
        for a in acts {
            match a {
                TAct::Select(iid) => {
                    self.ld[p.idx()].selected = iid.clone();
                    self.on_select(p, &iid);
                }
                TAct::Copy(s) => {
                    if !s.is_empty() {
                        self.copy_text(ctx, &s);
                    }
                }
                TAct::OpenFolder(s) => self.open_folder(&s),
                TAct::ClearScroll => self.ld[p.idx()].scroll_to_selected = false,
            }
        }
    }

    fn list_page(&mut self, ui: &mut egui::Ui, p: Page) {
        let ctx = ui.ctx().clone();
        self.page_header(ui, p);
        if self.is_empty_view(p) {
            self.empty_state(ui, p);
            return;
        }
        if p == Page::Disk && self.disk_running {
            self.disk_card(ui);
        }
        self.filter_row(ui, p);
        let avail = ui.available_height();
        let split = self.ld[p.idx()].split;
        let act = egui::TopBottomPanel::bottom(egui::Id::new(("detail", p)))
            .resizable(true)
            .show_separator_line(false)
            .min_height(90.0)
            .default_height((avail * (1.0 - split)).max(110.0))
            .max_height((avail - 100.0).max(110.0))
            .frame(widgets::card(12).outer_margin(egui::Margin {
                left: 0,
                right: 0,
                top: 10,
                bottom: 0,
            }))
            .show_inside(ui, |ui| {
                let can_open = self.ld[p.idx()].selected_path().contains(":\\");
                detail_view(ui, &self.ld[p.idx()].detail, ("det", p), can_open)
            });
        let act = act.inner;
        if act.copy {
            let t = self.ld[p.idx()].detail.join(
                "
",
            );
            self.copy_text(&ctx, &t);
        }
        if act.open {
            let pth = self.ld[p.idx()].selected_path();
            self.open_folder(&pth);
        }
        let acts = egui::CentralPanel::default()
            .frame(widgets::card(6))
            .show_inside(ui, |ui| self.table(ui, p))
            .inner;
        self.apply_acts(&ctx, p, acts);
        if !ctx.wants_keyboard_input() {
            let (down, up, copy) = ctx.input(|i| {
                (
                    i.key_pressed(egui::Key::ArrowDown),
                    i.key_pressed(egui::Key::ArrowUp),
                    i.events.iter().any(|e| matches!(e, egui::Event::Copy)),
                )
            });
            let l = &self.ld[p.idx()];
            if (down || up) && !l.shown.is_empty() {
                if let Some(cur) = l.shown_index_of(&l.selected) {
                    let nk = if down {
                        (cur + 1).min(l.shown.len() - 1)
                    } else {
                        cur.saturating_sub(1)
                    };
                    if nk != cur {
                        let iid = l.rows[l.shown[nk].0].iid.clone();
                        self.ld[p.idx()].scroll_to_selected = true;
                        self.apply_acts(&ctx, p, vec![TAct::Select(iid)]);
                    }
                } else if let Some(&(ri, _)) = l.shown.first() {
                    let iid = l.rows[ri].iid.clone();
                    self.apply_acts(&ctx, p, vec![TAct::Select(iid)]);
                }
            }
            if copy {
                let s = self.ld[p.idx()].selected_path();
                if !s.is_empty() {
                    self.copy_text(&ctx, &s);
                }
            }
        }
    }

    fn text_page(&mut self, ui: &mut egui::Ui, p: Page) {
        if p == Page::Sum {
            self.dashboard(ui);
            return;
        }
        let ctx = ui.ctx().clone();
        let joined_needed = self.page_header(ui, p);
        if self.is_empty_view(p) {
            self.empty_state(ui, p);
            return;
        }
        ui.add_space(2.0);
        let l2: &[String] = if p == Page::Sum {
            &self.sum_lines
        } else {
            &self.evt_lines
        };
        widgets::card(12).show(ui, |ui| {
            text_view(ui, l2, ("txt", p));
        });
        if joined_needed {
            self.copy_text(&ctx, &l2.join("\n"));
        }
    }
}

fn png_texture(ctx: &egui::Context, ad: &str, png: &[u8], boy: usize) -> Option<egui::TextureHandle> {
    let d = eframe::icon_data::from_png_bytes(png).ok()?;
    let (w, h) = (d.width as usize, d.height as usize);
    let img = if boy > 0 && boy < w && w == h {
        let mut rgba = vec![0u8; boy * boy * 4];
        for y in 0..boy {
            for x in 0..boy {
                let (x0, x1) = (x * w / boy, ((x + 1) * w / boy).max(x * w / boy + 1));
                let (y0, y1) = (y * h / boy, ((y + 1) * h / boy).max(y * h / boy + 1));
                let (mut r, mut g, mut b, mut a, mut n) = (0u32, 0u32, 0u32, 0u32, 0u32);
                for yy in y0..y1 {
                    for xx in x0..x1 {
                        let i = (yy * w + xx) * 4;
                        let al = d.rgba[i + 3] as u32;
                        r += d.rgba[i] as u32 * al;
                        g += d.rgba[i + 1] as u32 * al;
                        b += d.rgba[i + 2] as u32 * al;
                        a += al;
                        n += 1;
                    }
                }
                let o = (y * boy + x) * 4;
                if let (Some(rr), Some(gg), Some(bb)) = (r.checked_div(a), g.checked_div(a), b.checked_div(a)) {
                    rgba[o] = rr as u8;
                    rgba[o + 1] = gg as u8;
                    rgba[o + 2] = bb as u8;
                    rgba[o + 3] = (a / n) as u8;
                }
            }
        }
        egui::ColorImage::from_rgba_unmultiplied([boy, boy], &rgba)
    } else {
        egui::ColorImage::from_rgba_unmultiplied([w, h], &d.rgba)
    };
    Some(ctx.load_texture(ad, img, egui::TextureOptions::LINEAR))
}

pub fn fmt_n(n: i64) -> String {
    let s = n.max(0).to_string();
    let mut o = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            o.push('.');
        }
        o.push(c);
    }
    o
}

pub fn fmt_dur(secs: f64) -> String {
    let s = secs.max(0.0).round() as u64;
    if s < 60 {
        format!("{} sn", s)
    } else if s < 3600 {
        format!("{} dk {} sn", s / 60, s % 60)
    } else {
        format!("{} sa {:02} dk", s / 3600, (s % 3600) / 60)
    }
}

pub fn text_view(ui: &mut egui::Ui, lines: &[String], id: impl std::hash::Hash) {
    let rh = ui.text_style_height(&TextStyle::Monospace) + 3.0;
    egui::ScrollArea::both()
        .id_salt(id)
        .auto_shrink([false, false])
        .show_rows(ui, rh, lines.len(), |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for i in range {
                let ln = &lines[i];
                let (c, bold) = line_style(ln);
                let shown = if ln.is_empty() {
                    " ".to_string()
                } else {
                    ln.replace('\t', "    ")
                };
                let mut t = RichText::new(shown).monospace().color(c);
                if bold {
                    t = t.strong();
                }
                ui.add(egui::Label::new(t).wrap_mode(egui::TextWrapMode::Extend));
            }
        });
}

pub fn line_style(ln: &str) -> (Color32, bool) {
    let f = api::fold(ln);
    let s = f.trim_start_matches(' ');
    let has = |x: &str| f.contains(x);
    if s.starts_with("[KESIN HILE]") || has("GENEL KARAR : KESIN") || has("DISK KARARI : KESIN") {
        (theme::BAD, false)
    } else if s.starts_with("[YASAKLI ISLEV]") || has("GENEL KARAR : YASAKLI") {
        (theme::WARN, false)
    } else if s.starts_with("[SUPHELI]") || has("GENEL KARAR : SUPHELI") {
        (theme::SUS, false)
    } else if s.starts_with("[OK]")
        || s.starts_with("[TEMIZ")
        || has("GENEL KARAR : TEMIZ")
        || has("DISK KARARI : TEMIZ")
    {
        (theme::OK, false)
    } else if s.starts_with(">>") {
        (theme::INFO, false)
    } else if s.starts_with("[ ") || s.starts_with("===") {
        (theme::INFO, true)
    } else if s.starts_with("OLAY 50") {
        (theme::WARN, false)
    } else {
        (theme::TEXT, false)
    }
}

fn is_admin() -> bool {
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_msgs();
        self.shot.tick(ctx);
        if self.dev_select {
            let pi = self.page.idx();
            let l = &self.ld[pi];
            if l.selected.is_empty() {
                if let Some(&(ri, _)) = l.shown.first() {
                    let iid = l.rows[ri].iid.clone();
                    let pg = self.page;
                    self.ld[pi].selected = iid.clone();
                    self.on_select(pg, &iid);
                }
            }
        }
        if ctx.input(|i| i.viewport().close_requested()) {
            for s in [
                &self.disk_stop,
                &self.client_stop,
                &self.dll_stop,
                &self.brow_stop,
                &self.jrnl_stop,
                &self.app_stop,
            ] {
                s.set();
            }
        }
        egui::TopBottomPanel::top("menu")
            .frame(
                egui::Frame::new()
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::symmetric(8, 3)),
            )
            .show(ctx, |ui| self.menu_bar(ui));
        egui::TopBottomPanel::bottom("footer")
            .frame(
                egui::Frame::new()
                    .fill(theme::SIDEBAR)
                    .inner_margin(egui::Margin::symmetric(16, 8)),
            )
            .show(ctx, |ui| self.footer(ui));
        egui::SidePanel::left("nav")
            .resizable(false)
            .exact_width(if ctx.screen_rect().width() < 1100.0 {
                228.0
            } else {
                248.0
            })
            .frame(
                egui::Frame::new()
                    .fill(theme::SIDEBAR)
                    .inner_margin(egui::Margin::symmetric(12, 14)),
            )
            .show(ctx, |ui| {
                egui::TopBottomPanel::bottom("nav_bottom")
                    .frame(egui::Frame::NONE)
                    .show_separator_line(false)
                    .show_inside(ui, |ui| self.nav_bottom(ui));
                egui::CentralPanel::default()
                    .frame(egui::Frame::NONE)
                    .show_inside(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, |ui| self.nav_list(ui));
                    });
            });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::symmetric(18, 14)),
            )
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing.y = 10.0;
                let p = self.page;
                if p.has_list() {
                    self.list_page(ui, p);
                } else {
                    self.text_page(ui, p);
                }
            });
        if self.show_about {
            self.about_window(ctx);
        }
        if self.confirm_clear {
            egui::Window::new("Hafızayı temizle")
                .title_bar(false)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .frame(widgets::dialog_frame())
                .show(ctx, |ui| {
                    ui.set_width(360.0);
                    ui.label(
                        RichText::new("Hafıza temizlensin mi?")
                            .size(16.0)
                            .strong()
                            .color(theme::TEXT),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!(
                            "Hafızadaki {} kayıt silinecek. Önce 'Yeni hile listesini kaydet' ile listeyi kaydedip gönderdiğinizden emin olun.",
                            self.learn_n
                        ))
                        .color(theme::SUB),
                    );
                    ui.add_space(10.0);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::primary_button(ui, "Evet, sil").clicked() {
                            self.clear_learn();
                        }
                        if widgets::ghost_button(ui, "Vazgeç").clicked() {
                            self.confirm_clear = false;
                        }
                    });
                });
        }
        let busy = self.running_count() > 0;
        if busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
    }
}
