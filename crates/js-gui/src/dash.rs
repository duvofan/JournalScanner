use crate::api::{basename, fold};
use crate::app::App;
use crate::icons::{self, page_icon, Icon};
use crate::model::{Page, PAGES};
use crate::theme::{self, mix, sb, tag_color};
use crate::widgets::{self, Kind};
use egui::{pos2, vec2, Align, Color32, FontId, Layout, Rect, RichText, Sense, Stroke, Ui};

pub enum St {
    Idle,
    Running,
    Clean,
    Found(i32, char),
    Note(String),
}

struct Top {
    rank: i32,
    page: Page,
    iid: String,
    name: String,
    tag: char,
    reason: String,
}

pub fn short_path(p: &str) -> String {
    let looks_path = p.contains(":\\") || p.starts_with("\\\\") || p.starts_with('/');
    if !looks_path {
        return p.to_string();
    }
    let main = p.split(" !/ ").next().unwrap_or(p);
    let parts: Vec<&str> = main.split(['\\', '/']).filter(|s| !s.is_empty()).collect();
    if parts.len() <= 3 {
        return p.to_string();
    }
    format!("…\\{}\\{}", parts[parts.len() - 2], parts[parts.len() - 1])
}

fn verdict_col(key: &str) -> Color32 {
    let f = fold(key);
    if f.contains("KESIN") {
        theme::BAD
    } else if f.contains("YASAKLI") {
        theme::WARN
    } else if f.contains("SUPHELI") {
        theme::SUS
    } else if f.contains("TEMIZ") {
        theme::OK
    } else {
        theme::INFO
    }
}

fn tag_label(t: char) -> &'static str {
    match t {
        'k' => "Kesin",
        'y' => "Yasaklı",
        _ => "Şüpheli",
    }
}

impl App {
    pub fn status_of(&self, p: Page) -> St {
        if p != Page::Sum && self.is_running(p) {
            return St::Running;
        }
        let raw = self.nav_state[p.idx()].as_str();
        match self.nav_tag[p.idx()] {
            t @ ('k' | 'y' | 's') => {
                let n: String = raw
                    .chars()
                    .skip_while(|c| !c.is_ascii_digit())
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                St::Found(n.parse().unwrap_or(0), t)
            }
            't' => St::Clean,
            'n' if raw != "taranmadı" && !raw.is_empty() => St::Note(raw.to_string()),
            _ => St::Idle,
        }
    }

    fn top_findings(&self) -> (Vec<Top>, usize) {
        let mut v = Vec::new();
        for p in PAGES {
            if !p.has_list() {
                continue;
            }
            for r in &self.ld[p.idx()].rows {
                let rank = match r.tag {
                    'k' => 3,
                    'y' => 2,
                    's' => 1,
                    _ => continue,
                };
                v.push(Top {
                    rank,
                    page: p,
                    iid: r.iid.clone(),
                    name: r.text.clone(),
                    tag: r.tag,
                    reason: short_path(&r.v2),
                });
            }
        }
        v.sort_by_key(|t| std::cmp::Reverse(t.rank));
        let n = v.len();
        v.truncate(8);
        (v, n)
    }

    fn hero(&mut self, ui: &mut Ui) {
        let running = self.running_count();
        let scanned = [
            Page::Mod,
            Page::Log,
            Page::Client,
            Page::Dev,
            Page::Pf,
            Page::Dll,
            Page::Disk,
            Page::Brow,
            Page::Jrnl,
        ]
        .iter()
        .filter(|&&p| self.has_data(p))
        .count();
        let found: i32 = (1..4).map(|i| self.cnt_vals[i].parse::<i32>().unwrap_or(0)).sum();
        let (title, vc, icon) = match self.verdict.as_deref() {
            Some(v) if v.starts_with("KESIN") => ("Kesin hile bulundu", theme::BAD, Icon::Alert),
            Some(v) if v.starts_with("YASAKLI") => ("Yasaklı işlev bulundu", theme::WARN, Icon::Alert),
            Some(v) if v.starts_with("SUPHELI") => ("Şüpheli öğe var", theme::SUS, Icon::Alert),
            Some(_) => ("Temiz", theme::OK, Icon::ShieldCheck),
            None if running > 0 => ("Taranıyor…", theme::ACCENT, Icon::Shield),
            None => ("Henüz tarama yapılmadı", theme::FAINT, Icon::Shield),
        };
        let sub = if self.verdict.is_some() {
            let mut s = format!("{} / 9 kategori tarandı  ·  {} bulgu", scanned, found);
            if running > 0 {
                s += &format!("  ·  {} tarama sürüyor", running);
            }
            s
        } else if running > 0 {
            format!("{} tarama sürüyor, sonuçlar geldikçe burada görünür", running)
        } else {
            "Tüm kategorileri tek tıkla tarayıp genel kararı burada görün".to_string()
        };
        egui::Frame::new()
            .fill(mix(theme::SURFACE, vc, 0.07))
            .stroke(Stroke::new(1.0_f32, mix(theme::BORDER, vc, 0.45)))
            .corner_radius(14.0)
            .inner_margin(egui::Margin::same(20))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 16.0;
                    let (r, _) = ui.allocate_exact_size(vec2(64.0, 64.0), Sense::hover());
                    ui.painter()
                        .circle_filled(r.center(), 32.0, mix(theme::SURFACE, vc, 0.2));
                    if self.verdict.is_none() && running > 0 {
                        widgets::spinner(ui, r.center(), 28.0, vc);
                    } else {
                        icons::paint(ui.painter(), r.center(), 30.0, icon, vc);
                    }
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 3.0;
                        ui.add_space(8.0);
                        ui.label(RichText::new(title).font(sb(24.0)).color(theme::TEXT));
                        ui.label(RichText::new(sub).size(13.0).color(theme::SUB));
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if self.verdict.is_none() && running == 0 {
                            if widgets::button(ui, Some(Icon::Play), "Tüm taramaları başlat", Kind::Primary).clicked()
                            {
                                self.start_all();
                            }
                        } else {
                            let caps = ["Temiz", "Şüpheli", "Yasaklı", "Kesin"];
                            let tones = [theme::OK, theme::SUS, theme::WARN, theme::BAD];
                            for (k, cap) in caps.iter().enumerate() {
                                let v = &self.cnt_vals[4 - k];
                                let zero = v == "0" || v == "...";
                                let col = if zero { theme::FAINT } else { tones[k] };
                                ui.allocate_ui_with_layout(vec2(78.0, 56.0), Layout::top_down(Align::Min), |ui| {
                                    ui.spacing_mut().item_spacing.y = 0.0;
                                    ui.label(RichText::new(v).font(sb(26.0)).color(col));
                                    ui.label(RichText::new(*cap).size(12.0).color(theme::SUB));
                                });
                            }
                        }
                    });
                });
            });
    }

    fn findings_card(&mut self, ui: &mut Ui, jump: &mut Option<(Page, String)>) {
        let (top, total) = self.top_findings();
        widgets::card(14).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 4.0;
            ui.horizontal(|ui| {
                widgets::section_label(ui, "ÖNE ÇIKAN BULGULAR");
                if total > top.len() {
                    ui.label(
                        RichText::new(format!("+{} bulgu daha", total - top.len()))
                            .size(12.0)
                            .color(theme::FAINT),
                    );
                }
            });
            ui.add_space(4.0);
            if top.is_empty() {
                ui.horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(vec2(18.0, 20.0), Sense::hover());
                    icons::paint(ui.painter(), r.center(), 16.0, Icon::Check, theme::OK);
                    ui.label(RichText::new("Şu ana kadar öne çıkan bir bulgu yok.").color(theme::SUB));
                });
                return;
            }
            for t in &top {
                let w = ui.available_width();
                let (rect, resp) = ui.allocate_exact_size(vec2(w, 36.0), Sense::click());
                let h = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.12);
                if h > 0.0 {
                    ui.painter()
                        .rect_filled(rect, 8.0, mix(theme::SURFACE, theme::SURFACE2, h));
                }
                let col = tag_color(t.tag);
                let cy = rect.center().y;
                let bx = rect.left() + 10.0;
                let g = ui
                    .painter()
                    .layout_no_wrap(tag_label(t.tag).to_string(), FontId::proportional(11.5), col);
                let bw = 64.0;
                let br = Rect::from_min_size(pos2(bx, cy - 10.0), vec2(bw, 20.0));
                ui.painter().rect_filled(br, 6.0, mix(theme::SURFACE, col, 0.16));
                ui.painter()
                    .galley(pos2(br.center().x - g.size().x / 2.0, cy - g.size().y / 2.0), g, col);
                let name_x = bx + bw + 14.0;
                let name_w = (w * 0.30).max(120.0);
                widgets::text_at(ui, name_x, cy, name_w, &t.name, FontId::proportional(13.5), theme::TEXT);
                let cat_x = name_x + name_w + 12.0;
                icons::paint(
                    ui.painter(),
                    pos2(cat_x + 7.0, cy),
                    14.0,
                    page_icon(t.page),
                    theme::MUTED,
                );
                let cat_w = 140.0;
                widgets::text_at(
                    ui,
                    cat_x + 20.0,
                    cy,
                    cat_w - 20.0,
                    t.page.name(),
                    FontId::proportional(12.5),
                    theme::SUB,
                );
                let rx = cat_x + cat_w + 8.0;
                widgets::text_at(
                    ui,
                    rx,
                    cy,
                    rect.right() - rx - 12.0,
                    &t.reason,
                    FontId::monospace(12.0),
                    theme::MUTED,
                );
                if resp.clicked() {
                    *jump = Some((t.page, t.iid.clone()));
                }
                resp.on_hover_cursor(egui::CursorIcon::PointingHand);
            }
        });
    }

    fn tiles(&mut self, ui: &mut Ui, jump: &mut Option<(Page, String)>) {
        widgets::section_label(ui, "KATEGORİLER");
        let gap = 10.0;
        let w = ui.available_width();
        let cols = (((w + gap) / (210.0 + gap)).floor() as usize).clamp(1, 6);
        let tw = (w - gap * (cols as f32 - 1.0)) / cols as f32;
        let pages: Vec<Page> = PAGES.iter().copied().filter(|&p| p != Page::Sum).collect();
        for chunk in pages.chunks(cols) {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = gap;
                for &p in chunk {
                    let (rect, resp) = ui.allocate_exact_size(vec2(tw, 64.0), Sense::click());
                    let h = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.12);
                    ui.painter().rect(
                        rect,
                        12.0,
                        mix(theme::SURFACE, theme::SURFACE2, h),
                        Stroke::new(1.0_f32, mix(theme::BORDER, theme::BORDER_STRONG, h)),
                        egui::StrokeKind::Inside,
                    );
                    let st = self.status_of(p);
                    let (col, text) = match &st {
                        St::Idle => (theme::FAINT, "Taranmadı".to_string()),
                        St::Running => (theme::ACCENT_HI, "Taranıyor…".to_string()),
                        St::Clean => (theme::OK, "Temiz".to_string()),
                        St::Found(n, t) => (
                            tag_color(*t),
                            if *n > 0 {
                                format!("{} bulgu", n)
                            } else {
                                "Bulgu var".to_string()
                            },
                        ),
                        St::Note(s) => (theme::MUTED, s.clone()),
                    };
                    let ib = Rect::from_min_size(rect.left_top() + vec2(14.0, 15.0), vec2(34.0, 34.0));
                    ui.painter().rect_filled(ib, 10.0, mix(theme::BG, col, 0.14));
                    let ic = if matches!(st, St::Idle | St::Note(_)) {
                        theme::SUB
                    } else {
                        col
                    };
                    icons::paint(ui.painter(), ib.center(), 16.0, page_icon(p), ic);
                    let tx = rect.left() + 60.0;
                    let mw = rect.right() - tx - 30.0;
                    widgets::text_at(
                        ui,
                        tx,
                        rect.top() + 23.0,
                        mw,
                        p.name(),
                        FontId::proportional(13.5),
                        theme::TEXT,
                    );
                    widgets::text_at(ui, tx, rect.top() + 43.0, mw, &text, FontId::proportional(12.0), col);
                    if matches!(st, St::Running) {
                        widgets::spinner(ui, pos2(rect.right() - 20.0, rect.center().y), 14.0, theme::ACCENT_HI);
                    }
                    if resp.clicked() {
                        *jump = Some((p, String::new()));
                    }
                    resp.on_hover_cursor(egui::CursorIcon::PointingHand);
                }
            });
        }
    }

    pub fn dashboard(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        let mut jump: Option<(Page, String)> = None;
        egui::ScrollArea::vertical()
            .id_salt("dash")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 14.0;
                ui.add_space(2.0);
                self.hero(ui);
                if self.any_scanned() {
                    self.findings_card(ui, &mut jump);
                }
                self.tiles(ui, &mut jump);
                if !self.sum_lines.is_empty() {
                    let mut copy = false;
                    egui::CollapsingHeader::new(RichText::new("Tam raporu göster").color(theme::SUB))
                        .id_salt("tam_rapor")
                        .show(ui, |ui| {
                            copy = widgets::button(ui, Some(Icon::Copy), "Metni kopyala", Kind::Small).clicked();
                            widgets::card(12).show(ui, |ui| {
                                ui.allocate_ui(vec2(ui.available_width(), 360.0), |ui| {
                                    crate::app::text_view(ui, &self.sum_lines, "sum_txt");
                                });
                            });
                        });
                    if copy {
                        let t = self.sum_lines.join("\n");
                        self.copy_text(&ctx, &t);
                    }
                }
                ui.add_space(8.0);
            });
        if let Some((p, iid)) = jump {
            self.page = p;
            if !iid.is_empty() {
                self.table_select(p, &iid);
            }
        }
    }
}

struct Parsed {
    head: Option<(String, String)>,
    kv: Vec<(String, String)>,
    bullets: Vec<(String, Vec<String>)>,
    raw: Vec<String>,
}

fn kv_of(line: &str) -> Option<(String, String)> {
    let ind = line.len() - line.trim_start().len();
    let t = line.trim();
    if ind >= 5 || t.starts_with(">>") || t.starts_with('-') || t.starts_with('[') {
        return None;
    }
    let i = t.find(" : ")?;
    let k = t[..i].trim();
    if k.is_empty() || k.chars().count() > 20 || k.contains(':') {
        return None;
    }
    Some((k.to_string(), t[i + 3..].trim().to_string()))
}

fn parse(lines: &[String]) -> Parsed {
    let mut p = Parsed {
        head: None,
        kv: Vec::new(),
        bullets: Vec::new(),
        raw: Vec::new(),
    };
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if t.is_empty() {
            continue;
        }
        if i == 0 && t.starts_with('[') {
            if let Some(e) = t.find(']') {
                p.head = Some((t[1..e].to_string(), t[e + 1..].trim().to_string()));
                continue;
            }
        }
        let ind = l.len() - l.trim_start().len();
        if let Some(rest) = t.strip_prefix(">>") {
            p.bullets.push((rest.trim().to_string(), Vec::new()));
        } else if let Some(kv) = kv_of(l) {
            p.kv.push(kv);
        } else if (ind >= 5 || t.starts_with('-')) && !p.bullets.is_empty() {
            if let Some(b) = p.bullets.last_mut() {
                b.1.push(t.to_string());
            }
        } else {
            p.raw.push(l.replace('\t', "    "));
        }
    }
    p
}

pub struct DetailAct {
    pub open: bool,
    pub copy: bool,
}

pub fn detail_view(ui: &mut Ui, lines: &[String], id: impl std::hash::Hash + Copy, can_open: bool) -> DetailAct {
    let p = parse(lines);
    let mut act = DetailAct {
        open: false,
        copy: false,
    };
    let structured = p.head.is_some() || !p.kv.is_empty() || !p.bullets.is_empty();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        match &p.head {
            Some((v, name)) => {
                let c = verdict_col(v);
                widgets::badge(ui, v, c, theme::SURFACE);
                let n = if name.contains(['\\', '/']) {
                    basename(name)
                } else {
                    name.clone()
                };
                ui.add(egui::Label::new(RichText::new(n).font(sb(15.0)).color(theme::TEXT)).truncate());
            }
            None => widgets::section_label(ui, "KANIT / AYRINTI"),
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if widgets::button(ui, Some(Icon::Copy), "Kopyala", Kind::Small)
                .on_hover_text("Ayrıntı metnini panoya kopyala")
                .clicked()
            {
                act.copy = true;
            }
            if can_open
                && widgets::button(ui, Some(Icon::Folder), "Klasörü aç", Kind::Small)
                    .on_hover_text("Dosyayı Gezgin'de göster")
                    .clicked()
            {
                act.open = true;
            }
        });
    });
    ui.add_space(4.0);
    if !structured {
        crate::app::text_view(ui, lines, (id, "raw"));
        return act;
    }
    let dot_col = p.head.as_ref().map_or(theme::INFO, |(v, _)| verdict_col(v));
    egui::ScrollArea::vertical()
        .id_salt((id, "card"))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            if !p.kv.is_empty() {
                egui::Grid::new((id, "kv"))
                    .num_columns(2)
                    .spacing([16.0, 5.0])
                    .min_row_height(22.0)
                    .show(ui, |ui| {
                        for (k, v) in &p.kv {
                            ui.label(RichText::new(k).size(12.5).color(theme::FAINT));
                            let mono = matches!(k.as_str(), "Yol" | "SHA-256" | "Konum");
                            let t = if mono {
                                RichText::new(v).monospace().size(12.0).color(theme::TEXT)
                            } else {
                                RichText::new(v).size(13.0).color(theme::TEXT)
                            };
                            ui.add(egui::Label::new(t).wrap());
                            ui.end_row();
                        }
                    });
            }
            for (txt, subs) in &p.bullets {
                ui.add_space(2.0);
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    let (r, _) = ui.allocate_exact_size(vec2(8.0, 18.0), Sense::hover());
                    ui.painter().circle_filled(r.center(), 3.5, dot_col);
                    ui.add(egui::Label::new(RichText::new(txt).size(13.5).color(theme::TEXT)).wrap());
                });
                for s in subs {
                    ui.horizontal_top(|ui| {
                        ui.add_space(20.0);
                        ui.add(egui::Label::new(RichText::new(s).monospace().size(12.0).color(theme::MUTED)).wrap());
                    });
                }
            }
            if !p.raw.is_empty() {
                ui.add_space(4.0);
                egui::CollapsingHeader::new(RichText::new("Teknik ayrıntı").size(12.5).color(theme::SUB))
                    .id_salt((id, "tech"))
                    .show(ui, |ui| {
                        for l in &p.raw {
                            ui.add(
                                egui::Label::new(RichText::new(l).monospace().size(12.0).color(theme::MUTED))
                                    .wrap_mode(egui::TextWrapMode::Extend),
                            );
                        }
                    });
            }
        });
    act
}
