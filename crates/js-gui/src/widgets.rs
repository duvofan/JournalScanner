use crate::icons::{self, Icon};
use crate::theme::{self, mix};
use egui::{pos2, vec2, Color32, FontId, Margin, Rect, Response, RichText, Sense, Stroke, Ui};

pub fn card(margin: i8) -> egui::Frame {
    egui::Frame::new()
        .fill(theme::SURFACE)
        .stroke(Stroke::new(1.0_f32, theme::BORDER))
        .corner_radius(12.0)
        .inner_margin(Margin::same(margin))
}

pub fn dialog_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(theme::SURFACE)
        .stroke(Stroke::new(1.0_f32, theme::BORDER_STRONG))
        .corner_radius(12.0)
        .inner_margin(Margin::same(20))
}

pub fn section_label(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).font(theme::sb(10.5)).color(theme::FAINT));
}

pub fn dot_at(ui: &Ui, center: egui::Pos2, r: f32, color: Color32) {
    ui.painter().circle_filled(center, r, color);
}

pub fn dot(ui: &mut Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(vec2(8.0, 14.0), Sense::hover());
    dot_at(ui, rect.center(), 3.5, color);
}

pub fn badge(ui: &mut Ui, text: &str, color: Color32, base: Color32) -> Response {
    let font = FontId::proportional(11.5);
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, color);
    let size = vec2(galley.size().x + 14.0, 18.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter().rect_filled(rect, 5.0, mix(base, color, 0.16));
    let pos = pos2(rect.left() + 7.0, rect.center().y - galley.size().y / 2.0);
    ui.painter().galley(pos, galley, color);
    resp
}

pub fn chip(ui: &mut Ui, text: &str, dot_color: Color32, on: bool) -> Response {
    let font = FontId::proportional(12.5);
    let tc = if on { theme::TEXT } else { theme::FAINT };
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, tc);
    let size = vec2(galley.size().x + 32.0, 26.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let hov = resp.hovered();
    let fill = if on {
        theme::SURFACE2
    } else if hov {
        theme::SURFACE
    } else {
        theme::BG
    };
    let stroke = if on { theme::BORDER_STRONG } else { theme::BORDER };
    ui.painter()
        .rect(rect, 13.0, fill, Stroke::new(1.0_f32, stroke), egui::StrokeKind::Inside);
    dot_at(
        ui,
        pos2(rect.left() + 13.0, rect.center().y),
        3.5,
        if on { dot_color } else { theme::FAINT },
    );
    let pos = pos2(rect.left() + 23.0, rect.center().y - galley.size().y / 2.0);
    ui.painter().galley(pos, galley, tc);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

pub fn segmented(ui: &mut Ui, sel: &mut usize, labels: &[&str]) -> bool {
    let font = FontId::proportional(12.5);
    let galleys: Vec<_> = labels
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let c = if i == *sel { theme::TEXT } else { theme::SUB };
            ui.painter().layout_no_wrap((*l).to_string(), font.clone(), c)
        })
        .collect();
    let widths: Vec<f32> = galleys.iter().map(|g| g.size().x + 22.0).collect();
    let total: f32 = widths.iter().sum::<f32>() + 4.0;
    let (rect, _) = ui.allocate_exact_size(vec2(total, 28.0), Sense::hover());
    ui.painter().rect(
        rect,
        8.0,
        theme::BG,
        Stroke::new(1.0_f32, theme::BORDER),
        egui::StrokeKind::Inside,
    );
    let mut x = rect.left() + 2.0;
    let mut changed = false;
    let enabled = ui.is_enabled();
    for (i, g) in galleys.into_iter().enumerate() {
        let seg = Rect::from_min_size(pos2(x, rect.top() + 2.0), vec2(widths[i], 24.0));
        let resp = ui.interact(seg, ui.id().with(("seg", i, labels[0])), Sense::click());
        let active = i == *sel;
        if active {
            ui.painter().rect_filled(seg, 6.0, theme::BORDER_STRONG);
        } else if resp.hovered() && enabled {
            ui.painter().rect_filled(seg, 6.0, theme::SURFACE2);
        }
        let col = if active { theme::TEXT } else { theme::SUB };
        let pos = pos2(seg.center().x - g.size().x / 2.0, seg.center().y - g.size().y / 2.0);
        ui.painter().galley(pos, g, col);
        if resp.clicked() && !active {
            *sel = i;
            changed = true;
        }
        x += widths[i];
    }
    changed
}

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Primary,
    Ghost,
    Small,
}

pub fn button(ui: &mut Ui, icon: Option<Icon>, text: &str, kind: Kind) -> Response {
    button_w(ui, icon, text, kind, false)
}

pub fn button_w(ui: &mut Ui, icon: Option<Icon>, text: &str, kind: Kind, full: bool) -> Response {
    let small = kind == Kind::Small;
    let font = FontId::proportional(if small { 12.0 } else { 13.5 });
    let enabled = ui.is_enabled();
    let probe = ui.painter().layout_no_wrap(text.to_string(), font.clone(), theme::TEXT);
    let isz = if small { 13.0 } else { 15.0 };
    let pad = if small { 10.0 } else { 14.0 };
    let gap = if icon.is_some() && !text.is_empty() { 7.0 } else { 0.0 };
    let iw = if icon.is_some() { isz } else { 0.0 };
    let natural = probe.size().x + iw + gap + pad * 2.0;
    let w = if full { ui.available_width() } else { natural };
    let h = if small { 24.0 } else { 32.0 };
    let (rect, resp) = ui.allocate_exact_size(vec2(w, h), if enabled { Sense::click() } else { Sense::hover() });
    let t = ui
        .ctx()
        .animate_bool_with_time(resp.id, resp.hovered() && enabled, 0.12);
    let (fill, stroke, fg) = match kind {
        Kind::Primary => (
            mix(theme::ACCENT, theme::ACCENT_HI, t),
            Stroke::NONE,
            Color32::from_rgb(0x07, 0x0d, 0x1c),
        ),
        Kind::Ghost => (
            mix(theme::SURFACE, theme::SURFACE2, t),
            Stroke::new(1.0_f32, mix(theme::BORDER_STRONG, theme::FAINT, t)),
            theme::TEXT,
        ),
        Kind::Small => (
            mix(theme::SURFACE2, theme::HOVER_ROW, t),
            Stroke::new(1.0_f32, mix(theme::BORDER, theme::BORDER_STRONG, t)),
            mix(theme::SUB, theme::TEXT, t),
        ),
    };
    let (fill, fg, stroke) = if enabled {
        (fill, fg, stroke)
    } else {
        (
            mix(theme::SURFACE, fill, 0.35),
            mix(theme::SURFACE, fg, 0.4),
            Stroke::new(stroke.width, mix(theme::SURFACE, stroke.color, 0.4)),
        )
    };
    ui.painter().rect(
        rect,
        if small { 6.0 } else { 8.0 },
        fill,
        stroke,
        egui::StrokeKind::Inside,
    );
    let mut x = rect.left() + pad + (w - natural) / 2.0;
    if let Some(ic) = icon {
        icons::paint(ui.painter(), pos2(x + isz / 2.0, rect.center().y), isz, ic, fg);
        x += isz + gap;
    }
    let g = ui.painter().layout_no_wrap(text.to_string(), font, fg);
    ui.painter().galley(pos2(x, rect.center().y - g.size().y / 2.0), g, fg);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

pub fn primary_button(ui: &mut Ui, text: &str) -> Response {
    button(ui, None, text, Kind::Primary)
}

pub fn ghost_button(ui: &mut Ui, text: &str) -> Response {
    button(ui, None, text, Kind::Ghost)
}

pub fn small_button(ui: &mut Ui, text: &str) -> Response {
    button(ui, None, text, Kind::Small)
}

pub fn spinner(ui: &Ui, center: egui::Pos2, size: f32, color: Color32) {
    let r = Rect::from_center_size(center, vec2(size, size));
    egui::Spinner::new().size(size).color(color).paint_at(ui, r);
}

pub fn title_icon(ui: &mut Ui, icon: Icon) {
    let (rect, _) = ui.allocate_exact_size(vec2(32.0, 32.0), Sense::hover());
    ui.painter()
        .rect_filled(rect, 9.0, mix(theme::SURFACE, theme::ACCENT, 0.14));
    icons::paint(ui.painter(), rect.center(), 16.0, icon, theme::ACCENT_HI);
}

pub fn progress_bar(ui: &mut Ui, width: f32, height: f32, frac: Option<f32>, fill: Color32) {
    let (rect, _) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
    let r = height / 2.0;
    ui.painter().rect_filled(rect, r, theme::BORDER);
    match frac {
        Some(f) => {
            let f = f.clamp(0.0, 1.0);
            if f > 0.0 {
                let w = (rect.width() * f).max(height);
                ui.painter()
                    .rect_filled(Rect::from_min_size(rect.min, vec2(w, height)), r, fill);
            }
        }
        None => {
            let t = ui.input(|i| i.time) as f32;
            let seg = rect.width() * 0.28;
            let x = ((t * 0.8).fract()) * (rect.width() + seg) - seg;
            let a = (rect.left() + x).max(rect.left());
            let b = (rect.left() + x + seg).min(rect.right());
            if b > a {
                ui.painter()
                    .rect_filled(Rect::from_min_max(pos2(a, rect.top()), pos2(b, rect.bottom())), r, fill);
            }
        }
    }
}

pub fn text_at(ui: &Ui, left: f32, cy: f32, max_w: f32, text: &str, font: FontId, color: Color32) -> f32 {
    if max_w < 8.0 {
        return 0.0;
    }
    let mut job = egui::text::LayoutJob::simple_singleline(text.to_string(), font, color);
    job.wrap = egui::text::TextWrapping {
        max_width: max_w,
        max_rows: 1,
        break_anywhere: true,
        overflow_character: Some('…'),
    };
    let g = ui.fonts(|f| f.layout_job(job));
    let w = g.size().x;
    ui.painter().galley(pos2(left, cy - g.size().y / 2.0), g, color);
    w
}
