use egui::{Color32, FontData, FontDefinitions, FontFamily, FontId, Stroke, TextStyle};

pub const BG: Color32 = Color32::from_rgb(0x0e, 0x0f, 0x12);
pub const SURFACE: Color32 = Color32::from_rgb(0x15, 0x17, 0x1b);
pub const SURFACE2: Color32 = Color32::from_rgb(0x1d, 0x20, 0x26);
pub const CONTENT: Color32 = Color32::from_rgb(0x0b, 0x0c, 0x0e);
pub const ALT_ROW: Color32 = Color32::from_rgb(0x12, 0x14, 0x17);
pub const HOVER_ROW: Color32 = Color32::from_rgb(0x1a, 0x1d, 0x23);
pub const SELECT: Color32 = Color32::from_rgb(0x1b, 0x2a, 0x42);
pub const BORDER: Color32 = Color32::from_rgb(0x25, 0x28, 0x2f);
pub const BORDER_STRONG: Color32 = Color32::from_rgb(0x34, 0x38, 0x42);
pub const ACCENT: Color32 = Color32::from_rgb(0x5b, 0x9c, 0xf6);
pub const TEXT: Color32 = Color32::from_rgb(0xe6, 0xe8, 0xec);
pub const SUB: Color32 = Color32::from_rgb(0x9a, 0xa0, 0xab);
pub const MUTED: Color32 = Color32::from_rgb(0x7d, 0x83, 0x8f);
pub const FAINT: Color32 = Color32::from_rgb(0x62, 0x68, 0x74);
pub const BAD: Color32 = Color32::from_rgb(0xf0, 0x62, 0x6b);
pub const WARN: Color32 = Color32::from_rgb(0xf5, 0x9a, 0x4a);
pub const SUS: Color32 = Color32::from_rgb(0xe5, 0xbe, 0x4f);
pub const OK: Color32 = Color32::from_rgb(0x4c, 0xc3, 0x8a);
pub const INFO: Color32 = Color32::from_rgb(0x7a, 0xa7, 0xd9);

pub fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let f = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t + 0.5) as u8;
    Color32::from_rgb(f(a.r(), b.r()), f(a.g(), b.g()), f(a.b(), b.b()))
}

pub fn tag_color(t: char) -> Color32 {
    match t {
        'k' => BAD,
        'y' => WARN,
        's' => SUS,
        't' => OK,
        'i' | 'g' => INFO,
        'n' => SUB,
        _ => TEXT,
    }
}

pub fn verdict_color(v: &str) -> Color32 {
    match v {
        "KESIN HILE" => BAD,
        "YASAKLI ISLEV" => WARN,
        "SUPHELI" => SUS,
        _ => OK,
    }
}

pub fn rank_tag(r: i32) -> char {
    if r >= 3 {
        'k'
    } else if r == 2 {
        'y'
    } else if r == 1 {
        's'
    } else {
        't'
    }
}

fn load_system_font(name: &str) -> Option<Vec<u8>> {
    let dir = std::env::var_os("WINDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "C:\\Windows".into());
    std::fs::read(dir.join("Fonts").join(name)).ok()
}

fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    if let Some(b) = load_system_font("segoeui.ttf") {
        fonts
            .font_data
            .insert("segoeui".into(), std::sync::Arc::new(FontData::from_owned(b)));
        fonts
            .families
            .entry(FontFamily::Proportional)
            .or_default()
            .insert(0, "segoeui".into());
    }
    if let Some(b) = load_system_font("seguisym.ttf") {
        fonts
            .font_data
            .insert("seguisym".into(), std::sync::Arc::new(FontData::from_owned(b)));
        fonts
            .families
            .entry(FontFamily::Proportional)
            .or_default()
            .push("seguisym".into());
        fonts
            .families
            .entry(FontFamily::Monospace)
            .or_default()
            .push("seguisym".into());
    }
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .push("Hack".into());
    if let Some(b) = load_system_font("consola.ttf") {
        fonts
            .font_data
            .insert("consola".into(), std::sync::Arc::new(FontData::from_owned(b)));
        fonts
            .families
            .entry(FontFamily::Monospace)
            .or_default()
            .insert(0, "consola".into());
    }
    ctx.set_fonts(fonts);
}

pub fn setup(ctx: &egui::Context) {
    setup_fonts(ctx);
    let mut v = egui::Visuals::dark();
    v.override_text_color = None;
    v.panel_fill = BG;
    v.window_fill = SURFACE;
    v.extreme_bg_color = CONTENT;
    v.faint_bg_color = ALT_ROW;
    v.window_stroke = Stroke::new(1.0_f32, BORDER_STRONG);
    v.window_shadow = egui::epaint::Shadow::NONE;
    v.popup_shadow = egui::epaint::Shadow::NONE;
    v.selection.bg_fill = SELECT;
    v.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    v.hyperlink_color = ACCENT;
    v.striped = false;
    let r = egui::CornerRadius::same(6);
    v.widgets.noninteractive.bg_fill = SURFACE;
    v.widgets.noninteractive.weak_bg_fill = SURFACE;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    v.widgets.noninteractive.corner_radius = r;
    v.widgets.inactive.bg_fill = SURFACE2;
    v.widgets.inactive.weak_bg_fill = SURFACE2;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(0x7c, 0x83, 0x8f));
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.bg_fill = HOVER_ROW;
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x26, 0x2a, 0x32);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, BORDER_STRONG);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.bg_fill = SELECT;
    v.widgets.active.weak_bg_fill = Color32::from_rgb(0x2e, 0x33, 0x3d);
    v.widgets.active.bg_stroke = Stroke::new(1.0_f32, ACCENT);
    v.widgets.active.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    v.widgets.active.corner_radius = r;
    v.widgets.open.bg_fill = SURFACE2;
    v.widgets.open.weak_bg_fill = SURFACE2;
    v.widgets.open.bg_stroke = Stroke::new(1.0_f32, BORDER_STRONG);
    v.widgets.open.corner_radius = r;
    v.window_corner_radius = egui::CornerRadius::same(10);
    v.menu_corner_radius = egui::CornerRadius::same(8);
    ctx.set_visuals(v);
    ctx.style_mut(|s| {
        s.text_styles.insert(TextStyle::Body, FontId::proportional(13.5));
        s.text_styles.insert(TextStyle::Button, FontId::proportional(13.5));
        s.text_styles.insert(TextStyle::Small, FontId::proportional(11.5));
        s.text_styles.insert(TextStyle::Heading, FontId::proportional(20.0));
        s.text_styles.insert(TextStyle::Monospace, FontId::monospace(12.5));
        s.spacing.item_spacing = egui::vec2(8.0, 8.0);
        s.spacing.button_padding = egui::vec2(12.0, 5.0);
        s.spacing.interact_size.y = 28.0;
        s.spacing.menu_margin = egui::Margin::same(6);
        s.spacing.scroll.floating = false;
        s.spacing.scroll.bar_width = 8.0;
    });
}
