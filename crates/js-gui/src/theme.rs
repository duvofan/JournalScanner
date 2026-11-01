use egui::{Color32, FontData, FontDefinitions, FontFamily, FontId, Stroke, TextStyle};

pub const BG: Color32 = Color32::from_rgb(0x0b, 0x0d, 0x12);
pub const SIDEBAR: Color32 = Color32::from_rgb(0x0e, 0x11, 0x17);
pub const SURFACE: Color32 = Color32::from_rgb(0x12, 0x15, 0x1c);
pub const SURFACE2: Color32 = Color32::from_rgb(0x17, 0x1b, 0x24);
pub const CONTENT: Color32 = Color32::from_rgb(0x09, 0x0b, 0x0f);
pub const ALT_ROW: Color32 = Color32::from_rgb(0x0f, 0x12, 0x18);
pub const HOVER_ROW: Color32 = Color32::from_rgb(0x17, 0x1b, 0x24);
pub const SELECT: Color32 = Color32::from_rgb(0x19, 0x24, 0x40);
pub const BORDER: Color32 = Color32::from_rgb(0x1e, 0x23, 0x30);
pub const BORDER_STRONG: Color32 = Color32::from_rgb(0x2b, 0x32, 0x44);
pub const ACCENT: Color32 = Color32::from_rgb(0x5b, 0x8c, 0xff);
pub const ACCENT_HI: Color32 = Color32::from_rgb(0x7a, 0xa3, 0xff);
pub const TEXT: Color32 = Color32::from_rgb(0xe8, 0xec, 0xf4);
pub const SUB: Color32 = Color32::from_rgb(0x9a, 0xa4, 0xb5);
pub const MUTED: Color32 = Color32::from_rgb(0x7a, 0x86, 0x9a);
pub const FAINT: Color32 = Color32::from_rgb(0x5f, 0x6b, 0x7e);
pub const BAD: Color32 = Color32::from_rgb(0xff, 0x5a, 0x5f);
pub const WARN: Color32 = Color32::from_rgb(0xff, 0x8a, 0x3d);
pub const SUS: Color32 = Color32::from_rgb(0xf5, 0xc4, 0x51);
pub const OK: Color32 = Color32::from_rgb(0x3d, 0xd6, 0x8c);
pub const INFO: Color32 = Color32::from_rgb(0x7a, 0xa2, 0xf7);

pub fn sb(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("sb".into()))
}

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

fn add_font(fonts: &mut FontDefinitions, key: &str, files: &[&str]) -> bool {
    for f in files {
        if let Some(b) = load_system_font(f) {
            fonts
                .font_data
                .insert(key.into(), std::sync::Arc::new(FontData::from_owned(b)));
            return true;
        }
    }
    false
}

fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let mut prop: Vec<String> = Vec::new();
    if add_font(&mut fonts, "segoeui", &["segoeui.ttf", "SegUIVar.ttf"]) {
        prop.push("segoeui".into());
    }
    let mut semi: Vec<String> = Vec::new();
    if add_font(&mut fonts, "segoesb", &["seguisb.ttf", "segoeuib.ttf"]) {
        semi.push("segoesb".into());
    }
    if add_font(&mut fonts, "seguisym", &["seguisym.ttf"]) {
        prop.push("seguisym".into());
    }
    let mut mono: Vec<String> = Vec::new();
    if add_font(&mut fonts, "mono", &["CascadiaMono.ttf", "consola.ttf"]) {
        mono.push("mono".into());
    }
    let p = fonts.families.entry(FontFamily::Proportional).or_default();
    for (i, k) in prop.iter().enumerate() {
        p.insert(i, k.clone());
    }
    let base = p.clone();
    let m = fonts.families.entry(FontFamily::Monospace).or_default();
    for (i, k) in mono.iter().enumerate() {
        m.insert(i, k.clone());
    }
    if prop.iter().any(|k| k == "seguisym") {
        m.push("seguisym".into());
    }
    let mut sbf = semi;
    sbf.extend(base);
    fonts.families.insert(FontFamily::Name("sb".into()), sbf);
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
    let shadow = egui::epaint::Shadow {
        offset: [0, 8],
        blur: 24,
        spread: 0,
        color: Color32::from_black_alpha(110),
    };
    v.window_shadow = shadow;
    v.popup_shadow = shadow;
    v.selection.bg_fill = SELECT;
    v.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    v.hyperlink_color = ACCENT_HI;
    v.striped = false;
    let r = egui::CornerRadius::same(8);
    v.widgets.noninteractive.bg_fill = SURFACE;
    v.widgets.noninteractive.weak_bg_fill = SURFACE;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    v.widgets.noninteractive.corner_radius = r;
    v.widgets.inactive.bg_fill = SURFACE2;
    v.widgets.inactive.weak_bg_fill = SURFACE2;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, SUB);
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.bg_fill = HOVER_ROW;
    v.widgets.hovered.weak_bg_fill = HOVER_ROW;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, BORDER_STRONG);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, TEXT);
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.bg_fill = SELECT;
    v.widgets.active.weak_bg_fill = SELECT;
    v.widgets.active.bg_stroke = Stroke::new(1.0_f32, ACCENT);
    v.widgets.active.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    v.widgets.active.corner_radius = r;
    v.widgets.open.bg_fill = SURFACE2;
    v.widgets.open.weak_bg_fill = SURFACE2;
    v.widgets.open.bg_stroke = Stroke::new(1.0_f32, BORDER_STRONG);
    v.widgets.open.corner_radius = r;
    v.window_corner_radius = egui::CornerRadius::same(12);
    v.menu_corner_radius = egui::CornerRadius::same(10);
    ctx.set_visuals(v);
    ctx.style_mut(|s| {
        s.text_styles.insert(TextStyle::Body, FontId::proportional(13.5));
        s.text_styles.insert(TextStyle::Button, FontId::proportional(13.5));
        s.text_styles.insert(TextStyle::Small, FontId::proportional(11.5));
        s.text_styles.insert(TextStyle::Heading, sb(20.0));
        s.text_styles.insert(TextStyle::Monospace, FontId::monospace(12.5));
        s.spacing.item_spacing = egui::vec2(8.0, 8.0);
        s.spacing.button_padding = egui::vec2(12.0, 5.0);
        s.spacing.interact_size.y = 28.0;
        s.spacing.menu_margin = egui::Margin::same(6);
        s.spacing.scroll.floating = false;
        s.spacing.scroll.bar_width = 8.0;
    });
}
