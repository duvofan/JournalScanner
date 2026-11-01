use eframe::egui;

const BEKLE_KARE: u64 = 40;

pub struct Shot {
    hedef: Option<String>,
    kare: u64,
    istendi: bool,
    en_erken: std::time::Instant,
}

impl Shot {
    pub fn from_env() -> Self {
        let ms = std::env::var("JS_GUI_SHOT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        Shot {
            hedef: std::env::var("JS_GUI_SHOT").ok().filter(|s| !s.is_empty()),
            kare: 0,
            istendi: false,
            en_erken: std::time::Instant::now() + std::time::Duration::from_millis(ms),
        }
    }

    pub fn tick(&mut self, ctx: &egui::Context) {
        let Some(hedef) = self.hedef.clone() else { return };
        self.kare += 1;
        ctx.request_repaint();
        if !self.istendi && self.kare >= BEKLE_KARE && std::time::Instant::now() >= self.en_erken {
            self.istendi = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));
        }
        let img = ctx.input(|i| {
            i.raw.events.iter().find_map(|e| match e {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(img) = img {
            let _ = std::fs::write(&hedef, bmp(&img));
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

fn bmp(img: &egui::ColorImage) -> Vec<u8> {
    let (w, h) = (img.size[0] as u32, img.size[1] as u32);
    let veri = w * h * 4;
    let mut o = Vec::with_capacity(54 + veri as usize);
    o.extend_from_slice(b"BM");
    o.extend_from_slice(&(54 + veri).to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&54u32.to_le_bytes());
    o.extend_from_slice(&40u32.to_le_bytes());
    o.extend_from_slice(&(w as i32).to_le_bytes());
    o.extend_from_slice(&(h as i32).to_le_bytes());
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&32u16.to_le_bytes());
    o.extend_from_slice(&[0u8; 24]);
    for y in (0..h as usize).rev() {
        for p in &img.pixels[y * w as usize..(y + 1) * w as usize] {
            o.extend_from_slice(&[p.b(), p.g(), p.r(), 255]);
        }
    }
    o
}
