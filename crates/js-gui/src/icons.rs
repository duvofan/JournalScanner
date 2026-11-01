use crate::model::Page;
use egui::{pos2, Color32, Painter, Pos2, Rect, Shape, Stroke};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    Dash,
    Cube,
    Disk,
    File,
    Play,
    Usb,
    Clock,
    List,
    Cpu,
    Text,
    Globe,
    History,
    Check,
    Shield,
    ShieldCheck,
    Alert,
    Search,
    Folder,
    Copy,
}

pub fn page_icon(p: Page) -> Icon {
    match p {
        Page::Sum => Icon::Dash,
        Page::Mod => Icon::Cube,
        Page::Disk => Icon::Disk,
        Page::Log => Icon::File,
        Page::Client => Icon::Play,
        Page::Dev => Icon::Usb,
        Page::Pf => Icon::Clock,
        Page::Evt => Icon::List,
        Page::Dll => Icon::Cpu,
        Page::Str => Icon::Text,
        Page::Brow => Icon::Globe,
        Page::Jrnl => Icon::History,
    }
}

struct Pen<'a> {
    p: &'a Painter,
    o: Pos2,
    k: f32,
    st: Stroke,
}

impl Pen<'_> {
    fn pt(&self, x: f32, y: f32) -> Pos2 {
        pos2(self.o.x + x * self.k, self.o.y + y * self.k)
    }
    fn line(&self, pts: &[(f32, f32)]) {
        let v: Vec<Pos2> = pts.iter().map(|&(x, y)| self.pt(x, y)).collect();
        self.p.add(Shape::line(v, self.st));
    }
    fn poly(&self, pts: &[(f32, f32)]) {
        let v: Vec<Pos2> = pts.iter().map(|&(x, y)| self.pt(x, y)).collect();
        self.p.add(Shape::closed_line(v, self.st));
    }
    fn rect(&self, x: f32, y: f32, w: f32, h: f32, r: f32) {
        let rc = Rect::from_min_size(self.pt(x, y), egui::vec2(w * self.k, h * self.k));
        self.p.rect_stroke(rc, r * self.k, self.st, egui::StrokeKind::Middle);
    }
    fn circle(&self, x: f32, y: f32, r: f32) {
        self.p.circle_stroke(self.pt(x, y), r * self.k, self.st);
    }
    fn dot(&self, x: f32, y: f32, r: f32) {
        self.p.circle_filled(self.pt(x, y), r * self.k, self.st.color);
    }
    fn arc(&self, x: f32, y: f32, rx: f32, ry: f32, a0: f32, a1: f32) {
        let n = 40;
        let v: Vec<(f32, f32)> = (0..=n)
            .map(|i| {
                let a = (a0 + (a1 - a0) * i as f32 / n as f32).to_radians();
                (x + rx * a.cos(), y + ry * a.sin())
            })
            .collect();
        self.line(&v);
    }
}

pub fn draw(painter: &Painter, rect: Rect, icon: Icon, color: Color32, width: f32) {
    let k = rect.width().min(rect.height()) / 16.0;
    let o = rect.center() - egui::vec2(8.0 * k, 8.0 * k);
    let d = Pen {
        p: painter,
        o,
        k,
        st: Stroke::new(width, color),
    };
    match icon {
        Icon::Dash => {
            d.rect(2.0, 2.0, 4.6, 4.6, 1.2);
            d.rect(9.4, 2.0, 4.6, 7.0, 1.2);
            d.rect(2.0, 9.4, 4.6, 4.6, 1.2);
            d.rect(9.4, 11.4, 4.6, 2.6, 1.2);
        }
        Icon::Cube => {
            d.poly(&[
                (8.0, 1.5),
                (14.0, 4.8),
                (14.0, 11.2),
                (8.0, 14.5),
                (2.0, 11.2),
                (2.0, 4.8),
            ]);
            d.line(&[(2.0, 4.8), (8.0, 8.2), (14.0, 4.8)]);
            d.line(&[(8.0, 8.2), (8.0, 14.5)]);
        }
        Icon::Disk => {
            d.rect(1.8, 9.0, 12.4, 5.0, 1.6);
            d.line(&[(3.4, 9.0), (5.0, 2.6), (11.0, 2.6), (12.6, 9.0)]);
            d.dot(11.2, 11.5, 0.8);
            d.line(&[(4.2, 11.5), (7.2, 11.5)]);
        }
        Icon::File => {
            d.line(&[(9.4, 1.6), (3.6, 1.6), (3.6, 14.4), (12.4, 14.4), (12.4, 4.6)]);
            d.line(&[(9.4, 1.6), (12.4, 4.6), (9.4, 4.6), (9.4, 1.6)]);
            d.line(&[(5.8, 8.0), (10.2, 8.0)]);
            d.line(&[(5.8, 10.8), (10.2, 10.8)]);
        }
        Icon::Play => {
            d.circle(8.0, 8.0, 6.6);
            d.poly(&[(6.4, 5.0), (11.0, 8.0), (6.4, 11.0)]);
        }
        Icon::Usb => {
            d.line(&[(8.0, 14.0), (8.0, 3.4)]);
            d.poly(&[(6.2, 4.6), (8.0, 1.6), (9.8, 4.6)]);
            d.line(&[(8.0, 10.6), (4.4, 8.4), (4.4, 6.6)]);
            d.circle(4.4, 5.6, 1.1);
            d.line(&[(8.0, 8.4), (11.6, 6.8), (11.6, 5.8)]);
            d.rect(10.7, 3.6, 1.8, 1.8, 0.2);
            d.dot(8.0, 14.0, 1.3);
        }
        Icon::Clock => {
            d.circle(8.0, 8.0, 6.6);
            d.line(&[(8.0, 4.2), (8.0, 8.0), (10.8, 9.6)]);
        }
        Icon::List => {
            for y in [4.0, 8.0, 12.0] {
                d.dot(2.8, y, 0.9);
                d.line(&[(6.0, y), (14.0, y)]);
            }
        }
        Icon::Cpu => {
            d.rect(3.6, 3.6, 8.8, 8.8, 1.6);
            d.rect(6.4, 6.4, 3.2, 3.2, 0.6);
            for v in [6.2, 9.8] {
                d.line(&[(v, 1.4), (v, 3.6)]);
                d.line(&[(v, 12.4), (v, 14.6)]);
                d.line(&[(1.4, v), (3.6, v)]);
                d.line(&[(12.4, v), (14.6, v)]);
            }
        }
        Icon::Text => {
            d.line(&[(2.6, 3.4), (13.4, 3.4)]);
            d.line(&[(8.0, 3.4), (8.0, 13.0)]);
            d.line(&[(5.8, 13.0), (10.2, 13.0)]);
        }
        Icon::Globe => {
            d.circle(8.0, 8.0, 6.6);
            d.arc(8.0, 8.0, 2.9, 6.6, 0.0, 360.0);
            d.line(&[(1.4, 8.0), (14.6, 8.0)]);
        }
        Icon::History => {
            d.arc(8.0, 8.0, 6.4, 6.4, 150.0, 440.0);
            d.line(&[(1.2, 3.8), (1.9, 7.6), (5.6, 6.6)]);
            d.line(&[(8.0, 4.6), (8.0, 8.0), (10.4, 9.4)]);
        }
        Icon::Check => {
            d.line(&[(3.0, 8.6), (6.4, 12.0), (13.0, 4.6)]);
        }
        Icon::Shield => {
            d.line(&[
                (8.0, 1.6),
                (13.4, 3.6),
                (13.4, 8.0),
                (11.6, 11.6),
                (8.0, 14.4),
                (4.4, 11.6),
                (2.6, 8.0),
                (2.6, 3.6),
                (8.0, 1.6),
            ]);
        }
        Icon::ShieldCheck => {
            d.line(&[
                (8.0, 1.6),
                (13.4, 3.6),
                (13.4, 8.0),
                (11.6, 11.6),
                (8.0, 14.4),
                (4.4, 11.6),
                (2.6, 8.0),
                (2.6, 3.6),
                (8.0, 1.6),
            ]);
            d.line(&[(5.4, 8.0), (7.2, 9.8), (10.6, 6.2)]);
        }
        Icon::Alert => {
            d.poly(&[(8.0, 2.0), (14.6, 13.4), (1.4, 13.4)]);
            d.line(&[(8.0, 6.4), (8.0, 9.6)]);
            d.dot(8.0, 11.6, 0.8);
        }
        Icon::Search => {
            d.circle(7.0, 7.0, 4.6);
            d.line(&[(10.4, 10.4), (14.0, 14.0)]);
        }
        Icon::Folder => {
            d.line(&[
                (1.8, 4.0),
                (1.8, 13.0),
                (14.2, 13.0),
                (14.2, 5.6),
                (7.4, 5.6),
                (6.2, 3.6),
                (2.4, 3.6),
                (1.8, 4.0),
            ]);
        }
        Icon::Copy => {
            d.rect(5.4, 5.4, 8.4, 8.4, 1.6);
            d.line(&[
                (10.6, 3.6),
                (10.6, 2.4),
                (3.0, 2.4),
                (2.2, 3.2),
                (2.2, 10.6),
                (3.6, 10.6),
            ]);
        }
    }
}

pub fn paint(painter: &Painter, center: Pos2, size: f32, icon: Icon, color: Color32) {
    let r = Rect::from_center_size(center, egui::vec2(size, size));
    draw(painter, r, icon, color, 1.5 * (size / 16.0).powf(0.6));
}
