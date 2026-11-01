use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Page {
    Sum,
    Mod,
    Disk,
    Log,
    Client,
    Dev,
    Pf,
    Evt,
    Dll,
    Str,
    Brow,
    Jrnl,
}

pub const PAGES: [Page; 12] = [
    Page::Sum,
    Page::Mod,
    Page::Disk,
    Page::Log,
    Page::Client,
    Page::Dev,
    Page::Pf,
    Page::Evt,
    Page::Dll,
    Page::Str,
    Page::Brow,
    Page::Jrnl,
];

impl Page {
    pub fn idx(self) -> usize {
        self as usize
    }
    pub fn name(self) -> &'static str {
        match self {
            Page::Sum => "Özet",
            Page::Mod => "Mod Taraması",
            Page::Disk => "Disk Taraması",
            Page::Log => "Log Taraması",
            Page::Client => "Aktif Client",
            Page::Dev => "Bluetooth / USB",
            Page::Pf => "Prefetch",
            Page::Evt => "Olay Görüntüleyicisi",
            Page::Dll => "DLL / Yerel Modül",
            Page::Str => "String Scanner",
            Page::Brow => "Tarayıcı Geçmişi",
            Page::Jrnl => "Journal Geçmişi",
        }
    }
    pub fn has_list(self) -> bool {
        !matches!(self, Page::Sum | Page::Evt)
    }
    pub fn heads(self) -> [&'static str; 3] {
        match self {
            Page::Mod => ["Mod dosyası", "Karar", "Konum"],
            Page::Disk => ["Bulunan dosya", "Karar", "Konum"],
            Page::Log => ["Log dosyası", "Karar", "Konum"],
            Page::Client => ["Süreç / bulgu", "Karar / durum", "Ayrıntı / yol"],
            Page::Dev => ["Aygıt", "Durum", "Tarih / ayrıntı"],
            Page::Pf => ["Program / prefetch kaydı", "Karar", "Konum"],
            Page::Dll => ["DLL / yerel modül", "Karar", "Konum / nerede"],
            Page::Str => ["Bellek izi (string kalıntısı)", "Karar", "Nerede (bellek bölgesi)"],
            Page::Brow => ["İndirme / ziyaret", "Karar", "Kaynak / dosya yolu"],
            Page::Jrnl => ["Dosya (eylem)", "Karar", "Konum"],
            _ => ["", "", ""],
        }
    }
    pub fn verdict_boxes(self) -> bool {
        self != Page::Dev
    }
}

#[derive(Clone, Debug, Default)]
pub struct TRow {
    pub iid: String,
    pub parent: String,
    pub text: String,
    pub v1: String,
    pub v2: String,
    pub tag: char,
}

impl TRow {
    pub fn new(
        iid: impl Into<String>,
        parent: impl Into<String>,
        text: impl Into<String>,
        v1: impl Into<String>,
        v2: impl Into<String>,
        tag: char,
    ) -> Self {
        TRow {
            iid: iid.into(),
            parent: parent.into(),
            text: text.into(),
            v1: v1.into(),
            v2: v2.into(),
            tag,
        }
    }
}

pub fn match_expr(value: &str, expr: &str) -> bool {
    let v = value.to_lowercase();
    let e = expr.trim().to_lowercase();
    if e.is_empty() {
        return true;
    }
    if e.contains("||") {
        return e.split("||").any(|p| match_expr(value, p));
    }
    if e.contains("!!") {
        let parts: Vec<&str> = e.split("!!").collect();
        if !match_expr(value, parts[0]) {
            return false;
        }
        for p in &parts[1..] {
            let p = p.trim();
            if !p.is_empty() && v.contains(p) {
                return false;
            }
        }
        return true;
    }
    if e.contains("&&") {
        for p in e.split("&&") {
            let q = p.trim();
            if !q.is_empty() && !v.contains(q) {
                return false;
            }
        }
        return true;
    }
    v.contains(&e)
}

pub struct ListDetail {
    pub rows: Vec<TRow>,
    pub shown: Vec<(usize, usize)>,
    pub query: String,
    pub edit: String,
    pub col: usize,
    pub default_col: usize,
    pub verdicts: [bool; 4],
    pub selected: String,
    pub detail: Vec<String>,
    pub split: f32,
    pub scroll_to_selected: bool,
}

impl Default for ListDetail {
    fn default() -> Self {
        ListDetail {
            rows: Vec::new(),
            shown: Vec::new(),
            query: String::new(),
            edit: String::new(),
            col: 0,
            default_col: 0,
            verdicts: [true; 4],
            selected: String::new(),
            detail: Vec::new(),
            split: 0.58,
            scroll_to_selected: false,
        }
    }
}

impl ListDetail {
    fn row_match(&self, r: &TRow) -> bool {
        let vi = match r.tag {
            'k' => Some(0),
            'y' => Some(1),
            's' => Some(2),
            't' => Some(3),
            _ => None,
        };
        if let Some(vi) = vi {
            if !self.verdicts[vi] {
                return false;
            }
        }
        let q = self.query.trim();
        if q.is_empty() {
            return true;
        }
        let karar = format!("{} {}", r.v1, crate::api::goster(&r.v1));
        let fields = [r.text.as_str(), karar.as_str(), r.v2.as_str()];
        for part in q.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let mut col = self.default_col;
            let mut expr = part;
            if let Some((c, rest)) = part.split_once(':') {
                match c.trim().to_lowercase().as_str() {
                    "ad" => {
                        col = 0;
                        expr = rest;
                    }
                    "karar" => {
                        col = 1;
                        expr = rest;
                    }
                    "yol" => {
                        col = 2;
                        expr = rest;
                    }
                    _ => {}
                }
            }
            if !match_expr(fields[col], expr) {
                return false;
            }
        }
        true
    }

    pub fn refresh(&mut self) {
        let parents: HashMap<&str, &str> = self.rows.iter().map(|r| (r.iid.as_str(), r.parent.as_str())).collect();
        let mut keep: HashSet<&str> = HashSet::new();
        for r in &self.rows {
            if self.row_match(r) {
                keep.insert(r.iid.as_str());
            }
        }
        let initial: Vec<&str> = keep.iter().copied().collect();
        for iid in initial {
            let mut p = parents.get(iid).copied().unwrap_or("");
            let mut guard = 0;
            while !p.is_empty() && guard < 64 {
                keep.insert(p);
                p = parents.get(p).copied().unwrap_or("");
                guard += 1;
            }
        }
        let mut shown = Vec::new();
        for (i, r) in self.rows.iter().enumerate() {
            if !keep.contains(r.iid.as_str()) {
                continue;
            }
            let mut d = 0;
            let mut p = r.parent.as_str();
            while !p.is_empty() && keep.contains(p) && d < 6 {
                d += 1;
                p = parents.get(p).copied().unwrap_or("");
            }
            shown.push((i, d));
        }
        self.shown = shown;
    }

    pub fn set_rows(&mut self, rows: Vec<TRow>) {
        self.rows = rows;
        self.refresh();
    }

    pub fn shown_index_of(&self, iid: &str) -> Option<usize> {
        self.shown.iter().position(|&(i, _)| self.rows[i].iid == iid)
    }

    pub fn selected_path(&self) -> String {
        self.shown_index_of(&self.selected)
            .map(|k| self.rows[self.shown[k].0].v2.clone())
            .unwrap_or_default()
    }
}
