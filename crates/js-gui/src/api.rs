pub fn goster(key: &str) -> String {
    js_core::report::goster(key)
}

pub fn cat_tr(c: &str) -> String {
    js_core::report::cat_tr(c)
}

pub fn rank_verdict(r: i32) -> String {
    js_core::client::rank_verdict(r)
}

pub fn fmt_dt(t: Option<f64>) -> String {
    js_core::util::fmt_dt(t)
}

pub fn event_lines(e: &js_core::events::EventResult) -> Vec<String> {
    js_core::report::event_lines(e)
}

pub fn learn_count() -> usize {
    js_core::learn::learn_count()
}

pub fn learn_path() -> String {
    js_core::learn::learn_path()
}

pub fn basename(p: &str) -> String {
    p.trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_string()
}

pub fn rtail(s: &str, sep: char) -> String {
    s.rsplit(sep).next().unwrap_or("").to_string()
}

pub fn uslice(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

pub fn utail(s: &str, n: usize) -> String {
    let c = s.chars().count();
    s.chars().skip(c.saturating_sub(n)).collect()
}

pub fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'ş' | 'Ş' => 'S',
            'ı' | 'İ' | 'i' => 'I',
            'ğ' | 'Ğ' => 'G',
            'ü' | 'Ü' => 'U',
            'ö' | 'Ö' => 'O',
            'ç' | 'Ç' => 'C',
            c => c.to_ascii_uppercase(),
        })
        .collect()
}
