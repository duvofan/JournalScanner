use crate::model::TRow;

pub struct Sekme<'a> {
    pub ad: &'static str,
    pub basliklar: [&'static str; 3],
    pub satirlar: &'a [TRow],
}

pub struct Rapor<'a> {
    pub surum: &'a str,
    pub tarih: String,
    pub genel_karar: Option<String>,
    pub genel_etiket: char,
    pub sayilar: [String; 5],
    pub sekmeler: Vec<Sekme<'a>>,
    pub metin: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bicim {
    Html,
    Csv,
    Json,
    Txt,
}

impl Bicim {
    pub fn uzantidan(yol: &std::path::Path) -> Bicim {
        match yol
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref()
        {
            Some("csv") => Bicim::Csv,
            Some("json") => Bicim::Json,
            Some("txt") | Some("log") => Bicim::Txt,
            _ => Bicim::Html,
        }
    }
}

fn etiket(tag: char) -> (&'static str, &'static str) {
    match tag {
        'k' => ("Kesin hile", "k"),
        'y' => ("Yasaklı işlev", "y"),
        's' => ("Şüpheli", "s"),
        't' => ("Temiz", "t"),
        'x' => ("Temiz", "t"),
        'i' => ("Bilgi", "i"),
        _ => ("", "n"),
    }
}

fn agac(satirlar: &[TRow]) -> Vec<(&TRow, usize)> {
    use std::collections::HashMap;
    let mut cocuk: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut var: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for r in satirlar {
        var.insert(r.iid.as_str());
    }
    let mut kok = Vec::new();
    for (i, r) in satirlar.iter().enumerate() {
        if r.parent.is_empty() || !var.contains(r.parent.as_str()) {
            kok.push(i);
        } else {
            cocuk.entry(r.parent.as_str()).or_default().push(i);
        }
    }
    let mut out = Vec::with_capacity(satirlar.len());
    let mut yigin: Vec<(usize, usize)> = kok.into_iter().rev().map(|i| (i, 0)).collect();
    let mut gorulen = vec![false; satirlar.len()];
    while let Some((i, d)) = yigin.pop() {
        if std::mem::replace(&mut gorulen[i], true) {
            continue;
        }
        let r = &satirlar[i];
        out.push((r, d));
        if let Some(c) = cocuk.get(r.iid.as_str()) {
            for &j in c.iter().rev() {
                yigin.push((j, d + 1));
            }
        }
    }
    out
}

pub fn uret(r: &Rapor<'_>, b: Bicim) -> Vec<u8> {
    match b {
        Bicim::Html => html(r).into_bytes(),
        Bicim::Csv => bom(&csv(r)),
        Bicim::Json => json(r).into_bytes(),
        Bicim::Txt => bom(&r.metin.replace("\r\n", "\n").replace('\n', "\r\n")),
    }
}

fn bom(s: &str) -> Vec<u8> {
    let mut v = vec![0xEF, 0xBB, 0xBF];
    v.extend_from_slice(s.as_bytes());
    v
}

fn csv(r: &Rapor<'_>) -> String {
    fn hucre(s: &str) -> String {
        let s = s.replace("\r\n", " ").replace(['\n', '\r'], " ");
        let s = if s.starts_with(['=', '+', '-', '@']) {
            format!("'{s}")
        } else {
            s
        };
        if s.contains([';', '"']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s
        }
    }
    let mut o = String::from("Sekme;Seviye;Ad;Karar;Durum;Konum / ayrıntı\r\n");
    for s in &r.sekmeler {
        for (row, d) in agac(s.satirlar) {
            let (et, _) = etiket(row.tag);
            o.push_str(&format!(
                "{};{};{};{};{};{}\r\n",
                hucre(s.ad),
                d,
                hucre(&row.text),
                hucre(&row.v1),
                hucre(et),
                hucre(&row.v2)
            ));
        }
    }
    o
}

fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn json(r: &Rapor<'_>) -> String {
    let mut o = String::from("{\n");
    o.push_str(&format!(
        "  \"program\": {},\n",
        jstr(&format!("JournalScanner v{}", r.surum))
    ));
    o.push_str(&format!("  \"tarih\": {},\n", jstr(&r.tarih)));
    match &r.genel_karar {
        Some(k) => o.push_str(&format!("  \"genel_karar\": {},\n", jstr(k))),
        None => o.push_str("  \"genel_karar\": null,\n"),
    }
    let ad = ["toplam", "kesin", "yasakli", "supheli", "temiz"];
    let say: Vec<String> = ad
        .iter()
        .zip(&r.sayilar)
        .map(|(a, v)| match v.parse::<i64>() {
            Ok(n) => format!("\"{a}\": {n}"),
            Err(_) => format!("\"{a}\": null"),
        })
        .collect();
    o.push_str(&format!("  \"sayilar\": {{{}}},\n", say.join(", ")));
    o.push_str("  \"sekmeler\": [\n");
    for (si, s) in r.sekmeler.iter().enumerate() {
        o.push_str(&format!("    {{\"ad\": {}, \"satirlar\": [", jstr(s.ad)));
        for (i, (row, d)) in agac(s.satirlar).into_iter().enumerate() {
            let (et, _) = etiket(row.tag);
            o.push_str(if i == 0 { "\n" } else { ",\n" });
            o.push_str(&format!(
                "      {{\"seviye\": {d}, \"ad\": {}, \"karar\": {}, \"durum\": {}, \"konum\": {}}}",
                jstr(&row.text),
                jstr(&row.v1),
                jstr(et),
                jstr(&row.v2)
            ));
        }
        o.push_str(if s.satirlar.is_empty() { "]}" } else { "\n    ]}" });
        o.push_str(if si + 1 < r.sekmeler.len() { ",\n" } else { "\n" });
    }
    o.push_str("  ],\n");
    o.push_str(&format!("  \"metin_rapor\": {}\n", jstr(&r.metin)));
    o.push_str("}\n");
    o
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        o.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        o.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    o
}

const CSS: &str = r#"
:root{--bg:#f6f7f9;--sf:#ffffff;--bd:#dfe3e8;--tx:#1d2330;--sub:#5d6675;--k:#c62828;--y:#d9480f;--s:#b7791f;--t:#2f855a;--i:#2b6cb0;--ac:#2b6cb0}
@media (prefers-color-scheme:dark){:root{--bg:#14161b;--sf:#1c1f26;--bd:#2c313b;--tx:#e6e8ec;--sub:#9aa3b2;--k:#ff6b6b;--y:#ff922b;--s:#f2c94c;--t:#51cf66;--i:#74c0fc;--ac:#74c0fc}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
.w{max-width:1200px;margin:0 auto;padding:24px 16px 48px}
header{display:flex;align-items:center;gap:14px;margin-bottom:18px}header img{width:44px;height:44px}
h1{font-size:22px;font-weight:600;margin:0}.meta{color:var(--sub);font-size:13px}
.kart{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:14px 0 22px}
.c{background:var(--sf);border:1px solid var(--bd);border-radius:12px;padding:12px 14px}.c b{display:block;font-size:26px;font-weight:600}
.c span{font-size:12px;color:var(--sub);letter-spacing:.04em}
.c.k b{color:var(--k)}.c.y b{color:var(--y)}.c.s b{color:var(--s)}.c.t b{color:var(--t)}
.genel{background:var(--sf);border:1px solid var(--bd);border-left:6px solid var(--sub);border-radius:12px;padding:14px 18px;font-size:20px;font-weight:600}
.genel.k{border-left-color:var(--k);color:var(--k)}.genel.y{border-left-color:var(--y);color:var(--y)}.genel.s{border-left-color:var(--s);color:var(--s)}.genel.t{border-left-color:var(--t);color:var(--t)}
.ara{width:100%;padding:9px 12px;margin:18px 0 6px;border:1px solid var(--bd);border-radius:8px;background:var(--sf);color:var(--tx);font:inherit}
section{margin-top:22px}h2{font-size:17px;font-weight:600;margin:0 0 8px}h2 small{color:var(--sub);font-weight:400}
table{width:100%;border-collapse:collapse;background:var(--sf);border:1px solid var(--bd);border-radius:10px;overflow:hidden;table-layout:fixed}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--bd);vertical-align:top;overflow-wrap:anywhere}
th{font-size:12px;color:var(--sub);font-weight:600;background:var(--bg)}th:nth-child(1){width:34%}th:nth-child(2){width:18%}
tr:last-child td{border-bottom:0}td.yol{font-family:Consolas,monospace;font-size:12px;color:var(--sub)}
.b{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid currentColor}
.b.k{color:var(--k)}.b.y{color:var(--y)}.b.s{color:var(--s)}.b.t{color:var(--t)}.b.i{color:var(--i)}.b.n{color:var(--sub)}
tr.k td:first-child{color:var(--k);font-weight:600}tr.y td:first-child{color:var(--y);font-weight:600}tr.s td:first-child{color:var(--s)}
.bos{color:var(--sub);font-style:italic;padding:6px 0}
details{margin-top:28px}summary{cursor:pointer;font-weight:600}pre{background:var(--sf);border:1px solid var(--bd);border-radius:10px;padding:14px;overflow:auto;font:12px/1.45 Consolas,monospace;white-space:pre-wrap}
footer{margin-top:30px;color:var(--sub);font-size:12px}
@media print{.ara{display:none}details{display:block}body{background:#fff;color:#000}}
"#;

const JS: &str = r#"
const a=document.getElementById('ara');a&&a.addEventListener('input',()=>{const q=a.value.toLocaleLowerCase('tr');
document.querySelectorAll('tbody tr').forEach(r=>{r.style.display=!q||r.textContent.toLocaleLowerCase('tr').includes(q)?'':'none'})});
"#;

fn html(r: &Rapor<'_>) -> String {
    let mut o = String::with_capacity(r.metin.len() * 2 + 64 * 1024);
    let logo = base64(include_bytes!("../assets/icon.png"));
    o.push_str("<!doctype html>\n<html lang=\"tr\"><head><meta charset=\"utf-8\">");
    o.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    o.push_str(&format!("<title>JournalScanner raporu - {}</title>", esc(&r.tarih)));
    o.push_str(&format!("<link rel=\"icon\" href=\"data:image/png;base64,{logo}\">"));
    o.push_str("<style>");
    o.push_str(CSS);
    o.push_str("</style></head><body><div class=\"w\">");
    o.push_str(&format!(
        "<header><img alt=\"\" src=\"data:image/png;base64,{logo}\"><div><h1>JournalScanner raporu</h1>\
         <div class=\"meta\">v{} &middot; {}</div></div></header>",
        esc(r.surum),
        esc(&r.tarih)
    ));
    let (gk, gc) = match &r.genel_karar {
        Some(k) => (k.as_str(), etiket(r.genel_etiket).1),
        None => ("Tarama tamamlanmadı", "n"),
    };
    o.push_str(&format!("<div class=\"genel {gc}\">Genel karar: {}</div>", esc(gk)));
    let ad = [
        ("TOPLAM", ""),
        ("KESİN", "k"),
        ("YASAKLI", "y"),
        ("ŞÜPHELİ", "s"),
        ("TEMİZ", "t"),
    ];
    o.push_str("<div class=\"kart\">");
    for ((a, c), v) in ad.iter().zip(&r.sayilar) {
        o.push_str(&format!("<div class=\"c {c}\"><span>{a}</span><b>{}</b></div>", esc(v)));
    }
    o.push_str("</div>");
    o.push_str(
        "<input id=\"ara\" class=\"ara\" type=\"search\" placeholder=\"Tüm tablolarda ara (dosya adı, karar, yol)\">",
    );
    for s in &r.sekmeler {
        let satir = agac(s.satirlar);
        let isaretli = s.satirlar.iter().filter(|x| matches!(x.tag, 'k' | 'y' | 's')).count();
        o.push_str(&format!(
            "<section><h2>{} <small>({} satır{})</small></h2>",
            esc(s.ad),
            s.satirlar.len(),
            if isaretli > 0 {
                format!(", {isaretli} bulgu")
            } else {
                String::new()
            }
        ));
        if satir.is_empty() {
            o.push_str("<div class=\"bos\">Kayıt yok.</div></section>");
            continue;
        }
        o.push_str(&format!(
            "<table><thead><tr><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>",
            esc(s.basliklar[0]),
            esc(s.basliklar[1]),
            esc(s.basliklar[2])
        ));
        for (row, d) in satir {
            let (_, c) = etiket(row.tag);
            let girinti = if d > 0 {
                format!(" style=\"padding-left:{}px\"", 10 + d * 18)
            } else {
                String::new()
            };
            let karar = if row.v1.is_empty() {
                String::new()
            } else {
                format!("<span class=\"b {c}\">{}</span>", esc(&row.v1))
            };
            o.push_str(&format!(
                "<tr class=\"{c}\"><td{girinti}>{}</td><td>{karar}</td><td class=\"yol\">{}</td></tr>",
                esc(&row.text),
                esc(&row.v2)
            ));
        }
        o.push_str("</tbody></table></section>");
    }
    o.push_str("<details><summary>Tam metin rapor</summary><pre>");
    o.push_str(&esc(&r.metin));
    o.push_str("</pre></details>");
    o.push_str(&format!(
        "<footer>JournalScanner v{} &middot; Tarama yalnızca okur; hiçbir dosya silinmez veya değiştirilmez.</footer>",
        esc(r.surum)
    ));
    o.push_str("</div><script>");
    o.push_str(JS);
    o.push_str("</script></body></html>\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ornek() -> Vec<TRow> {
        vec![
            TRow::new("a", "", "hile.jar", "KESİN HİLE", "C:\\x\\hile.jar", 'k'),
            TRow::new("a1", "a", "alt <b>", "", "detay \"tırnak\"; noktalı", 'i'),
            TRow::new("b", "", "=cmd", "Temiz", "C:\\y", 't'),
        ]
    }

    fn rapor(s: &[TRow]) -> Rapor<'_> {
        Rapor {
            surum: "23.0",
            tarih: "2026-11-01 12:00".into(),
            genel_karar: Some("Kesin hile".into()),
            genel_etiket: 'k',
            sayilar: ["3".into(), "1".into(), "0".into(), "0".into(), "1".into()],
            sekmeler: vec![Sekme {
                ad: "Mod Taraması",
                basliklar: ["Ad", "Karar", "Yol"],
                satirlar: s,
            }],
            metin: "satır 1\nsatır 2".into(),
        }
    }

    #[test]
    fn agac_sirasi_ve_derinlik() {
        let s = ornek();
        let a: Vec<(String, usize)> = agac(&s).into_iter().map(|(r, d)| (r.iid.clone(), d)).collect();
        assert_eq!(a, vec![("a".into(), 0), ("a1".into(), 1), ("b".into(), 0)]);
    }

    #[test]
    fn html_kacis_ve_icerik() {
        let s = ornek();
        let h = html(&rapor(&s));
        assert!(h.contains("alt &lt;b&gt;"));
        assert!(!h.contains("alt <b>"));
        assert!(h.contains("Genel karar: Kesin hile"));
        assert!(h.contains("data:image/png;base64,"));
    }

    #[test]
    fn csv_ayirici_tirnak_ve_formul() {
        let s = ornek();
        let c = csv(&rapor(&s));
        assert!(c.starts_with("Sekme;"));
        assert!(c.contains("\"detay \"\"tırnak\"\"; noktalı\""));
        assert!(c.contains(";'=cmd;"));
    }

    #[test]
    fn json_gecerli_kacis() {
        let s = ornek();
        let j = json(&rapor(&s));
        assert!(j.contains("\"toplam\": 3"));
        assert!(j.contains("detay \\\"tırnak\\\"; noktalı"));
        assert!(j.contains("\"metin_rapor\": \"satır 1\\nsatır 2\""));
    }

    #[test]
    fn base64_dogru() {
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
    }

    #[test]
    fn uzanti_bicim() {
        use std::path::Path;
        assert_eq!(Bicim::uzantidan(Path::new("a.CSV")), Bicim::Csv);
        assert_eq!(Bicim::uzantidan(Path::new("a.json")), Bicim::Json);
        assert_eq!(Bicim::uzantidan(Path::new("a.txt")), Bicim::Txt);
        assert_eq!(Bicim::uzantidan(Path::new("a")), Bicim::Html);
    }
}
