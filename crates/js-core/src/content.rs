use crate::disk::*;
use crate::report::{mod_lines, text_hit_lines};
use crate::util::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ContentVerdict {
    pub readable: bool,
    pub rank: i32,
    pub verdict: String,
    pub res: Option<ResultP>,
    pub texts: Vec<TextHit>,
}
impl Default for ContentVerdict {
    fn default() -> Self {
        ContentVerdict {
            readable: false,
            rank: 0,
            verdict: "TEMIZ".to_string(),
            res: None,
            texts: Vec::new(),
        }
    }
}

fn outer_of(label: &str) -> String {
    let a = split(label, " !/ ", -1).into_iter().next().unwrap_or_default();
    let b = split(&a, "  (", -1).into_iter().next().unwrap_or_default();
    py_lower(&b)
}

pub fn analyze_files(
    paths: &[String],
    stop: Option<&StopFlag>,
    progress: Option<StrProgress>,
) -> BTreeMap<String, ContentVerdict> {
    let mut out: BTreeMap<String, ContentVerdict> = BTreeMap::new();
    let mut todo: StrList = Vec::new();
    for p in paths {
        let k = py_lower(p);
        if out.contains_key(&k) {
            continue;
        }
        let head = read_file(p, 64, 0);
        let c = ContentVerdict {
            readable: head.is_some(),
            ..Default::default()
        };
        let readable = c.readable;
        out.insert(k, c);
        if readable {
            todo.push(p.clone());
        }
    }
    if todo.is_empty() {
        return out;
    }
    if let Some(pr) = progress {
        pr(&format!("{} dosyanın içeriği taranıyor (disk motoru)...", todo.len()));
    }
    let own = Arc::new(StopFlag::new());
    let done = AtomicBool::new(false);
    let dr = std::thread::scope(|sc| {
        if let Some(ext) = stop {
            let own2 = Arc::clone(&own);
            let done_ref = &done;
            sc.spawn(move || {
                while !done_ref.load(Ordering::Relaxed) {
                    if ext.is_set() {
                        own2.set();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
        }
        let mut ds = DiskScanner::new(Vec::new(), None, Some(Arc::clone(&own)), 0, Vec::new());
        let dr = ds.scan_paths(&todo, "içerik analizi");
        done.store(true, Ordering::Relaxed);
        dr
    });
    for rp in &dr.results {
        let mut keys: StrList = vec![outer_of(&rp.file)];
        for a in &rp.also_at {
            keys.push(outer_of(a));
        }
        for k in &keys {
            let Some(c) = out.get_mut(k) else {
                continue;
            };
            if rp.rank > c.rank {
                c.rank = rp.rank;
                c.verdict = rp.verdict.clone();
                c.res = Some(Arc::clone(rp));
            }
        }
    }
    for th in &dr.text_hits {
        let Some(c) = out.get_mut(&outer_of(&th.file)) else {
            continue;
        };
        c.texts.push(th.clone());
        if c.rank < 1 {
            c.rank = 1;
            c.verdict = "SUPHELI".to_string();
        }
    }
    out
}

pub fn content_lines(c: &ContentVerdict) -> StrList {
    let mut l: StrList = Vec::new();
    if let Some(r) = &c.res {
        l.extend(mod_lines(r, ""));
    }
    for t in &c.texts {
        if !l.is_empty() {
            l.push(String::new());
        }
        l.extend(text_hit_lines(t, ""));
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outer_of_keser() {
        assert_eq!(outer_of(r"C:\A\B.JAR !/ x/y.class"), r"c:\a\b.jar");
        assert_eq!(outer_of(r"C:\A\B.bin  (gizli veri akisi -> :x)"), r"c:\a\b.bin");
    }
}
