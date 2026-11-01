use crate::analysis::*;
use crate::hidden::*;
use crate::jbytecode::{java_finish, JavaAcc};
use crate::pat_data::*;
use crate::patterns::*;
use crate::payload::scan_payload;
use crate::pe::parse_pe;
use crate::score::*;
use crate::util::*;
use std::collections::{BTreeMap, BTreeSet};

fn dict_cat(cat: u8) -> bool {
    cat == C_FAMILY || cat == C_CLIENT_A || cat == C_MOD_STRONG || cat == C_OPT || cat == C_SDSTR || cat == C_GUICHEAT
}

fn scan_buf(a: &mut Analysis, cx: &mut StrCtx, o: &AnalyzeOpts, b: &[u8], payload: bool) {
    let db = get_db();
    extract_strings(b, 0, b.len(), 4, |s, off, _| {
        let sl = s.len();
        match_string(s, cx, false, |id, _, _| {
            let pi = &db.pats[id as usize];
            let m = if payload { &mut a.phits } else { &mut a.hits };
            if !m.contains_key(&id) {
                m.insert(
                    id,
                    Hit1 {
                        text: bs(&s[..sl.min(160)]),
                        off,
                    },
                );
            }
            if !payload && sl >= 6 && dict_cat(pi.cat) && a.dict_s.len() < 600 {
                a.dict_s.insert(bs(&s[..sl.min(120)]));
            }
        });
        if !payload {
            collect_misc(s, &cx.low, a);
        }
        if o.keep_strings && !payload && a.strs.len() < 200000 {
            a.strs.push(bs(&s[..sl.min(300)]));
        }
    });
}

fn feed_hidden(a: &mut Analysis, cx: &mut StrCtx, s: &[u8], off: usize, how: &str) -> i32 {
    let hdb = get_db();
    let mut added = 0;
    match_string(s, cx, false, |id, _, _| {
        let pi = &hdb.pats[id as usize];
        if !a.hits.contains_key(&id) {
            a.hits.insert(
                id,
                Hit1 {
                    text: format!("[{}] {}", how, bs(&s[..s.len().min(150)])),
                    off,
                },
            );
            added += 1;
        }
        if s.len() >= 6 && dict_cat(pi.cat) && a.dict_s.len() < 600 {
            a.dict_s.insert(bs(&s[..s.len().min(120)]));
        }
    });
    collect_misc(s, &cx.low, a);
    if added != 0 && a.hidden.len() < 60 {
        a.hidden.push(HiddenStr {
            text: bs(&s[..s.len().min(200)]),
            how: how.to_string(),
            off,
        });
    }
    added
}

fn run_payload(a: &mut Analysis, cx: &mut StrCtx, o: &AnalyzeOpts, buf: &[u8], at: usize, how: &str, npay: &mut i32) {
    if !payload_magic(buf) {
        return;
    }
    let cls0 = a.classes.len();
    let zip0 = a.zip_count;
    let is_cls = buf[0] == 0xCA;
    scan_buf(a, cx, o, buf, false);
    {
        let cxp = &mut *cx;
        scan_payload(buf, a, &mut |aa, b, p| scan_buf(aa, cxp, o, b, p), 0);
    }
    *npay += 1;
    a.hid_payload += 1;
    if a.hidden.len() < 60 {
        let t = format!(
            "gömülü {} ({}) çözüldü -> {} sınıf, {} arşiv payload analizine alındı",
            if is_cls { ".class" } else { "JAR/ZIP" },
            fmt_size(buf.len() as u64),
            a.classes.len() - cls0,
            a.zip_count - zip0
        );
        a.hidden.push(HiddenStr {
            text: t,
            how: how.to_string(),
            off: at,
        });
    }
}

pub fn analyze_buffer(d: &[u8], o: &AnalyzeOpts, a: &mut Analysis) {
    let n = d.len();
    a.size = n;
    a.in_user_dir = o.in_user_dir;
    a.mem_image = o.mem_image;
    a.sha = sha256_hex(d);
    a.entropy = entropy_of(d);
    if n >= 0x200 && d[0] == b'M' && d[1] == b'Z' {
        let mut pa = parse_pe(d, o.mem_image);
        if o.auto_layout && !o.mem_image {
            let score = |p: &crate::pe::PeInfo| -> i32 {
                let mut sc = 0;
                for dl in &p.imp_dlls {
                    if dl.len() >= 5 && dl.ends_with(".dll") {
                        let okc = dl.bytes().all(|c| is_alnum(c) || c == b'.' || c == b'_' || c == b'-');
                        if okc {
                            sc += 1;
                        }
                    }
                }
                sc
            };
            let pb = parse_pe(d, true);
            match (&pa, pb) {
                (Some(x), Some(y)) => {
                    if score(&y) > score(x) {
                        pa = Some(y);
                    }
                }
                (None, Some(y)) => pa = Some(y),
                _ => {}
            }
        }
        if let Some(p) = pa {
            a.pe = p;
            a.is_pe = true;
        }
    }
    let mut cx = StrCtx::default();
    scan_buf(a, &mut cx, o, d, false);
    if memchr::memmem::find(d, SCANNER_MARKER.as_bytes()).is_some() {
        a.has_marker = true;
    }
    if a.is_pe {
        if !a.pe.pdb.is_empty() {
            let pdb = a.pe.pdb.clone();
            let low = lower_str(&pdb);
            match_string(pdb.as_bytes(), &mut cx, false, |id, _, _| {
                a.hits.entry(id).or_insert_with(|| Hit1 {
                    text: pdb.clone(),
                    off: 0,
                });
            });
            if low.contains("custom-base") || low.contains("custombase") {
                a.pdb_family = true;
            }
            let anti = low.contains("anticheat") || low.contains("anti-cheat") || low.contains("anti_cheat");
            const W: [&str; 7] = [
                "cheat",
                "hack",
                "inject",
                "aimbot",
                "killaura",
                "triggerbot",
                "ghostclient",
            ];
            if !anti {
                for x in W {
                    if low.contains(x) {
                        a.pdb_sus = true;
                        break;
                    }
                }
            }
        }
        analyze_code(d, a);
        a.benign_jvm = (a.pe.exp_create && a.pe.exp_jvm >= 10)
            || (a.pe.exp_total >= 3 && (a.pe.exp_jdk as u64) * 10 >= (a.pe.exp_total as u64) * 7);
        a.benign_cef = a.pe.exp_cef >= 40 && (a.pe.exp_cef as u64) * 2 >= a.pe.exp_total as u64 && n >= (30usize << 20);
        for s in a.pe.secs.clone() {
            let nm = lower_str(&s.name);
            if nm == ".vmp0" || nm == ".vmp1" || nm == ".vmp2" {
                a.packer = "VMProtect".into();
                a.packer_strong = true;
            } else if nm == ".themida" || nm == ".winlice" {
                a.packer = "Themida/WinLicense".into();
                a.packer_strong = true;
            } else if nm == ".enigma1" || nm == ".enigma2" {
                a.packer = "Enigma Protector".into();
                a.packer_strong = true;
            } else if a.packer.is_empty() && (nm == "upx0" || nm == "upx1") {
                a.packer = "UPX".into();
            } else if a.packer.is_empty() && (nm == ".aspack" || nm == ".adata") {
                a.packer = "ASPack".into();
            } else if a.packer.is_empty() && (nm == ".mpress1" || nm == ".mpress2") {
                a.packer = "MPRESS".into();
            }
        }
        if a.packer.is_empty() && !a.pe.mem_layout && a.pe.imps.len() < 12 {
            for s in &a.pe.secs {
                if (s.chars & 0x2000_0000) != 0 && s.ent > 7.3 && s.raw_size > 0x4000 {
                    a.packer = format!("yüksek entropi {:.2} (olası paketleyici/şifreleme)", s.ent);
                    break;
                }
            }
        }
    }
    if a.is_pe {
        let hdb = get_db();
        {
            let mut seen_stk: BTreeSet<Vec<u8>> = BTreeSet::new();
            let pe = std::mem::take(&mut a.pe);
            stack_strings(d, &pe, &mut |s, off| {
                if seen_stk.len() >= 20000 || !seen_stk.insert(s.to_vec()) {
                    return;
                }
                if feed_hidden(a, &mut cx, s, off, "yığın string") > 0 {
                    a.hid_stack += 1;
                }
            });
            a.pe = pe;
        }
        {
            let mut xc: Vec<XorCand> = Vec::new();
            xor_string_cands(d, &mut xc);
            let mut grp: BTreeMap<u8, Vec<XorCand>> = BTreeMap::new();
            for c in &xc {
                grp.entry(c.key & 0xDF).or_default().push(*c);
            }
            let mut by_key: BTreeMap<u8, Vec<usize>> = BTreeMap::new();
            for (gk, list) in &grp {
                let mut best: i64 = -1;
                let mut bk = 0u8;
                for k in [*gk, *gk | 0x20] {
                    if k == 0x00 || k == 0x20 {
                        continue;
                    }
                    let mut sc: i64 = 0;
                    let mut valid = true;
                    for c in list {
                        for j in 0..c.len {
                            let ch = d[c.off + j] ^ k;
                            if !is_print_a(ch) {
                                valid = false;
                                break;
                            }
                            if ch.is_ascii_lowercase() {
                                sc += 1;
                            }
                        }
                        if !valid {
                            break;
                        }
                        if c.off + c.len < n && (d[c.off + c.len] ^ k) == 0 {
                            sc += 100;
                        }
                        if c.off > 0 && (d[c.off - 1] ^ k) == 0 {
                            sc += 100;
                        }
                    }
                    if valid && sc > best {
                        best = sc;
                        bk = k;
                    }
                }
                if best >= 0 {
                    for c in list {
                        by_key.entry(bk).or_default().push(c.off);
                    }
                }
            }
            for (&k, offs) in &by_key {
                let mut starts: BTreeSet<usize> = BTreeSet::new();
                let mut wins: Vec<(Vec<u8>, usize)> = Vec::new();
                for &o2 in offs {
                    let mut st = o2;
                    while st > 0 && o2 - st < 80 && d[st - 1] != 0 && is_print_a(d[st - 1] ^ k) {
                        st -= 1;
                    }
                    let mut e = o2;
                    while e < n && e - st < 240 && d[e] != 0 && is_print_a(d[e] ^ k) {
                        e += 1;
                    }
                    if !starts.insert(st) {
                        continue;
                    }
                    let w: Vec<u8> = d[st..e].iter().map(|&c| c ^ k).collect();
                    wins.push((w, st));
                }
                let mut strong: BTreeSet<i32> = BTreeSet::new();
                for w in &wins {
                    match_string(&w.0, &mut cx, false, |id, _, _| {
                        if hid_strong_cat(hdb.pats[id as usize].cat) {
                            strong.insert(id);
                        }
                    });
                }
                if strong.len() < 2 {
                    continue;
                }
                for w in &wins {
                    if feed_hidden(a, &mut cx, &w.0, w.1, &format!("XOR 0x{:02X}", k)) > 0 {
                        a.hid_xor += 1;
                    }
                }
            }
        }
        {
            let mut npay = 0i32;
            let mut done_r: Vec<(usize, usize)> = Vec::new();
            let in_done = |done_r: &[(usize, usize)], p: usize| done_r.iter().any(|r| p >= r.0 && p < r.1);
            const B64N: [&[u8]; 2] = [b"yv66vg", b"UEsDB"];
            for wide in 0..2usize {
                if npay >= 6 {
                    break;
                }
                for nd in B64N {
                    let nl = nd.len();
                    let st = if wide != 0 { 2 } else { 1 };
                    let mut i = 0usize;
                    while i + nl * st < n && npay < 6 {
                        let window = n - i - nl * st;
                        let Some(off) = memchr::memchr(nd[0], &d[i..i + window]) else {
                            break;
                        };
                        i += off;
                        let mut m = true;
                        for j in 0..nl {
                            if !m {
                                break;
                            }
                            if d[i + j * st] != nd[j] || (wide != 0 && d[i + j * st + 1] != 0) {
                                m = false;
                            }
                        }
                        if !m || in_done(&done_r, i) {
                            i += 1;
                            continue;
                        }
                        if i >= st && is_b64c(d[i - st]) && (wide == 0 || d[i - 1] == 0) {
                            i += 1;
                            continue; // bir base64 dizisinin ortası (hizasız): atla
                        }
                        let mut s: Vec<u8> = Vec::new();
                        let mut j = i;
                        while j + (if wide != 0 { 1 } else { 0 }) < n && s.len() < (128usize << 20) {
                            let ch = d[j];
                            if wide != 0 && d[j + 1] != 0 {
                                break;
                            }
                            if is_b64c(ch) || ch == b'=' {
                                s.push(ch);
                            } else if ch != b'\r' && ch != b'\n' {
                                break;
                            }
                            j += st;
                        }
                        done_r.push((i, j));
                        if s.len() < 40 {
                            i += 1;
                            continue;
                        }
                        let mut buf = Vec::new();
                        b64_decode(&s, &mut buf, 96 << 20);
                        run_payload(
                            a,
                            &mut cx,
                            o,
                            &buf,
                            i,
                            if wide != 0 { "base64 (UTF-16)" } else { "base64" },
                            &mut npay,
                        );
                        i += 1;
                    }
                }
            }
            let mut xor_done: BTreeMap<u8, usize> = BTreeMap::new();
            let mut i = 0usize;
            while i + 32 <= n && npay < 6 {
                let cur = i;
                i += 1;
                let a0 = d[cur] ^ d[cur + 1];
                let cls = a0 == 0x34 && (d[cur + 1] ^ d[cur + 2]) == 0x44 && (d[cur + 2] ^ d[cur + 3]) == 0x04;
                let zip = !cls && a0 == 0x1B && (d[cur + 1] ^ d[cur + 2]) == 0x48 && (d[cur + 2] ^ d[cur + 3]) == 0x07;
                if !cls && !zip {
                    continue;
                }
                let k = d[cur] ^ if cls { 0xCA } else { b'P' };
                if k == 0 {
                    continue;
                }
                if let Some(&dn) = xor_done.get(&k) {
                    if cur < dn {
                        continue;
                    }
                }
                let mut hd = [0u8; 32];
                for j in 0..32 {
                    hd[j] = d[cur + j] ^ k;
                }
                if !payload_magic(&hd) {
                    continue;
                }
                let len = (n - cur).min(if cls { 8usize << 20 } else { 96usize << 20 });
                let buf: Vec<u8> = d[cur..cur + len].iter().map(|&c| c ^ k).collect();
                xor_done.insert(k, cur + len);
                run_payload(a, &mut cx, o, &buf, cur, &format!("XOR 0x{:02X}", k), &mut npay);
            }
        }
    }
    {
        let cxp = &mut cx;
        scan_payload(d, a, &mut |aa, b, p| scan_buf(aa, cxp, o, b, p), 0);
    }
    {
        let jacc = std::mem::take(&mut a.jacc);
        let meta = std::mem::take(&mut a.jmeta);
        let mut jv = std::mem::take(&mut a.jv);
        java_finish(&jacc, &meta, &mut jv);
        a.beh_red = jv.red() > 0;
        a.beh_yellow = jv.yel() > 0;
        a.jv = jv;
        a.jmeta = meta;
        a.jacc = JavaAcc::default();
    }
    filter_exported_apis(a);
    if !a.is_pe {
        let ph: Vec<(i32, Hit1)> = a.phits.iter().map(|(k, v)| (*k, v.clone())).collect();
        for (k, v) in ph {
            a.hits.entry(k).or_insert(v);
        }
    }
    build_cat_labels(a);
    build_sd(a);
    score(a);
}

pub fn render_analysis(a: &Analysis) -> Vec<String> {
    let mut l: Vec<String> = Vec::new();
    let hdr = |l: &mut Vec<String>, t: &str| {
        let dashes = (62i64 - t.len() as i64).max(2) as usize;
        l.push(format!("  +--[ {} ]{}", t, "-".repeat(dashes)));
    };
    let row = |l: &mut Vec<String>, k: &str, v: &str| {
        let pad = if k.len() < 11 { 11 - k.len() } else { 1 };
        l.push(format!("  | {}{}: {}", k, " ".repeat(pad), v));
    };
    let line = |l: &mut Vec<String>, v: &str| l.push(format!("  |   {}", v));
    let pe = &a.pe;
    hdr(&mut l, "DOSYA KİMLİĞİ");
    if !a.path.is_empty() {
        row(&mut l, "Yol", &a.path);
    }
    if a.size == 0 {
        row(
            &mut l,
            "Durum",
            if a.sig_text.is_empty() {
                "dosya yok / bellek izi"
            } else {
                &a.sig_text
            },
        );
    } else {
        row(
            &mut l,
            "Boyut",
            &format!("{}   SHA-256: {}", fmt_size(a.size as u64), a.sha),
        );
        if a.is_pe {
            row(
                &mut l,
                "PE",
                &format!(
                    "{} {}   derleme: {}   entropi: {:.2}{}",
                    if pe.is64 { "x64" } else { "x86" },
                    if pe.is_dll { "DLL" } else { "EXE" },
                    fmt_time(pe.timestamp),
                    a.entropy,
                    if a.mem_image { "   [BELLEK GÖRÜNTÜSÜ]" } else { "" }
                ),
            );
        } else {
            row(
                &mut l,
                "Tür",
                &format!("PE değil / ayrıştırılamadı   entropi: {:.2}", a.entropy),
            );
        }
        if !pe.pdb.is_empty() {
            row(&mut l, "PDB", &pe.pdb);
        }
        row(
            &mut l,
            "İmza",
            if a.sig_text.is_empty() {
                "bilinmiyor"
            } else {
                &a.sig_text
            },
        );
        if a.is_pe && !pe.secs.is_empty() {
            let mut s = String::new();
            let mut k = 0;
            for x in &pe.secs {
                let stop = k >= 8;
                k += 1;
                if stop {
                    s.push_str(" ...");
                    break;
                }
                let sz = x.raw_size.max(if a.mem_image { x.vsize } else { 0 });
                s.push_str(&format!("{}({},e{:.1}) ", x.name, fmt_size(sz as u64), x.ent));
            }
            row(&mut l, "Bölümler", &s);
            let dl: Vec<String> = pe.imp_dlls.iter().cloned().collect();
            row(
                &mut l,
                "Import DLL",
                &format!("{} adet: {}", dl.len(), join_l(&dl, 14, ", ")),
            );
            if !pe.exps.is_empty() {
                row(
                    &mut l,
                    "Export",
                    &format!("{} adet: {}", pe.exps.len(), join_l(&pe.exps, 6, ", ")),
                );
            }
        }
    }
    let any_t = a.ev.iter().any(|e| e.cls == 'T');
    if any_t {
        hdr(&mut l, "YETENEK ANALİZİ (JVM / Minecraft / hook)");
        for e in &a.ev {
            if e.cls == 'T' {
                line(&mut l, &format!("[+{}] {}", e.w, e.text));
            }
        }
    }
    if !a.mc_refs.is_empty() || !a.srg.is_empty() || !a.cat_labels[C_MCNAME as usize].is_empty() {
        hdr(&mut l, "MINECRAFT ERİŞİMİ");
        if !a.mc_refs.is_empty() {
            let v: Vec<String> = a.mc_refs.iter().cloned().collect();
            row(
                &mut l,
                "Sınıf ref.",
                &format!("{} adet: {}", v.len(), join_l(&v, 8, ", ")),
            );
        }
        if !a.srg.is_empty() {
            let v: Vec<String> = a.srg.iter().cloned().collect();
            row(
                &mut l,
                "Eşlemeli ad",
                &format!("{} adet (field_/method_/class_): {}", v.len(), join_l(&v, 6, ", ")),
            );
        }
        if !a.cat_labels[C_MCNAME as usize].is_empty() {
            row(&mut l, "İç adlar", &join_l(&a.cat_labels[C_MCNAME as usize], 8, ", "));
        }
    }
    {
        const ORDER: [u8; 9] = [
            C_FAMILY,
            C_CLIENT_A,
            C_CLIENT_B,
            C_MOD_STRONG,
            C_MOD_WEAK,
            C_OPT,
            C_GUICHEAT,
            C_SDSTR,
            C_NET,
        ];
        let any = ORDER.iter().any(|&c| !a.cat_labels[c as usize].is_empty());
        if any {
            hdr(&mut l, "HİLE SİNYALLERİ (modül / metot / ayar / istemci adları)");
            for c in ORDER {
                if !a.cat_labels[c as usize].is_empty() {
                    row(
                        &mut l,
                        CAT_NAME[c as usize],
                        &join_l(&a.cat_labels[c as usize], 14, ", "),
                    );
                }
            }
        }
    }
    if !a.hidden.is_empty() {
        hdr(&mut l, "GİZLENMİŞ STRINGLER / PAYLOAD (düz metin taramasında görünmez)");
        row(
            &mut l,
            "Özet",
            &format!(
                "yığın string: {}   XOR: {}   gizli Java payload: {}",
                a.hid_stack, a.hid_xor, a.hid_payload
            ),
        );
        let mut k = 0usize;
        for h in &a.hidden {
            let stop = k >= 16;
            k += 1;
            if stop {
                line(&mut l, &format!("... +{}", a.hidden.len() - 16));
                break;
            }
            line(
                &mut l,
                &format!("[{}  ofset {}] {}", h.how, hex(h.off as u64), trunc(&h.text, 140)),
            );
        }
    }
    {
        let gui = !a.cat_labels[C_IMGUI as usize].is_empty() || !a.cat_labels[C_HOOKLIB as usize].is_empty();
        if gui || !a.keys.is_empty() {
            hdr(&mut l, "GUI / TUŞ ANALİZİ");
            if gui {
                let mut g: Vec<String> = Vec::new();
                g.extend(a.cat_labels[C_IMGUI as usize].iter().cloned());
                g.extend(a.cat_labels[C_HOOKLIB as usize].iter().cloned());
                row(&mut l, "GUI/Hook", &join_l(&g, 8, ", "));
            }
            for k in &a.keys {
                let tail = if k.exit_branch {
                    "   ** TETİKLEYİCİ TUŞ: koşullu atlama modül boşaltmaya (self-destruct) gidiyor"
                } else if k.near_unload {
                    "   * olası tetik/menu tuşu (aynı fonksiyonda modül boşaltma var)"
                } else {
                    ""
                };
                line(
                    &mut l,
                    &format!("{:<12} <- {} (RVA 0x{:X}){}", vk_name(k.vk), k.api, k.rva, tail),
                );
            }
            if a.keys.is_empty() {
                line(
                    &mut l,
                    "sabit tuş değeri statik olarak bulunamadı (hesaplanmış/şifreli olabilir)",
                );
            } else {
                line(&mut l, "not: tuşlar komut-akışı sezgisiyle bulunur (olası); kesin doğrulama için dosyayı tersine mühendislikle inceleyin");
            }
        }
    }
    if a.sd.level > 0 || a.sd.sd_str {
        hdr(&mut l, "SELF-DESTRUCT ANALİZİ");
        row(&mut l, "Seviye", &format!("{}/4 - {}", a.sd.level, a.sd.level_name));
        for n in &a.sd.notes {
            line(&mut l, &format!("- {}", n));
        }
        {
            let mut any_exit = false;
            for k in &a.keys {
                if k.exit_branch {
                    any_exit = true;
                    row(
                        &mut l,
                        "Tetik tuşu",
                        &format!("{} ({}) - dallanma doğrulandı", vk_name(k.vk), k.api),
                    );
                }
            }
            if !any_exit {
                for k in &a.keys {
                    if k.near_unload {
                        row(
                            &mut l,
                            "Tetik adayı",
                            &format!("{} ({}) - aynı fonksiyonda boşaltma var (olası)", vk_name(k.vk), k.api),
                        );
                    }
                }
            }
        }
        if !a.unload_sites.is_empty() {
            row(
                &mut l,
                "Boşaltma",
                &format!("modül boşaltma çağrısı RVA: {}", join_l(&a.unload_sites, 6, ", ")),
            );
        }
        if a.sd.unload && !a.sd.file_del && !a.sd.cmd_del {
            line(
                &mut l,
                "iz: dosya diskte kaldığı için disk taramasıyla bulunur; çıkış sonrası heap kalıntıları aranır",
            );
        }
        if a.sd.file_del || a.sd.cmd_del {
            line(&mut l, "iz: dosya silinmiş olabilir -> Geri Dönüşüm Kutusu, bellek kalıntıları ve enjeksiyon-yolu izleri aranır");
        }
    }
    if a.jv.analyzed || a.jv.lib_only {
        let jv = &a.jv;
        hdr(&mut l, "GÖMÜLÜ JAVA KODU - BYTECODE ANALİZİ (DLL payload)");
        if jv.lib_only {
            line(&mut l, "tüm sınıflar bilinen kütüphane/Minecraft paketlerinde ve mod bildirimi yok: vanilla/kütüphane JAR'i, içerik analizine alınmadı");
        } else {
            let name = if jv.mod_name.is_empty() {
                if jv.mod_id.is_empty() {
                    "(bildirim yok)".to_string()
                } else {
                    jv.mod_id.clone()
                }
            } else {
                jv.mod_name.clone()
            };
            let mod_s = format!(
                "{}{}{}",
                name,
                if jv.mod_ver.is_empty() {
                    String::new()
                } else {
                    format!(" {}", jv.mod_ver)
                },
                if jv.loader.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", jv.loader)
                }
            );
            row(&mut l, "Mod", &mod_s);
            row(
                &mut l,
                "Sınıflar",
                &format!(
                    "{} 3. parti sınıf, {} değerlendirilen, {} mixin, {} native metot{}{}",
                    jv.third_party,
                    jv.classes_eval,
                    jv.mixins,
                    jv.natives,
                    if jv.agent { ", JAVA AJANI" } else { "" },
                    if jv.server_plugin { ", SUNUCU EKLENTİSİ" } else { "" }
                ),
            );
            if jv.obfuscated {
                row(&mut l, "Obfuscation", &jv.obf_note);
            }
            if jv.beh.is_empty() {
                line(&mut l, "hile modülü davranışı bulunmadı");
            }
            for b in &jv.beh {
                line(
                    &mut l,
                    &format!(
                        "{}{}  sınıf {}{}{}  <- {}",
                        if b.sev >= 3 { "[KESİN]   " } else { "[şüpheli] " },
                        b.module,
                        trunc(&b.cls, 60),
                        if b.indirect {
                            " (yardımcı sınıflar üzerinden)"
                        } else {
                            ""
                        },
                        if b.classes > 1 {
                            format!(" (+{} sınıf)", b.classes - 1)
                        } else {
                            String::new()
                        },
                        b.why
                    ),
                );
            }
            if jv.sd_confirmed || jv.sd_suspect {
                row(
                    &mut l,
                    "Self-destruct",
                    &format!(
                        "Java mantığı: seviye {} ({})",
                        jv.sd_level,
                        if jv.sd_confirmed { "KESİN" } else { "şüpheli" }
                    ),
                );
                for nn in &jv.sd_notes {
                    line(&mut l, &format!("- {}", nn));
                }
                if !jv.sd_classes.is_empty() {
                    row(&mut l, "SD sınıfları", &join_l(&jv.sd_classes, 6, ", "));
                }
                line(&mut l, "geriye donuk: bu kod daha önce çalıştırılıp self-destruct yapıldıysa dosya diskte değiştirilmiş/silinmiş olabilir -> unload kaydı, bellek kalıntısı ve yetim thread (faz 3/4/6/9) aranır");
            }
        }
    }
    if a.zip_count > 0 || !a.classes.is_empty() {
        hdr(&mut l, "GÖMÜLÜ JAVA PAYLOAD");
        row(
            &mut l,
            "Arşiv",
            &format!(
                "{} gömülü ZIP/JAR, {} dosya girdisi, {} .class çözüldü",
                a.zip_count,
                a.zip_names.len(),
                a.classes.len()
            ),
        );
        let natives: i32 = a.classes.iter().map(|c| c.natives).sum();
        let cn: Vec<String> = a.classes.iter().map(|c| c.name.clone()).collect();
        row(&mut l, "Sınıflar", &join_l(&cn, 12, ", "));
        if natives != 0 {
            row(&mut l, "Native", &format!("{} native metot (JNI köprüsü)", natives));
        }
        if !a.pay_cat_labels[C_MOD_STRONG as usize].is_empty() || !a.pay_cat_labels[C_CLIENT_A as usize].is_empty() {
            row(
                &mut l,
                "Hile izi",
                &format!(
                    "{} {}",
                    join_l(&a.pay_cat_labels[C_MOD_STRONG as usize], 8, ", "),
                    join_l(&a.pay_cat_labels[C_CLIENT_A as usize], 4, ", ")
                ),
            );
        }
    }
    if !a.urls.is_empty() || !a.ips.is_empty() || !a.paths.is_empty() || !a.cmds.is_empty() || !a.regs.is_empty() {
        hdr(&mut l, "AĞ / YOL / KOMUT İZLERİ");
        if !a.urls.is_empty() {
            row(
                &mut l,
                "URL",
                &join_l(&a.urls.iter().cloned().collect::<Vec<_>>(), 5, ", "),
            );
        }
        if !a.ips.is_empty() {
            row(
                &mut l,
                "IP",
                &join_l(&a.ips.iter().cloned().collect::<Vec<_>>(), 5, ", "),
            );
        }
        if !a.paths.is_empty() {
            let all: Vec<String> = a.paths.iter().cloned().collect();
            let (mut first, rest): (Vec<String>, Vec<String>) =
                all.into_iter().partition(|s| lower_str(s).contains("\\users\\"));
            first.extend(rest);
            row(&mut l, "Yol", &join_l(&first, 5, ", "));
        }
        if !a.cmds.is_empty() {
            row(
                &mut l,
                "Komut",
                &join_l(&a.cmds.iter().cloned().collect::<Vec<_>>(), 4, ", "),
            );
        }
        if !a.regs.is_empty() {
            row(
                &mut l,
                "Kayıt",
                &join_l(&a.regs.iter().cloned().collect::<Vec<_>>(), 3, ", "),
            );
        }
    }
    hdr(&mut l, "KANITLAR / PUAN");
    for e in &a.ev {
        if e.cls != 'T' {
            line(&mut l, &format!("[{} +{}] {}", e.cls, e.w, e.text));
        }
    }
    if a.ev.is_empty() {
        line(&mut l, "kanıt yok");
    }
    row(
        &mut l,
        "Puan",
        &format!("S(anlamsal)={}  T(teknik)={}  H(gizlenme)={}", a.s, a.t, a.h),
    );
    row(
        &mut l,
        "KARAR",
        &format!("{}  --  {}", verdict_name(a.verdict), a.vreason),
    );
    l.push(format!("  +{}", "-".repeat(70)));
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_plain_text_hit() {
        let mut data = b"padding ".to_vec();
        data.extend_from_slice(b"LiquidBounce is here and KillAura AimAssist");
        let mut a = Analysis::default();
        analyze_buffer(&data, &AnalyzeOpts::default(), &mut a);
        assert!(a.cat_labels[C_CLIENT_A as usize].iter().any(|x| x == "LiquidBounce"));
        assert_ne!(a.verdict, Verdict::Clean);
        let r = render_analysis(&a);
        assert!(r.iter().any(|x| x.contains("KARAR")));
    }

    #[test]
    fn analyze_wide_and_clean() {
        let mut data = Vec::new();
        for c in "madebygrave".bytes() {
            data.push(c);
            data.push(0);
        }
        let mut a = Analysis::default();
        analyze_buffer(&data, &AnalyzeOpts::default(), &mut a);
        assert_eq!(a.verdict, Verdict::Confirmed);
        let mut b = Analysis::default();
        analyze_buffer(b"hello world nothing here", &AnalyzeOpts::default(), &mut b);
        assert_eq!(b.verdict, Verdict::Clean);
    }

    #[test]
    fn analyze_base64_class_payload() {
        let mut data = b"xx yv66vgAAADQ".to_vec();
        data.extend(std::iter::repeat(b'A').take(80));
        let mut a = Analysis::default();
        analyze_buffer(&data, &AnalyzeOpts::default(), &mut a);
    }
}
