use crate::analysis::*;
use crate::pat_data::*;
use crate::patterns::get_db;
use crate::util::*;
use std::collections::BTreeSet;

pub fn has_pat(a: &Analysis, norm_text: &str) -> bool {
    let db = get_db();
    a.hits.keys().any(|&k| db.pats[k as usize].text == norm_text.as_bytes())
}

pub fn imp_fn(a: &Analysis, lower: &str) -> bool {
    a.pe.imp_funcs.contains(lower)
}

pub fn join_l(v: &[String], max_n: usize, sep: &str) -> String {
    let mut s = String::new();
    let mut k = 0usize;
    for x in v {
        if k >= max_n {
            s.push_str(&format!("{}... +{}", sep, v.len() - max_n));
            break;
        }
        if k != 0 {
            s.push_str(sep);
        }
        s.push_str(x);
        k += 1;
    }
    s
}

fn jl(v: &[String], max_n: usize) -> String {
    join_l(v, max_n, ", ")
}

pub fn filter_exported_apis(a: &mut Analysis) {
    if !a.is_pe || a.pe.exps.is_empty() {
        return;
    }
    let db = get_db();
    let ex: Vec<Vec<u8>> = a.pe.exps.iter().map(|e| e.bytes().map(low_c).collect()).collect();
    let api_cats = [
        C_SD_UNLOAD,
        C_SD_FILEDEL,
        C_SD_MEMFREE,
        C_SD_EXEC,
        C_INJ,
        C_ANTIDBG,
        C_JNI,
        C_JVMTI,
        C_HOOKLIB,
        C_CLASSLDR,
    ];
    a.hits.retain(|&id, _| {
        let pi = &db.pats[id as usize];
        let mut drop = false;
        if api_cats.contains(&pi.cat) {
            for e in &ex {
                if memchr::memmem::find(e, &pi.text).is_some() {
                    drop = true;
                    break;
                }
            }
        }
        !drop
    });
}

pub fn build_cat_labels(a: &mut Analysis) {
    let db = get_db();
    for pass in 0..2 {
        let ids: Vec<i32> = if pass == 1 {
            a.phits.keys().copied().collect()
        } else {
            a.hits.keys().copied().collect()
        };
        for id in ids {
            let pi = &db.pats[id as usize];
            let lst = if pass == 1 {
                &mut a.pay_cat_labels[pi.cat as usize]
            } else {
                &mut a.cat_labels[pi.cat as usize]
            };
            let lb = pi.label.to_string();
            if !lst.contains(&lb) {
                lst.push(lb);
            }
        }
    }
}

pub fn build_sd(a: &mut Analysis) {
    let unload = has_pat(a, "freelibraryandexitthread")
        || ((has_pat(a, "freelibrary") || imp_fn(a, "freelibrary"))
            && (has_pat(a, "exitthread") || imp_fn(a, "exitthread")));
    let file_del = !a.cat_labels[C_SD_FILEDEL as usize].is_empty();
    let mem_wipe =
        ((has_pat(a, "rtlsecurezeromemory") || has_pat(a, "securezeromemory") || has_pat(a, "rtlzeromemory"))
            && has_pat(a, "virtualprotect"))
            || has_pat(a, "ntunmapviewofsection")
            || has_pat(a, "zwunmapviewofsection")
            || has_pat(a, "ntfreevirtualmemory");
    let cmd = has_pat(a, "cmd /c") || has_pat(a, "cmd.exe /c");
    let cmd_del = (cmd
        && (has_pat(a, "del /f")
            || has_pat(a, "del /q")
            || has_pat(a, "ping 127.0.0.1")
            || has_pat(a, "ping -n")
            || has_pat(a, "timeout /t")
            || has_pat(a, "attrib +h")))
        || has_pat(a, "remove-item");
    let peb_unlink = !a.cat_labels[C_SD_ANTIFOR as usize].is_empty();
    let sd_str = !a.cat_labels[C_SDSTR as usize].is_empty();
    let sd = &mut a.sd;
    sd.unload = unload;
    sd.file_del = file_del;
    sd.mem_wipe = mem_wipe;
    sd.cmd_del = cmd_del;
    sd.peb_unlink = peb_unlink;
    sd.sd_str = sd_str;
    let tech = sd.unload as i32 + (sd.file_del || sd.cmd_del) as i32 + sd.mem_wipe as i32 + sd.peb_unlink as i32;
    sd.level = tech;
    const NAMES: [&str; 5] = ["YOK / BELİRSİZ", "TEMEL", "ORTA", "İLERİ", "ÇOK İLERİ"];
    let li = tech.clamp(0, 4) as usize; // dizi sınırı: 0..4
    sd.level_name = NAMES[li].to_string();
    if tech == 0 && sd.sd_str {
        sd.level_name = "BELİRSİZ (self-destruct ifadesi var, yöntem görünmüyor)".to_string();
    }
    if sd.unload {
        sd.notes.push("Modül boşaltma: FreeLibrary(AndExitThread)/ExitThread -> DLL bellekten çıkar; DOSYA diskte KALIR, string/class kalıntıları heap'te kalabilir".into());
    }
    if sd.file_del {
        sd.notes.push("Dosya silme API'leri (DeleteFile/MoveFileEx/NtDeleteFile...) -> kendi dosyasını silebilir; disk izi yok, bellek kalıntısı + silinmiş-dosya yolu aranır".into());
    }
    if sd.cmd_del {
        sd.notes
            .push("Komut satırı ile gecikmeli silme (cmd /c del, ping/timeout) -> çıkış sonrası dosya silinir".into());
    }
    if sd.mem_wipe {
        sd.notes.push("Bellek/header temizleme (VirtualProtect + sıfırlama, UnmapViewOfSection) -> PE header ve imza stringleri bellekten silinir".into());
    }
    if sd.peb_unlink {
        sd.notes.push("PEB modül listesinden çıkarma/iz silme ifadeleri -> modül listesinde görünmez (VAD taraması ile yakalanır)".into());
    }
    if sd.sd_str {
        sd.notes
            .push("'selfdestruct/uninject/panic' ifadesi içeriyor (kullanıcı tetikli kaldırma özelliği)".into());
    }
}

pub fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Confirmed => "KESİN HİLE",
        Verdict::Suspect => "ŞÜPHELİ - İNCELE",
        Verdict::Info => "BİLGİ (kanıt yetersiz)",
        Verdict::Tool => "ARAÇ / İMZA VERİTABANI (hile değil)",
        Verdict::Clean => "TEMİZ",
    }
}

fn names_of(a: &Analysis, f: impl Fn(&crate::jbytecode::JBeh) -> bool) -> String {
    let mut nm = String::new();
    let mut c = 0;
    for b in &a.jv.beh {
        if f(b) {
            let ok = c < 6;
            c += 1;
            if ok {
                if !nm.is_empty() {
                    nm.push_str(", ");
                }
                nm.push_str(&b.module);
            }
        }
    }
    nm
}

pub fn decide(a: &mut Analysis) {
    let fam_w = a.fam_w;
    let n_a = a.cat_labels[C_CLIENT_A as usize].len() as i32;
    let k = a.cat_labels[C_MOD_STRONG as usize].len() as i32;
    a.strong_s = fam_w > 0 || n_a > 0 || k >= 3 || a.pdb_family;
    let exe_only = a.is_pe && !a.pe.is_dll;
    let mut v = Verdict::Clean;
    let why: String;
    if a.client_distinct >= 8 || a.has_marker {
        v = Verdict::Tool;
        why = format!(
            "{} farklı hile istemci adı içeriyor: imza veritabanı/tarayıcı/araç (hile değil)",
            a.client_distinct
        );
    } else if fam_w >= 100 {
        v = Verdict::Confirmed;
        why = "bilinen hile ailesi imzası (kesin)".to_string();
    } else if a.beh_red {
        let nm = names_of(a, |b| b.sev >= 3);
        v = Verdict::Confirmed;
        why = format!(
            "Java bytecode davranışı (obfuscation'a dayanıklı, Minecraft API kullanımı): {}",
            nm
        );
    } else if a.jv.sd_confirmed && (a.beh_yellow || a.s > 0) {
        v = Verdict::Confirmed;
        why = format!(
            "Java self-destruct mantığı (seviye {}) + hile davranışı/ifadeleri (S={})",
            a.jv.sd_level, a.s
        );
    } else if a.strong_s && a.t >= 15 {
        v = Verdict::Confirmed;
        why = format!("güçlü hile kanıtı (S={}) + JVM/Minecraft yeteneği (T={})", a.s, a.t);
    } else if a.s >= 20 && a.s + a.t >= 100 {
        v = Verdict::Confirmed;
        why = format!("anlamsal kanıt (S={}) + yüksek teknik uyum (T={})", a.s, a.t);
    } else if a.h > 0 && (a.strong_s || a.s >= 15 || a.t >= 40) {
        v = Verdict::Confirmed;
        why = format!(
            "gizlenme/yükleyici izi (H={}) + içerik kanıtı (S={}, T={})",
            a.h, a.s, a.t
        );
    } else if a.beh_yellow {
        let nm = names_of(a, |b| b.sev == 2);
        v = Verdict::Suspect;
        why = format!("Java bytecode davranışı (şüpheli, elle doğrulayın): {}", nm);
    } else if a.s >= 12 && a.t >= 25 && a.jvm_cap {
        v = Verdict::Suspect;
        why = format!(
            "anlamsal (S={}) + JVM/Minecraft teknik kanıtı (T={}) var ama kesin eşik altında",
            a.s, a.t
        );
    } else if a.strong_s {
        v = Verdict::Suspect;
        why = format!("güçlü hile ifadesi var (S={}) fakat JVM bağlantısı görünmüyor", a.s);
    } else if a.h > 0 {
        v = Verdict::Suspect;
        why = format!("gizlenme/yükleyici izi (H={}), içerik kanıtı yok", a.h);
    } else if a.t >= 50 && a.in_user_dir && a.jvm_cap {
        v = Verdict::Suspect;
        why = format!(
            "indirilenler/masaüstü/geçici dizinde imzasız, JVM+Minecraft yetenekli DLL (T={})",
            a.t
        );
    } else if a.s > 0 || a.t >= 25 {
        v = Verdict::Info;
        why = format!("zayıf/dolaylı kanıt (S={}, T={})", a.s, a.t);
    } else {
        why = "hile kanıtı yok".to_string();
    }
    let mut why = why;
    let names = a.cat_labels[C_CLIENT_A as usize].len() as i32
        + a.cat_labels[C_CLIENT_B as usize].len() as i32
        + k
        + a.cat_labels[C_MOD_WEAK as usize].len() as i32;
    if v != Verdict::Tool && !a.jvm_cap && names >= 12 {
        v = Verdict::Tool;
        why = format!(
            "{} farklı hile adı/modül adı içeriyor ve JVM bağlantısı yok: imza listesi/analiz aracı (hile değil)",
            names
        );
    }
    if exe_only && v >= Verdict::Suspect && !a.jvm_cap && !(fam_w >= 100 || a.pdb_family) {
        v = Verdict::Info;
        why = "EXE ve JVM bağlantısı yok: analiz aracı/yükleyici olabilir (hile DLL'i değil)".to_string();
    }
    if exe_only && v == Verdict::Confirmed && !(fam_w >= 100 || n_a > 0) {
        v = Verdict::Suspect;
        why.push_str(" [EXE: kesin sayılmadı]");
    }
    if a.jv.server_plugin && v != Verdict::Tool && !a.beh_red && v >= Verdict::Suspect {
        v = Verdict::Info;
        why = "sunucu eklentisi (plugin.yml/bungee.yml): hile adları anti-cheat kontrol listesi olabilir; istemci hilesi değil".to_string();
    }
    if a.benign_jvm && v != Verdict::Tool && !a.strong_s {
        v = Verdict::Clean;
        why = "JVM/JDK yerel bileşeni (export tablosundan doğrulandı: JNI_CreateJavaVM/JVM_*/Java_java_*)".to_string();
    }
    if a.benign_cef && v != Verdict::Tool && a.fam_w == 0 && !a.pdb_family {
        v = Verdict::Clean;
        why = format!(
            "Chromium Embedded Framework (CEF/MCEF - Minecraft gömülü tarayıcı): export tablosunda {} adet cef_* API (hile değil)",
            a.pe.exp_cef
        );
    }
    if a.trusted && v != Verdict::Tool {
        v = Verdict::Clean;
        why = format!("güvenilir yayıncı imzası: {}", a.sig_text);
    }
    a.verdict = v;
    a.vreason = why;
}

pub fn score(a: &mut Analysis) {
    let db = get_db();
    let n_c = |a: &Analysis, c: u8| a.cat_labels[c as usize].len() as i32;
    a.client_distinct = n_c(a, C_CLIENT_A) + n_c(a, C_CLIENT_B);
    let mut fam_w: i32 = 0;
    let mut fam_l: Vec<String> = Vec::new();
    {
        let mut seen_f: BTreeSet<i32> = BTreeSet::new();
        for pass in 0..2 {
            let ids: Vec<i32> = if pass == 1 {
                a.phits.keys().copied().collect()
            } else {
                a.hits.keys().copied().collect()
            };
            for id in ids {
                let pi = &db.pats[id as usize];
                if pi.cat == C_FAMILY && !seen_f.contains(&id) {
                    seen_f.insert(id);
                    fam_w += pi.w as i32;
                    fam_l.push(pi.label.to_string());
                }
            }
        }
    }
    fam_w = fam_w.min(100);
    a.fam_strong = fam_w >= 100;
    if fam_w > 0 {
        add_ev(a, 'S', fam_w, &format!("Bilinen hile ailesi imzası: {}", jl(&fam_l, 4)));
    }
    let n_a = n_c(a, C_CLIENT_A);
    let n_b = n_c(a, C_CLIENT_B);
    let k = n_c(a, C_MOD_STRONG);
    let w = n_c(a, C_MOD_WEAK);
    let op = n_c(a, C_OPT);
    let mc = a.mc_refs.len() as i32;
    if n_a >= 1 {
        let t = format!("Hile istemci adı: {}", jl(&a.cat_labels[C_CLIENT_A as usize], 5));
        add_ev(a, 'S', (60 + 10 * (n_a - 1)).min(100), &t);
    }
    if n_b >= 3 {
        let t = format!(
            "Genel hile istemci adları kümesi: {}",
            jl(&a.cat_labels[C_CLIENT_B as usize], 5)
        );
        add_ev(a, 'S', 45, &t);
    } else if n_b == 2 {
        let t = format!(
            "Genel hile istemci adları: {}",
            jl(&a.cat_labels[C_CLIENT_B as usize], 3)
        );
        add_ev(a, 'S', 25, &t);
    } else if n_b == 1 {
        let t = format!(
            "Genel istemci adı (zayıf): {}",
            jl(&a.cat_labels[C_CLIENT_B as usize], 1)
        );
        add_ev(a, 'S', 6, &t);
    }
    if k >= 1 {
        const TAB: [i32; 5] = [0, 4, 12, 28, 44];
        let ws = if k >= 5 {
            60 + (k - 5).min(5) * 2
        } else {
            TAB[k as usize]
        };
        let t = format!(
            "{} güçlü hile modülü adı: {}",
            k,
            jl(&a.cat_labels[C_MOD_STRONG as usize], 8)
        );
        add_ev(a, 'S', ws, &t);
    }
    if w >= 1 && (k >= 1 || mc > 0) {
        let t = format!("{} zayıf modül adı: {}", w, jl(&a.cat_labels[C_MOD_WEAK as usize], 6));
        add_ev(a, 'S', (2 * w).min(12), &t);
    }
    if op >= 6 {
        let t = format!("{} savaş ayar etiketi: {}", op, jl(&a.cat_labels[C_OPT as usize], 6));
        add_ev(a, 'S', 18, &t);
    } else if op >= 3 {
        let t = format!("{} savaş ayar etiketi: {}", op, jl(&a.cat_labels[C_OPT as usize], 6));
        add_ev(a, 'S', 12, &t);
    }
    if n_c(a, C_SDSTR) >= 1 {
        let t = format!("Self-destruct ifadesi: {}", jl(&a.cat_labels[C_SDSTR as usize], 4));
        add_ev(a, 'S', 15, &t);
    }
    if n_c(a, C_GUICHEAT) >= 1 {
        let t = format!("Hile GUI ifadesi: {}", jl(&a.cat_labels[C_GUICHEAT as usize], 4));
        add_ev(a, 'S', 12, &t);
    }
    {
        let mut nw = 0;
        let mut nl: Vec<String> = Vec::new();
        for l in &a.cat_labels[C_NET as usize] {
            let ww = if l.contains("KeyAuth") {
                20
            } else if l.contains("webhook") {
                15
            } else {
                6
            };
            nw += ww;
            nl.push(l.clone());
        }
        if nw > 0 {
            add_ev(
                a,
                'S',
                nw.min(40),
                &format!("Lisans/HWID/webhook izleri: {}", jl(&nl, 5)),
            );
        }
    }
    if a.pdb_family {
        let t = format!(
            "PDB yolu bilinen hile tabanını gösteriyor (custom-base): {}",
            trunc(&a.pe.pdb, 110)
        );
        add_ev(a, 'S', 35, &t);
    }
    if a.pdb_sus {
        let t = format!("PDB yolu hile/enjeksiyon ifadesi içeriyor: {}", trunc(&a.pe.pdb, 110));
        add_ev(a, 'S', 25, &t);
    }
    {
        let pa = a.pay_cat_labels[C_CLIENT_A as usize].len();
        let pk = a.pay_cat_labels[C_MOD_STRONG as usize].len();
        let pf = a.pay_cat_labels[C_FAMILY as usize].len();
        let po = a.pay_cat_labels[C_OPT as usize].len();
        if pa >= 1 || pk >= 2 || pf >= 1 || po >= 3 {
            let mut all: Vec<String> = Vec::new();
            for c in [C_FAMILY, C_CLIENT_A, C_MOD_STRONG, C_OPT] {
                for l in &a.pay_cat_labels[c as usize] {
                    all.push(l.clone());
                }
            }
            let t = format!(
                "Gömülü Java payload ({} sınıf) hile ifadeleri içeriyor: {}",
                a.classes.len(),
                jl(&all, 8)
            );
            add_ev(a, 'S', 30, &t);
        }
    }
    let jvm_import = a.pe.imp_dlls.contains("jvm.dll");
    let jni_str = has_pat(a, "getcreatedjavavms") || has_pat(a, "attachcurrentthread") || has_pat(a, "jvm.dll");
    a.jvm_cap = jvm_import || jni_str || a.jvmti_const || mc >= 3;
    if a.bypass_const && (jvm_import || jni_str || mc > 0) {
        add_ev(a, 'S', 40, "Örnek koddaki 'bypass' sabiti 0xFCE01E99 (javaw belleğindeki işareti sıfırlayan anti-tespit) kodda bulundu");
    }
    if jvm_import {
        add_ev(
            a,
            'T',
            25,
            "jvm.dll IMPORT tablosunda -> JNI_GetCreatedJavaVMs ile doğrudan çalışan JVM'e bağlanır",
        );
    } else if jni_str {
        let t = format!("JVM bağlantı stringleri: {}", jl(&a.cat_labels[C_JNI as usize], 3));
        add_ev(a, 'T', 12, &t);
    }
    if a.jvmti_const {
        let t = format!(
            "JVMTI GetEnv sürüm sabiti (0x{:08X}) -> çalışan JVM'e JVMTI ile bağlanma (sınıf tarama/kanca)",
            a.jvmti_ver
        );
        add_ev(a, 'T', 20, &t);
    }
    if n_c(a, C_JVMTI) >= 1 {
        let t = format!("JVMTI ifadeleri: {}", jl(&a.cat_labels[C_JVMTI as usize], 4));
        add_ev(a, 'T', 8, &t);
    }
    if mc >= 10 {
        add_ev(
            a,
            'T',
            35,
            &format!(
                "{} Minecraft sınıf referansı -> yerel kod Minecraft iç sınıflarına erişiyor",
                mc
            ),
        );
    } else if mc >= 3 {
        add_ev(a, 'T', 20, &format!("{} Minecraft sınıf referansı", mc));
    } else if mc >= 1 {
        add_ev(a, 'T', 8, &format!("{} Minecraft sınıf referansı", mc));
    }
    if a.srg.len() >= 3 {
        let t = format!(
            "{} obfuscate Minecraft adı (field_/method_/class_ eşlemeleri)",
            a.srg.len()
        );
        add_ev(a, 'T', 8, &t);
    }
    if n_c(a, C_MCNAME) >= 2 {
        let t = format!("Minecraft iç adları: {}", jl(&a.cat_labels[C_MCNAME as usize], 5));
        add_ev(a, 'T', 8, &t);
    }
    if a.jni_desc_count >= 5 {
        let t = format!("{} JNI metot imzası stringi", a.jni_desc_count);
        add_ev(a, 'T', 6, &t);
    }
    if n_c(a, C_CLASSLDR) >= 2 {
        let t = format!(
            "Java ClassLoader manipülasyonu: {}",
            jl(&a.cat_labels[C_CLASSLDR as usize], 4)
        );
        add_ev(a, 'T', 8, &t);
    }
    {
        let mut hs = 0;
        let mut hl: Vec<String> = Vec::new();
        if has_pat(a, "wglswapbuffers") {
            hs += 10;
            hl.push("wglSwapBuffers".into());
        }
        if has_pat(a, "mh_initialize") || has_pat(a, "mh_createhook") || has_pat(a, "mh_enablehook") {
            hs += 6;
            hl.push("MinHook".into());
        }
        if has_pat(a, "detourattach") || has_pat(a, "detourtransactionbegin") {
            hs += 4;
            hl.push("Detours".into());
        }
        if has_pat(a, "kiero") {
            hs += 4;
            hl.push("kiero".into());
        }
        if has_pat(a, "polyhook") || has_pat(a, "subhook") || has_pat(a, "safetyhook") || has_pat(a, "funchook") {
            hs += 6;
            hl.push("PolyHook/SubHook/SafetyHook/funchook".into());
        }
        if has_pat(a, "glfwswapbuffers") {
            hs += 6;
            hl.push("glfwSwapBuffers".into());
        }
        if hs != 0 {
            add_ev(
                a,
                'T',
                hs.min(20),
                &format!("Hook kütüphanesi/oyun çizim kancası: {}", jl(&hl, 4)),
            );
        }
    }
    if n_c(a, C_IMGUI) >= 1 {
        add_ev(a, 'T', 10, "ImGui GUI kütüphanesi (hile menüsü)");
    }
    if imp_fn(a, "wglcreatecontext")
        && imp_fn(a, "wglmakecurrent")
        && (imp_fn(a, "setwindowlongptra") || imp_fn(a, "setwindowlongptrw") || imp_fn(a, "setwindowlonga"))
    {
        add_ev(
            a,
            'T',
            6,
            "OpenGL bağlamı + pencere WndProc kancası importları (oyun üstüne GUI çizme)",
        );
    }
    if a.sd.level > 0 {
        let t = format!("Self-destruct yeteneği: seviye {} ({})", a.sd.level, a.sd.level_name);
        add_ev(a, 'T', (6 * a.sd.level).min(24), &t);
    }
    if !a.keys.is_empty() {
        let t = format!(
            "{} tuş yoklama/kısayol noktası (GetAsyncKeyState/RegisterHotKey/WM_KEYDOWN)",
            a.keys.len()
        );
        add_ev(a, 'T', 4, &t);
    }
    if n_c(a, C_INJ) >= 2 {
        let t = format!("Enjeksiyon API'leri: {}", jl(&a.cat_labels[C_INJ as usize], 4));
        add_ev(a, 'T', 8, &t);
    }
    if n_c(a, C_ANTIDBG) >= 1 {
        let t = format!("Analiz-engelleme: {}", jl(&a.cat_labels[C_ANTIDBG as usize], 4));
        add_ev(a, 'T', (3 * n_c(a, C_ANTIDBG)).min(9), &t);
    }
    if !a.packer.is_empty() {
        let t = format!("Paketleyici/koruyucu: {}", a.packer);
        add_ev(a, 'T', if a.packer_strong { 20 } else { 8 }, &t);
    }
    if a.peb_walk && a.fnv_hash {
        add_ev(
            a,
            'T',
            8,
            "API-hash ile gizli import çözümleme (PEB erişimi + FNV; lazy_importer benzeri)",
        );
    } else if a.peb_walk {
        add_ev(a, 'T', 3, "Doğrudan PEB erişimi (gs:[60h])");
    }
    if a.jv.analyzed {
        let mut shown = 0;
        let beh = a.jv.beh.clone();
        for b in &beh {
            let stop = shown >= 8;
            shown += 1;
            if stop {
                break;
            }
            let t = format!(
                "{}{}  [sınıf {}{}]  {}",
                if b.sev >= 3 {
                    "Java davranışı (KESİN): "
                } else {
                    "Java davranışı (şüpheli): "
                },
                b.module,
                trunc(&b.cls, 56),
                if b.indirect {
                    ", yardımcı sınıflar üzerinden"
                } else {
                    ""
                },
                trunc(&b.why, 160)
            );
            add_ev(a, 'S', if b.sev >= 3 { 55 } else { 14 }, &t);
        }
        if a.jv.sd_confirmed {
            let first = match a.jv.sd_notes.first() {
                None => "bkz. SELF-DESTRUCT ANALİZİ".to_string(),
                Some(n) => trunc(n, 150),
            };
            let t = format!("Java self-destruct mantığı var (seviye {}): {}", a.jv.sd_level, first);
            add_ev(a, 'H', 45, &t);
        } else if a.jv.sd_suspect {
            let first = match a.jv.sd_notes.first() {
                None => "bkz. SELF-DESTRUCT ANALİZİ".to_string(),
                Some(n) => trunc(n, 150),
            };
            add_ev(a, 'H', 20, &format!("Java self-destruct belirtisi: {}", first));
        }
        if a.jv.obfuscated && a.jv.third_party >= 12 {
            let t = format!("Java obfuscation: {}", a.jv.obf_note);
            add_ev(a, 'T', 10, &t);
        }
        if a.jv.agent {
            add_ev(
                a,
                'T',
                8,
                "JAR bir Java ajanı (Premain-Class/Agent-Class): çalışan JVM'e sınıf enjekte edebilir",
            );
        }
        if a.jv.natives > 0 && a.jv.third_party > 0 {
            let t = format!("JAR içinde {} native metot (JNI köprüsü)", a.jv.natives);
            add_ev(a, 'T', 6, &t);
        }
    }
    a.fam_w = fam_w;
    decide(a);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join() {
        let v: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        assert_eq!(join_l(&v, 2, ", "), "a, b, ... +1");
        assert_eq!(join_l(&v, 5, ", "), "a, b, c");
    }
    #[test]
    fn clean_default() {
        let mut a = Analysis::default();
        decide(&mut a);
        assert_eq!(a.verdict, Verdict::Clean);
        assert_eq!(a.vreason, "hile kanıtı yok");
        a.s = 5;
        decide(&mut a);
        assert_eq!(a.verdict, Verdict::Info);
        a.client_distinct = 8;
        decide(&mut a);
        assert_eq!(a.verdict, Verdict::Tool);
    }
    #[test]
    fn confirmed_by_family() {
        let mut a = Analysis::default();
        a.fam_w = 100;
        decide(&mut a);
        assert_eq!(a.verdict, Verdict::Confirmed);
        a.trusted = true;
        decide(&mut a);
        assert_eq!(a.verdict, Verdict::Clean);
    }
    #[test]
    fn sd_levels() {
        let mut a = Analysis::default();
        a.cat_labels[C_SDSTR as usize].push("x".into());
        build_sd(&mut a);
        assert_eq!(a.sd.level, 0);
        assert!(a.sd.level_name.starts_with("BELİRSİZ"));
    }
}
