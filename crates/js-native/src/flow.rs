use crate::analysis::*;
use crate::ctx::*;
use crate::jbytecode::java_beh_line;
use crate::pat_data::*;
use crate::patterns::get_db;
use crate::phases::*;
use crate::score::*;
use crate::util::*;
use crate::winutil::*;
use std::collections::BTreeMap;
use std::sync::Arc;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;

fn addr_of(f: &Finding, tag: &str) -> String {
    if f.path.starts_with(tag) {
        f.path[tag.len()..].to_string()
    } else {
        String::new()
    }
}

pub fn finding_type_name(f: &Finding) -> &'static str {
    let h = |k: &str| kind_has(f, k);
    if h("UNBACKED THREAD") || h("YETİM THREAD") || h("UNBACKED BELLEK") {
        return "UNBACKED THREAD";
    }
    if h("YENİDEN ADLANDIRILMIŞ") {
        return "JVM ADI GİZLEME";
    }
    if h("API HOOK") || h("API YAMASI") {
        return "API HOOK";
    }
    if h("GİZLİ") {
        return "GİZLİ DLL";
    }
    if h("YÜKLÜ MODÜL") {
        return "DLL (aktif)";
    }
    if h("BOŞALTILMIŞ") {
        return "BOŞALTILMIŞ DLL";
    }
    if h("HEAP") || h("BELLEK") || h("ENJEKSİYON") || h("HANDLE") || h("KERNEL") {
        return "BELLEK İZİ";
    }
    if h("DİSK") {
        return "DİSK DOSYASI";
    }
    "DİĞER"
}

pub fn sd_evidence(f: &Finding, out: &mut Vec<String>) {
    if kind_has(f, "BOŞALTILMIŞ MODÜL") {
        out.push("javaw'dan BOŞALTILMIŞ modül (ntdll unload kaydı): kod çalışıp bellekten çıkarılmış".into());
    }
    if kind_has(f, "YETİM THREAD") {
        out.push("thread sürüyor ama başlangıç kodu bellekten silinmiş".into());
    }
    if kind_has(f, "ENJEKSİYON YOLU") && kind_has(f, "silinmiş") {
        out.push("enjeksiyon yolu bellekte, DLL dosyası diskten silinmiş".into());
    }
    if let Some(a) = &f.an {
        if a.sd.level > 0 || a.sd.sd_str {
            out.push(format!(
                "kodunda self-destruct yeteneği (seviye {}/4 - {})",
                a.sd.level, a.sd.level_name
            ));
        }
        if a.jv.sd_confirmed || a.jv.sd_suspect {
            let mut s = format!(
                "Java kodunda self-destruct mantığı (seviye {}, {})",
                a.jv.sd_level,
                if a.jv.sd_confirmed { "KESİN" } else { "şüpheli" }
            );
            if let Some(n) = a.jv.sd_notes.first() {
                s.push_str(&format!(": {}", trunc(n, 130)));
            }
            out.push(s);
        }
        for k in &a.keys {
            if k.exit_branch {
                out.push(format!(
                    "tetik tuşu: {} ({}) koşullu atlama modül boşaltmaya gidiyor",
                    vk_name(k.vk),
                    k.api
                ));
                break;
            }
        }
    }
    if !f.remnants.is_empty() {
        out.push(format!(
            "modül artık yüklü değil ama {} ortak string javaw heap'inde duruyor (bellek kalıntısı)",
            f.remnants.len()
        ));
    }
}

fn is_file_path(f: &Finding) -> bool {
    !f.path.is_empty() && !f.path.starts_with('<')
}

impl Ctx {
    pub fn phase_correlate(&mut self) {
        self.begin_phase(9, "Korelasyon (disk <-> javaw izleri)");
        let mut links = 0;
        let mut worst = Verdict::Clean;
        let db = get_db();
        let unl = self.unloaded.clone();
        for ur in &unl {
            if ur.cls != "unknown" {
                continue;
            }
            let un = lower_w(&ur.e.name);
            for i in 0..self.findings.len() {
                let (an, path) = {
                    let f = &self.findings[i];
                    (f.an.clone(), f.path.clone())
                };
                let Some(an) = an else { continue };
                if path.is_empty() || path.starts_with('<') || !an.is_pe {
                    continue;
                }
                if !(an.s > 0 || an.t >= 25 || an.verdict >= Verdict::Suspect) {
                    continue;
                }
                let pe = &an.pe;
                let exact = pe.timestamp == ur.e.ts
                    && pe.size_of_image as u64 == ur.e.size
                    && (ur.e.checksum == 0 || pe.checksum == 0 || pe.checksum == ur.e.checksum);
                let bn = lower_w(&base_name(&path));
                let bnc: String = if bn.chars().count() > 31 {
                    bn.chars().take(31).collect()
                } else {
                    bn.clone()
                };
                let name_eq = bn == un || bnc == un;
                if !exact && !name_eq {
                    continue;
                }
                let tag = format!("unload kaydı #{}", ur.e.seq);
                if self.findings[i].notes.iter().any(|n| n.contains(&tag)) {
                    continue;
                }
                let mut b = (*an).clone();
                add_ev(
                    &mut b,
                    'H',
                    if exact { 45 } else { 25 },
                    &format!(
                        "javaw unload kaydında '{}' (taban {}, boyut {}, PE zamanı {}) bu dosyayla {}: dosya javaw'a yüklenmiş ve BOŞALTILMIŞ (self-destruct izi)",
                        ur.e.name,
                        addr_s(ur.e.base),
                        fmt_size(ur.e.size),
                        fmt_time(ur.e.ts),
                        if exact { "BİREBİR eşleşiyor (zaman damgası + boyut)" } else { "ad olarak eşleşiyor" }
                    ),
                );
                decide(&mut b);
                self.findings[i].an = Some(Arc::new(b));
                self.refresh_dict(i);
                let f = &mut self.findings[i];
                if !f.kinds.iter().any(|k| k.contains("BOŞALTILMIŞ MODÜL KAYDI")) {
                    f.kinds.push("BOŞALTILMIŞ MODÜL KAYDI (self-destruct izi)".into());
                }
                f.notes.push(format!(
                    "{}: '{}' boşaltıldı (PE zamanı {}, boyut {}) -> {}",
                    tag,
                    ur.e.name,
                    fmt_time(ur.e.ts),
                    fmt_size(ur.e.size),
                    if exact { "birebir eşleşme" } else { "ad eşleşmesi" }
                ));
                links += 1;
                if f.verd() > worst {
                    worst = f.verd();
                }
            }
        }
        if !self.heap_pats.is_empty() {
            for i in 0..self.findings.len() {
                let (an, path) = {
                    let f = &self.findings[i];
                    (f.an.clone(), f.path.clone())
                };
                let Some(an) = an else { continue };
                if path.is_empty() || path.starts_with('<') {
                    continue;
                }
                if an.verdict < Verdict::Suspect && an.s == 0 {
                    continue;
                }
                let mut shared: Vec<String> = Vec::new();
                let mut fam_or_client = false;
                for k in an.hits.keys() {
                    let Some(hp) = self.heap_pats.get(k) else { continue };
                    let pi = &db.pats[*k as usize];
                    shared.push(format!(
                        "\"{}\" x{}  {}  [{}]",
                        pi.label,
                        hp.count,
                        addr_s(hp.first),
                        hp.reg
                    ));
                    if pi.cat == C_FAMILY || pi.cat == C_CLIENT_A {
                        fam_or_client = true;
                    }
                }
                if !(shared.len() >= 2 || fam_or_client) {
                    continue;
                }
                if self.findings[i].remnants.is_empty() {
                    for sh in &shared {
                        if self.findings[i].remnants.len() < 12 {
                            self.findings[i].remnants.push(sh.clone());
                        }
                    }
                }
                if !self.findings[i].loaded {
                    if self.findings[i]
                        .notes
                        .iter()
                        .any(|n| n.contains("heap'te ortak string"))
                    {
                        continue;
                    }
                    let mut b = (*an).clone();
                    add_ev(
                        &mut b,
                        'H',
                        35,
                        &format!("Bu dosyanın {} ayırt edici stringi javaw HEAP'inde bulundu (modül artık yüklü değil): çalıştırılıp bellekten çıkarılmış (self-destruct) -> kaynak dosya bu", shared.len()),
                    );
                    decide(&mut b);
                    self.findings[i].an = Some(Arc::new(b));
                    self.refresh_dict(i);
                    self.findings[i].notes.push(format!(
                        "heap'te ortak string: {} (kaynak dosya doğrulandı)",
                        shared.len()
                    ));
                    links += 1;
                    if self.findings[i].verd() > worst {
                        worst = self.findings[i].verd();
                    }
                }
            }
        }
        {
            for i in 0..self.findings.len() {
                if !kind_has(&self.findings[i], "UNBACKED THREAD") {
                    continue;
                }
                let a = addr_of(&self.findings[i], "<bellek ");
                if a.is_empty() {
                    continue;
                }
                for j in 0..self.findings.len() {
                    if !kind_has(&self.findings[j], "API HOOK") {
                        continue;
                    }
                    if addr_of(&self.findings[j], "<hook-hedefi ") != a {
                        continue;
                    }
                    self.findings[i].v_override = Some(Verdict::Confirmed);
                    self.findings[j].v_override = Some(Verdict::Confirmed);
                    let a2 = &a[..a.len() - 1];
                    self.findings[i].notes.push(format!(
                        "aynı bellek bölgesi ({}) ayrıca sistem API hook hedefi: enjekte edilmiş kod + thread + kanca",
                        a2
                    ));
                    self.findings[j].notes.push(
                        "bu bölgede ayrıca DOSYASIZ BELLEKTE ÇALIŞAN THREAD var: enjekte edilmiş kod + thread + kanca"
                            .into(),
                    );
                    links += 1;
                    worst = Verdict::Confirmed;
                }
            }
        }
        let summary = if links != 0 {
            format!("{} eşleşme: javaw'daki iz <-> diskteki dosya", links)
        } else {
            "eşleşme yok".to_string()
        };
        let col = if links != 0 {
            if worst == Verdict::Confirmed {
                COL_RED
            } else {
                COL_YEL
            }
        } else {
            COL_GRN
        };
        self.end_phase_guard(&summary, col);
    }

    fn print_rows(&mut self, v: &[usize], col: usize, tag: &str) {
        let mut num = 0usize;
        for &i in v {
            num += 1;
            if num > 150 {
                self.out_now(
                    &format!(
                        "   ... +{} bulgu daha (--log=DOSYA ile tamamını kaydedin)",
                        v.len() - 150
                    ),
                    COL_GRY,
                );
                break;
            }
            let f = self.findings[i].clone();
            let is_file = is_file_path(&f);
            let mut name = if is_file { base_name(&f.path) } else { f.title.clone() };
            if is_file {
                if let Some(a) = &f.an {
                    if a.jv.analyzed && !(a.jv.mod_name.is_empty() && a.jv.mod_id.is_empty()) {
                        name.push_str(&format!(
                            "  ({}{})",
                            if a.jv.mod_name.is_empty() {
                                &a.jv.mod_id
                            } else {
                                &a.jv.mod_name
                            },
                            if a.jv.mod_ver.is_empty() {
                                String::new()
                            } else {
                                format!(" {}", a.jv.mod_ver)
                            }
                        ));
                    }
                }
            }
            self.out_now(
                &format!("  [{}{}] {}   <{}>", tag, num, trunc(&name, 100), finding_type_name(&f)),
                col,
            );
            if is_file {
                self.out_now(&format!("        dosya  : {}", trunc(&f.path, 150)), COL_DEF);
            }
            self.out_now(&format!("        yer    : {}", where_text(&f)), COL_DEF);
            let why = why_of(&f);
            if !why.is_empty() {
                self.out_now(&format!("        neden  : {}", trunc(&why, 170)), COL_DEF);
            }
            if let Some(n0) = f.notes.first() {
                if !n0.starts_with("kaynak:") {
                    let more = if f.notes.len() > 1 {
                        format!("  (+{} not daha)", f.notes.len() - 1)
                    } else {
                        String::new()
                    };
                    self.out_now(&format!("        not    : {}{}", trunc(n0, 170), more), COL_DEF);
                }
            }
            if let Some(a) = &f.an {
                if a.jv.analyzed && !a.jv.beh.is_empty() {
                    self.out_now(&format!("        modüller: {}", java_beh_line(&a.jv, 8)), col);
                }
            }
            let mut sd = Vec::new();
            sd_evidence(&f, &mut sd);
            if !sd.is_empty() {
                let more = if sd.len() > 1 {
                    format!("  (+{} kanıt daha)", sd.len() - 1)
                } else {
                    String::new()
                };
                self.out_now(&format!("        SELF-DESTRUCT: {}{}", trunc(&sd[0], 150), more), col);
            }
        }
    }

    pub fn print_consolidated(&mut self) {
        let mut reds: Vec<usize> = Vec::new();
        let mut yels: Vec<usize> = Vec::new();
        for (i, f) in self.findings.iter().enumerate() {
            match f.verd() {
                Verdict::Confirmed => reds.push(i),
                Verdict::Suspect => yels.push(i),
                _ => {}
            }
        }
        let names: Vec<&'static str> = self.findings.iter().map(finding_type_name).collect();
        reds.sort_by(|&a, &b| names[a].cmp(names[b]));
        yels.sort_by(|&a, &b| names[a].cmp(names[b]));
        self.out_now("", COL_DEF);
        self.out_now(
            "==============================================================================",
            COL_CYN,
        );
        self.out_now("  TOPLU SONUÇ TABLOSU  -  tüm arama türlerinin birleşik özeti", COL_CYN);
        self.out_now(
            "==============================================================================",
            COL_CYN,
        );
        if reds.is_empty() {
            self.out_now("  KIRMIZI (KESİN HİLE): 0", COL_GRN);
        } else {
            self.out_now(&format!("  KIRMIZI - HİLE (KESİN): {}", reds.len()), COL_RED);
            self.print_rows(&reds, COL_RED, "K");
        }
        self.out_now("", COL_DEF);
        if yels.is_empty() {
            self.out_now("  SARI (ŞÜPHELİ): 0", COL_GRN);
        } else {
            self.out_now(&format!("  SARI - ŞÜPHELİ (elle doğrulayın): {}", yels.len()), COL_YEL);
            self.print_rows(&yels, COL_YEL, "S");
        }
        {
            let mut by_t: BTreeMap<&'static str, (i32, i32)> = BTreeMap::new();
            for &i in &reds {
                by_t.entry(names[i]).or_default().0 += 1;
            }
            for &i in &yels {
                by_t.entry(names[i]).or_default().1 += 1;
            }
            if !by_t.is_empty() {
                self.out_now("", COL_DEF);
                self.out_now("  Tür bazında: ", COL_GRY);
                for (k, v) in &by_t {
                    self.out_now(
                        &format!("   {:<18} kırmızı: {:<3} sarı: {}", k, v.0, v.1),
                        if v.0 != 0 { COL_RED } else { COL_YEL },
                    );
                }
            }
        }
        {
            let mut sdl: Vec<(String, Vec<String>)> = Vec::new();
            for f in &self.findings {
                if f.verd() < Verdict::Suspect {
                    continue;
                }
                let mut ev = Vec::new();
                sd_evidence(f, &mut ev);
                if !ev.is_empty() {
                    sdl.push((
                        if is_file_path(f) {
                            base_name(&f.path)
                        } else {
                            f.title.clone()
                        },
                        ev,
                    ));
                }
            }
            let unk: Vec<String> = self
                .unloaded
                .iter()
                .filter(|u| u.cls == "unknown")
                .map(|u| u.e.name.clone())
                .collect();
            self.out_now("", COL_DEF);
            self.out_now("  SELF-DESTRUCT / GEÇMİŞ (geriye donuk) ANALİZ:", COL_CYN);
            if sdl.is_empty() && unk.is_empty() {
                self.out_now("   self-destruct izi bulunmadı (modül boşaltma kaydı, yetim thread, bellek kalıntısı, DLL self-destruct mantığı).", COL_GRN);
            }
            for s in &sdl {
                self.out_now(&format!("   * {}", trunc(&s.0, 90)), COL_RED);
                for (k, e) in s.1.iter().enumerate() {
                    if k >= 4 {
                        break;
                    }
                    self.out_now(&format!("       - {}", trunc(e, 160)), COL_DEF);
                }
            }
            if !unk.is_empty() {
                self.out_now(
                    &format!(
                        "   javaw unload kaydında sistem dışı modül(ler): {}",
                        join_l(&unk, 6, ", ")
                    ),
                    COL_YEL,
                );
            }
        }
        self.out_now("", COL_DEF);
        self.out_now("  ARAMA TÜRLERİ:", COL_CYN);
        for n in 1..=PHASES {
            let st = self.phase_state[n];
            self.out_now(
                &format!(
                    "   [{}] {:>2}. {}{}",
                    if st == 1 { '+' } else { '-' },
                    n,
                    PHASE_NAMES[n],
                    if st == 1 { "" } else { "   (atlandı)" }
                ),
                if st == 1 { COL_GRY } else { COL_YEL },
            );
        }
    }

    pub fn print_verdict(&mut self, javaw_found: bool) -> i32 {
        let (mut n_c, mut n_s) = (0, 0);
        let (mut active, mut unloaded, mut mem, mut disk) = (false, false, false, false);
        for f in &self.findings {
            let v = f.verd();
            if v == Verdict::Confirmed {
                n_c += 1;
            } else if v == Verdict::Suspect {
                n_s += 1;
            }
            if v < Verdict::Suspect {
                continue;
            }
            for k in &f.kinds {
                if [
                    "YÜKLÜ MODÜL",
                    "GİZLİ",
                    "MODÜL DIŞI THREAD",
                    "UNBACKED THREAD",
                    "API HOOK",
                    "API YAMASI",
                ]
                .iter()
                .any(|x| k.contains(x))
                {
                    active = true;
                }
                if k.contains("BOŞALTILMIŞ") || k.contains("YETİM THREAD") {
                    unloaded = true;
                }
                if ["BELLEK", "ENJEKSİYON", "HEAP", "HANDLE", "KERNEL"]
                    .iter()
                    .any(|x| k.contains(x))
                {
                    mem = true;
                }
                if k.contains("DİSK") {
                    disk = true;
                }
            }
            if let Some(a) = &f.an {
                if a.jv.sd_confirmed {
                    unloaded = true;
                }
            }
        }
        let mut ran = 0;
        let mut skipped = String::new();
        for n in 1..=PHASES {
            if self.phase_state[n] == 1 {
                ran += 1;
            } else {
                if !skipped.is_empty() {
                    skipped.push(',');
                }
                skipped.push_str(&n.to_string());
            }
        }
        let nothing = ran == 0 && n_c == 0 && n_s == 0;
        let col = if n_c != 0 {
            COL_RED
        } else if n_s != 0 || nothing {
            COL_YEL
        } else {
            COL_GRN
        };
        self.out_now("", COL_DEF);
        self.out_now(
            "==============================================================================",
            col,
        );
        if n_c != 0 {
            self.out_now(
                &format!("  SONUÇ: HİLE TESPİT EDİLDİ (KESİN)  -  {} bulgu", n_c),
                COL_RED,
            );
        } else if n_s != 0 {
            self.out_now(
                &format!(
                    "  SONUÇ: ŞÜPHELİ BULGU VAR (kesin değil)  -  {} bulgu, elle doğrulayın",
                    n_s
                ),
                COL_YEL,
            );
        } else if nothing {
            self.out_now("  SONUÇ: TARAMA YAPILMADI (javaw çalışmıyor ve disk atlandı)", COL_YEL);
        } else {
            self.out_now("  SONUÇ: HİLE BULUNAMADI", COL_GRN);
        }
        self.out_now(
            "==============================================================================",
            col,
        );
        let yn = |b: bool| if b { "EVET" } else { "hayır" };
        if n_c != 0 || n_s != 0 {
            let t = format!(
                "  javaw'da AKTİF: {}   |   self-destruct/boşaltılmış izi: {}   |   javaw hafızasında iz: {}   |   diskte: {}",
                yn(active),
                yn(unloaded),
                yn(mem),
                yn(disk)
            );
            self.out_now(&t, col);
        }
        if n_c == 0 && n_s == 0 && !nothing {
            let t = format!(
                "  Kontrol edilen arama türü: {}/{}{}",
                ran,
                PHASES,
                if skipped.is_empty() {
                    String::new()
                } else {
                    format!("  (atlanan: {})", skipped)
                }
            );
            self.out_now(&t, COL_GRY);
            self.out_now("  Not: kendini silen ve iz temizleyen şifreli hileler bulunamayabilir; hiçbir tarayıcı %100 garanti vermez.", COL_GRY);
        }
        if n_c != 0 && !javaw_found {
            self.out_now("  Not: hile dosyası diskte var ama javaw içinde iz bulunamadı -> ya hiç yüklenmedi ya da izler silindi (ileri düzey self-destruct).", COL_GRY);
        }
        if n_c != 0 {
            2
        } else if n_s != 0 {
            1
        } else if nothing {
            3
        } else {
            0
        }
    }

    pub fn print_help(&mut self) {
        let lines = [
            "Kullanım: AvenorScanner.exe [seçenekler]   (YÖNETİCİ olarak çalıştırın)",
            "  --verbose, -v   tüm ayrıntıları göster (güvenilir modüller, bilgi düzeyi bulgular, tam teknik rapor)",
            "  --nodisk        disk taramasını atla (yalnızca javaw)",
            "  --full          tüm sabit diskleri tara (yavaş)   [varsayılan: kullanıcı profilleri, ProgramData, Windows Temp, Geri Dönüşüm Kutusu]",
            "  --nohandles     handle denetimini atla",
            "  --nohooks       API hook kontrolünü atla",
            "  --deepthreads   thread'leri kısa süreliğine durdurup çalışma konumunu (RIP) da kontrol et (varsayılan kapalı)",
            "  --root=KLASÖR   disk taramasını varsayılan konumlar yerine yalnızca bu klasörde yap (birden fazla kullanılabilir)",
            "  --pid=N         yalnızca bu PID'yi tara",
            "  --log=DOSYA     çıktıyı dosyaya da yaz",
            "  --dump=KLASÖR   bulguların raporlarını, tüm stringlerini ve bellekteki PE kopyalarını KLASORe kaydet",
            "  --nopause       bitince bekleme",
        ];
        for l in lines {
            self.out_now(l, COL_DEF);
        }
    }

    pub fn plan_work(&mut self, targets: &[Target]) {
        use windows::Win32::System::Threading::GetProcessHandleCount;
        for t in targets {
            let mods = self.list_modules(t.h);
            let mod_mb: f64 = mods.iter().map(|m| m.size as f64 / 1048576.0).sum();
            let regs = enum_regions(t.h);
            let mut mem_bytes = 0u64;
            for r in &regs {
                if r.state == MEM_COMMIT_V
                    && r.typ != MEM_IMAGE_V
                    && (r.protect & (0x01 | 0x100)) == 0
                    && (r.protect & 0xFF) != 0
                {
                    mem_bytes += r.size;
                }
            }
            let mut threads = 0usize;
            if let Ok(s) = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) } {
                let mut te: THREADENTRY32 = unsafe { std::mem::zeroed() };
                te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                let mut more = unsafe { Thread32First(s, &mut te) }.is_ok();
                while more {
                    if te.th32OwnerProcessID == t.pid {
                        threads += 1;
                    }
                    more = unsafe { Thread32Next(s, &mut te) }.is_ok();
                }
                unsafe {
                    let _ = CloseHandle(s);
                }
            }
            let mut handles = 0u32;
            if unsafe { GetProcessHandleCount(t.h, &mut handles) }.is_err() {
                handles = 2000;
            }
            let nm = mods.len() as f64;
            self.prog_add(1, 0.3 + 0.06 * nm + 0.01 * mod_mb);
            self.prog_add(2, 0.3 + 0.002 * regs.len() as f64);
            self.prog_add(3, 0.3);
            self.prog_add(4, 0.6 + 0.004 * threads as f64);
            if !self.cfg.no_hooks {
                self.prog_add(5, 0.5 + 0.04 * nm + 0.012 * mod_mb);
            }
            self.prog_add(6, 0.5 + mem_bytes as f64 / (120.0 * 1048576.0));
            if !self.cfg.no_handles {
                self.prog_add(7, 0.4 + 0.0015 * handles as f64);
            }
        }
        if !self.cfg.no_disk {
            self.disk_enumerate();
            let w = self.disk_work;
            self.prog_add(8, 0.3 + w);
        }
        if !(targets.is_empty() && self.cfg.no_disk) {
            self.prog_add(9, 0.2);
        }
    }

    pub fn guard<F: FnOnce(&mut Ctx)>(&mut self, what: &str, f: F) {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self)));
        if let Err(e) = r {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                Some(s.to_string())
            } else {
                e.downcast_ref::<String>().cloned()
            };
            self.quiet = false;
            self.clear_status();
            match msg {
                Some(m) => self.out_now(&format!("  [!] {} sırasında hata: {}", what, m), COL_YEL),
                None => self.out_now(&format!("  [!] {} sırasında bilinmeyen hata", what), COL_YEL),
            }
        }
    }
}

fn atoi(s: &str) -> u32 {
    let t = s.trim_start();
    let mut v: i64 = 0;
    for c in t.bytes() {
        if c.is_ascii_digit() {
            v = (v * 10 + (c - b'0') as i64).min(u32::MAX as i64);
        } else {
            break;
        }
    }
    v as u32
}

pub fn parse_args(args: &[String]) -> (Config, bool) {
    let mut cfg = Config::default();
    let mut nopause = false;
    for a in args.iter().skip(1) {
        let l = lower_w(a);
        if l == "--verbose" || l == "-v" {
            cfg.verbose = true;
        } else if l == "--nodisk" {
            cfg.no_disk = true;
        } else if l == "--full" {
            cfg.full = true;
        } else if l == "--nohandles" {
            cfg.no_handles = true;
        } else if l == "--nopause" {
            nopause = true;
        } else if l == "--help" || l == "-h" || l == "/?" {
            cfg.help = true;
        } else if l.starts_with("--pid=") {
            cfg.pid = atoi(&a[6..]);
        } else if l.starts_with("--log=") {
            cfg.log_path = a[6..].to_string();
        } else if l.starts_with("--dump=") {
            cfg.dump_dir = a[7..].to_string();
        } else if l == "--nohooks" {
            cfg.no_hooks = true;
        } else if l == "--deepthreads" {
            cfg.deep_threads = true;
        } else if l.starts_with("--root=") {
            cfg.roots.push(a[7..].to_string());
        } else if l.starts_with("--analyze=") {
            cfg.analyze_one = a[10..].to_string(); // tek dosyayı analiz et (teşhis)
        }
    }
    (cfg, nopause)
}

fn exe_has_icon() -> bool {
    use windows::Win32::System::LibraryLoader::*;
    unsafe {
        let hi = GetModuleHandleW(windows::core::PCWSTR::null()).unwrap_or_default();
        !FindResourceW(
            Some(hi),
            windows::core::PCWSTR(core::ptr::without_provenance(1)),
            windows::core::PCWSTR(core::ptr::without_provenance(14)),
        )
        .is_invalid()
    }
}

pub fn run_main(args: Vec<String>) -> i32 {
    let (cfg, nopause) = parse_args(&args);
    let mut c = Ctx::new(cfg);
    c.init_console();
    unsafe {
        let t = wz("AvenorCraft Cheat Scanner v12.4");
        let _ = windows::Win32::System::Console::SetConsoleTitleW(windows::core::PCWSTR(t.as_ptr()));
    }
    if !c.cfg.log_path.is_empty() {
        c.log = std::fs::File::create(&c.cfg.log_path).ok();
    }
    if !c.cfg.dump_dir.is_empty() {
        let _ = std::fs::create_dir(&c.cfg.dump_dir);
    }
    c.out_now(
        "==============================================================================",
        COL_CYN,
    );
    c.out_now(
        "  AvenorCraft Minecraft Cheat Scanner v12.4   (Author: Jestron)",
        COL_CYN,
    );
    c.out_now(
        "  9 arama türü - yalnızca DLL - içerik + imza + davranış tabanlı - KESİN sonuç",
        COL_CYN,
    );
    c.out_now(
        "==============================================================================",
        COL_CYN,
    );
    if c.cfg.help {
        c.print_help();
        return 0;
    }
    c.nt = init_nt();
    c.dev_map = build_dev_map();
    c.dirs = init_dirs();
    if !c.cfg.analyze_one.is_empty() {
        c.quiet = false;
        let one = c.cfg.analyze_one.clone();
        let a = c.analyze_file(&one);
        match &a {
            None => c.out_now(&format!("  analiz edilemedi (okunamadı): {}", one), COL_RED),
            Some(a) => {
                c.out_now(
                    &format!(
                        "  KARAR: {} | expCef={} expTotal={} benignCef={} S={} T={} | {}",
                        verdict_name(a.verdict),
                        a.pe.exp_cef,
                        a.pe.exp_total,
                        a.benign_cef as i32,
                        a.s,
                        a.t,
                        a.vreason
                    ),
                    COL_CYN,
                );
                c.out_now(
                    &format!(
                        "  JAVA: analiz={} sınıf={} değerlendirilen={} mixin={} kütüphane-yalnız={} mod={}",
                        a.jv.analyzed as i32,
                        a.jv.classes_total,
                        a.jv.classes_eval,
                        a.jv.mixins,
                        a.jv.lib_only as i32,
                        a.jv.mod_id
                    ),
                    COL_GRY,
                );
                for b in &a.jv.beh {
                    c.out_now(
                        &format!(
                            "  JAVA DAVRANIŞ: {} [{}] sınıf={}{} | {}",
                            b.module,
                            if b.sev >= 3 { "KESİN" } else { "ŞÜPHELİ" },
                            b.cls,
                            if b.indirect { " (dolaylı)" } else { "" },
                            b.why
                        ),
                        COL_GRY,
                    );
                }
            }
        }
        return 0;
    }
    let adm = is_elevated();
    let dbg = enable_debug_privilege();
    c.out_now(
        &format!(
            "  Yönetici: {}   SeDebugPrivilege: {}{}",
            if adm { "EVET" } else { "HAYIR" },
            if dbg { "AKTİF" } else { "PASİF" },
            if c.cfg.full { "   [tam disk]" } else { "" }
        ),
        if adm && dbg { COL_GRN } else { COL_YEL },
    );
    if !adm {
        c.out_now(
            "  [!] Yönetici değilsiniz: javaw belleği okunamayabilir. Sağ tik -> 'Yönetici olarak çalıştır'.",
            COL_YEL,
        );
    }
    if !exe_has_icon() {
        c.out_now("  [i] exe dosyasına ikon gömülmemiş: AvenorScanner.rc projeye eklenmemiş (pencere ikonu yine aslan; Explorer'daki exe ikonu için .rc gerekli).", COL_GRY);
    }
    c.out_now("", COL_DEF);
    c.prog_start(); // bundan sonra tüm sonuçlar TOPLANIR
    let mut targets: Vec<Target> = Vec::new();
    c.guard("hedef arama", |c| targets = c.find_targets());
    let st = format!(
        "  JAVAW_DURUM: bulunan={} erişilen={} erişilemeyen={}",
        c.javaw_seen,
        targets.len(),
        c.javaw_open_fail
    );
    c.out_now(&st, COL_GRY);
    if targets.is_empty() && c.javaw_open_fail > 0 {
        c.out("  Minecraft/javaw süreci ÇALIŞIYOR ama belleğine ERİŞİLEMEDİ -> programı YÖNETİCİ olarak çalıştırın (javaw aramaları 1-7 atlandı).", COL_YEL);
    } else if targets.is_empty() {
        c.out(
            "  Çalışan Minecraft/javaw süreci bulunamadı -> javaw aramaları (1-7) atlandı; yalnızca disk tarandı.",
            COL_YEL,
        );
    }
    for t in targets.iter() {
        c.guard("süreç bilgisi", |c| c.phase_info(t));
    }
    c.out("", COL_DEF);
    {
        let tr = &targets;
        c.guard("planlama", |c| c.plan_work(tr));
    }
    if targets.is_empty() {
        for n in 1..=7 {
            c.skip_phase(n, PHASE_NAMES[n], "javaw çalışmıyor");
        }
    }
    for t in targets.iter_mut() {
        c.guard("modül denetimi", |c| c.phase_modules(t));
        c.guard("gizli modül taraması", |c| c.phase_hidden(t));
        c.guard("boşaltılmış modül kaydı", |c| c.phase_unloaded(t));
        c.guard("unbacked thread taraması", |c| c.phase_unbacked(t));
        if !c.cfg.no_hooks {
            c.guard("API hook kontrolü", |c| c.phase_hooks(t));
        } else {
            c.skip_phase(5, PHASE_NAMES[5], "--nohooks");
        }
        c.guard("bellek taraması", |c| c.phase_memory(t));
        if !c.cfg.no_handles {
            c.guard("handle denetimi", |c| c.phase_handles(t));
        } else {
            c.skip_phase(7, PHASE_NAMES[7], "--nohandles");
        }
    }
    let javaw_found = c.findings.iter().any(|f| f.verd() >= Verdict::Suspect);
    if !c.cfg.no_disk {
        c.guard("disk taraması", |c| c.phase_disk());
    } else {
        c.skip_phase(8, PHASE_NAMES[8], "--nodisk");
    }
    if targets.is_empty() && c.cfg.no_disk {
        c.skip_phase(9, PHASE_NAMES[9], "taranacak veri yok");
    } else {
        c.guard("korelasyon", |c| c.phase_correlate());
    }
    c.prog_finish(); // toplama bitti: tüm sonuçlar aşağıda TEK SEFERDE
    if !targets.is_empty() && !javaw_found {
        c.out_now("  javaw içinde hile izi bulunamadı (modül, gizli görüntü, unbacked thread, API hook, boşaltılmış modül kaydı, bellek, handle).", COL_GRN);
    }
    c.print_new("SONUÇLAR (KESİN bulgular + şüpheliler)");
    c.print_consolidated();
    let rc = c.print_verdict(javaw_found);
    for t in &targets {
        unsafe {
            let _ = CloseHandle(t.h);
        }
    }
    c.log = None;
    if !nopause && c.is_console {
        c.out_now("", COL_DEF);
        c.out_now("  Çıkmak için ENTER'a basın...", COL_DEF);
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
    }
    rc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args() {
        let a: Vec<String> = [
            "x",
            "--avdll",
            "--nopause",
            "--verbose",
            "--log=C:\\a b\\l.txt",
            "--nodisk",
            "--root=C:\\r",
            "--pid=123abc",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let (c, np) = parse_args(&a);
        assert!(np && c.verbose && c.no_disk);
        assert_eq!(c.log_path, "C:\\a b\\l.txt");
        assert_eq!(c.roots, vec!["C:\\r".to_string()]);
        assert_eq!(c.pid, 123);
    }
    #[test]
    fn type_names() {
        let f = Finding {
            kinds: vec!["API HOOK (IAT)".into()],
            path: String::new(),
            an: None,
            notes: vec![],
            remnants: vec![],
            detail: vec![],
            loaded: false,
            title: String::new(),
            v_override: None,
            printed: false,
            printed_v: -99,
        };
        assert_eq!(finding_type_name(&f), "API HOOK");
    }
    #[test]
    #[ignore]
    fn smoke_nodisk() {
        let log = std::env::temp_dir().join("js_native_smoke.txt");
        let args: Vec<String> = [
            "x".to_string(),
            "--avdll".into(),
            "--nopause".into(),
            "--verbose".into(),
            format!("--log={}", log.display()),
            "--nodisk".into(),
        ]
        .to_vec();
        let rc = run_main(args);
        assert!((0..=3).contains(&rc));
        let t = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(t.contains("JAVAW_DURUM:") && t.contains("SONUÇ:"));
    }
    #[test]
    fn atoi_like() {
        assert_eq!(atoi("  42x"), 42);
        assert_eq!(atoi("x"), 0);
    }
}
