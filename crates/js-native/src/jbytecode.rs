use crate::classfile::sanitize_j;
use crate::jf_data::*;
use crate::patterns::AhoCorasick;
use crate::util::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;

pub struct JfPat {
    pub owner: Vec<u8>,
    pub desc: Vec<u8>,
    pub f: usize,
}

pub struct JfDb {
    pub by_name: HashMap<Vec<u8>, Vec<JfPat>>,
    pub by_owner: HashMap<Vec<u8>, u64>,
    pub s_ac: AhoCorasick,
    pub e_ac: AhoCorasick,
    pub s_feat: Vec<usize>,
    pub e_feat: Vec<usize>,
    pub e_len: Vec<usize>,
}

fn find_byte(h: &[u8], c: u8, from: usize) -> Option<usize> {
    h.get(from..)?.iter().position(|&x| x == c).map(|i| i + from)
}

impl JfDb {
    fn new() -> JfDb {
        let mut db = JfDb {
            by_name: HashMap::new(),
            by_owner: HashMap::new(),
            s_ac: AhoCorasick::default(),
            e_ac: AhoCorasick::default(),
            s_feat: Vec::new(),
            e_feat: Vec::new(),
            e_len: Vec::new(),
        };
        for &(f, p) in JF_DEFS {
            let all = p.as_bytes();
            let mut st = 0usize;
            while st <= all.len() {
                let e = find_byte(all, b'|', st).unwrap_or(all.len());
                let tok: Vec<u8> = all[st..e].iter().map(|&c| low_c(c)).collect();
                st = e + 1;
                if tok.is_empty() {
                    continue;
                }
                if tok.starts_with(b"s:") {
                    let s = &tok[2..];
                    if !s.is_empty() {
                        db.s_ac.add(s, db.s_feat.len() as i32);
                        db.s_feat.push(f);
                    }
                    continue;
                }
                if tok.starts_with(b"e:") {
                    let s = &tok[2..];
                    if !s.is_empty() {
                        db.e_ac.add(s, db.e_feat.len() as i32);
                        db.e_feat.push(f);
                        db.e_len.push(s.len());
                    }
                    continue;
                }
                let Some(h1) = find_byte(&tok, b'#', 0) else { continue };
                let Some(h2) = find_byte(&tok, b'#', h1 + 1) else {
                    continue;
                };
                let owner = tok[..h1].to_vec();
                let nm = tok[h1 + 1..h2].to_vec();
                let desc = tok[h2 + 1..].to_vec();
                if nm.is_empty() {
                    if !owner.is_empty() {
                        *db.by_owner.entry(owner).or_insert(0) |= 1u64 << f;
                    }
                } else {
                    db.by_name.entry(nm).or_default().push(JfPat { owner, desc, f });
                }
            }
        }
        db.s_ac.build();
        db.e_ac.build();
        db
    }
}

pub fn get_jf_db() -> &'static JfDb {
    static DB: OnceLock<JfDb> = OnceLock::new();
    DB.get_or_init(JfDb::new)
}

#[derive(Debug, Clone, Default)]
pub struct JClass {
    pub name: String,
    pub super_name: String,
    pub m: u64,
    pub major: u16,
    pub methods: i32,
    pub natives: i32,
    pub indy: i32,
    pub custom_bsm: i32,
    pub mixin: bool,
    pub iface: bool,
    pub demo_obf: bool,
    pub deps: Vec<u32>,
}

pub fn fnv32(s: &[u8]) -> u32 {
    let mut h: u32 = 2166136261;
    for &c in s {
        h ^= c as u32;
        h = h.wrapping_mul(16777619);
    }
    h
}
pub fn fnv64(s: &[u8]) -> u64 {
    let mut h: u64 = 1469598103934665603;
    for &c in s {
        h ^= c as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}
pub fn outer_name(n: &str) -> &str {
    match n.find('$') {
        None | Some(0) => n,
        Some(k) => &n[..k],
    }
}

#[derive(Clone, Copy, Default)]
struct Cp {
    tag: u8,
    a: u16,
    b: u16,
    off: u32,
    len: u32,
}

fn starts(s: &[u8], p: &str) -> bool {
    s.starts_with(p.as_bytes())
}

pub fn scan_class_feat(p: &[u8]) -> Option<JClass> {
    let n = p.len();
    let mut jc = JClass::default();
    if n < 32 || rd32be(p, 0) != 0xCAFEBABE {
        return None;
    }
    jc.major = rd16be(p, 6);
    if jc.major < 45 || jc.major > 90 {
        return None;
    }
    let cp_count = rd16be(p, 8) as usize;
    if cp_count < 2 {
        return None;
    }
    let mut cp = vec![Cp::default(); cp_count];
    let mut pos = 10usize;
    let mut i = 1usize;
    while i < cp_count {
        if pos + 1 > n {
            return None;
        }
        let tag = p[pos];
        pos += 1;
        cp[i].tag = tag;
        match tag {
            1 => {
                if pos + 2 > n {
                    return None;
                }
                let len = rd16be(p, pos) as usize;
                pos += 2;
                if pos + len > n {
                    return None;
                }
                cp[i].off = pos as u32;
                cp[i].len = len as u32;
                pos += len;
            }
            3 | 4 => {
                if pos + 4 > n {
                    return None;
                }
                pos += 4;
            }
            5 | 6 => {
                if pos + 8 > n {
                    return None;
                }
                pos += 8;
                i += 1;
            }
            7 | 8 | 16 | 19 | 20 => {
                if pos + 2 > n {
                    return None;
                }
                cp[i].a = rd16be(p, pos);
                pos += 2;
            }
            9 | 10 | 11 | 12 | 17 | 18 => {
                if pos + 4 > n {
                    return None;
                }
                cp[i].a = rd16be(p, pos);
                cp[i].b = rd16be(p, pos + 2);
                pos += 4;
            }
            15 => {
                if pos + 3 > n {
                    return None;
                }
                cp[i].a = p[pos] as u16;
                cp[i].b = rd16be(p, pos + 1);
                pos += 3;
            }
            _ => return None,
        }
        i += 1;
    }
    let db = get_jf_db();
    let u = |idx: usize| -> &[u8] {
        if idx == 0 || idx >= cp_count || cp[idx].tag != 1 {
            return &[];
        }
        p.get(cp[idx].off as usize..(cp[idx].off + cp[idx].len) as usize)
            .unwrap_or(&[])
    };
    let cn = |idx: usize| -> &[u8] {
        if idx == 0 || idx >= cp_count || cp[idx].tag != 7 {
            return &[];
        }
        u(cp[idx].a as usize)
    };
    const MIXIN_ANN: &[u8] = b"Lorg/spongepowered/asm/mixin/Mixin;";
    const BSM_PRE: &[u8] = b"(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;";
    let mut low: Vec<u8> = Vec::new();
    let mut e_bits: u64 = 0; // yalnızca mixin hedef ADINDAN (E:) gelen özellikler
    for c in cp.iter().skip(1) {
        if c.tag == 1 {
            let len = c.len as usize;
            if !(4..=600).contains(&len) {
                continue;
            }
            let Some(s) = p.get(c.off as usize..c.off as usize + len) else {
                continue;
            };
            if s == MIXIN_ANN {
                jc.mixin = true;
            }
            if len >= 13 && &s[..13] == b"ALLATORIxDEMO" {
                jc.demo_obf = true;
            }
            low.clear();
            low.extend(s.iter().map(|&b| low_c(b)));
            let mut m = jc.m;
            db.s_ac.search(&low, |id, _| m |= 1u64 << db.s_feat[id as usize]);
            jc.m = m;
            db.e_ac.search(&low, |id, en| {
                let l = db.e_len[id as usize];
                let stt = en - l;
                if en > len || stt > len {
                    return;
                }
                let lb = stt == 0 || matches!(low[stt - 1], b';' | b' ' | b'.' | b'"');
                let rb = en == len || matches!(low[en], b'(' | b';' | b'"');
                if lb && rb {
                    e_bits |= 1u64 << db.e_feat[id as usize];
                }
            });
        }
    }
    let mut deps: Vec<u32> = Vec::new();
    for i in 1..cp_count {
        let tag = cp[i].tag;
        if tag == 18 {
            jc.indy += 1;
            continue;
        }
        if tag == 7 {
            let cnm = u(cp[i].a as usize);
            if cnm.is_empty() || cnm[0] == b'[' {
                continue;
            }
            let sl = cnm.iter().rposition(|&c| c == b'/');
            let ol: Vec<u8> = cnm[sl.map_or(0, |x| x + 1)..].iter().map(|&c| low_c(c)).collect();
            if let Some(v) = db.by_owner.get(&ol) {
                jc.m |= *v;
            }
            if !(starts(cnm, "java/")
                || starts(cnm, "javax/")
                || starts(cnm, "jdk/")
                || starts(cnm, "sun/")
                || starts(cnm, "net/minecraft/")
                || starts(cnm, "com/mojang/"))
                && deps.len() < 96
            {
                let k = cnm.iter().position(|&c| c == b'$');
                let on = match k {
                    None | Some(0) => cnm,
                    Some(k) => &cnm[..k],
                };
                deps.push(fnv32(on));
            }
            continue;
        }
        if tag != 9 && tag != 10 && tag != 11 {
            continue;
        }
        let cnm = cn(cp[i].a as usize);
        let ni = cp[i].b as usize;
        if ni == 0 || ni >= cp_count || cp[ni].tag != 12 {
            continue;
        }
        let name = u(cp[ni].a as usize);
        let desc = u(cp[ni].b as usize);
        if name.is_empty() {
            continue;
        }
        if tag == 10
            && desc.starts_with(BSM_PRE)
            && !(starts(cnm, "java/")
                || starts(cnm, "jdk/")
                || starts(cnm, "sun/")
                || starts(cnm, "org/codehaus/groovy/")
                || starts(cnm, "groovy/")
                || starts(cnm, "org/apache/groovy/")
                || starts(cnm, "kotlin/")
                || starts(cnm, "scala/")
                || starts(cnm, "clojure/"))
        {
            jc.custom_bsm += 1; // JDK/dil çalışma zamanı dışındaki özel invokedynamic bootstrap
        }
        let sl = cnm.iter().rposition(|&c| c == b'/');
        let ol: Vec<u8> = cnm[sl.map_or(0, |x| x + 1)..].iter().map(|&c| low_c(c)).collect();
        let nl: Vec<u8> = name.iter().map(|&c| low_c(c)).collect();
        if let Some(v) = db.by_owner.get(&ol) {
            jc.m |= *v;
        }
        if let Some(list) = db.by_name.get(&nl) {
            let dl: Vec<u8> = desc.iter().map(|&c| low_c(c)).collect();
            for jp in list {
                if !jp.owner.is_empty() && jp.owner != ol {
                    continue;
                }
                if !jp.desc.is_empty() && memchr::memmem::find(&dl, &jp.desc).is_none() {
                    continue;
                }
                jc.m |= 1u64 << jp.f;
            }
        }
    }
    deps.sort_unstable();
    deps.dedup();
    jc.deps = deps;
    if pos + 8 > n {
        return None;
    }
    let acc = rd16be(p, pos);
    jc.iface = acc & 0x0200 != 0;
    pos += 2;
    if !(jc.mixin && !jc.iface) {
        jc.m |= e_bits;
    }
    let this_c = rd16be(p, pos) as usize;
    pos += 2;
    let super_c = rd16be(p, pos) as usize;
    pos += 2;
    let n_if = rd16be(p, pos) as usize;
    pos += 2;
    jc.name = sanitize_j(cn(this_c), 160);
    jc.super_name = sanitize_j(cn(super_c), 160);
    if jc.name.is_empty() {
        return None;
    }
    if pos + n_if * 2 <= n {
        pos += n_if * 2;
    } else {
        return Some(jc);
    }
    for pass in 0..2 {
        if pos + 2 > n {
            return Some(jc);
        }
        let cnt = rd16be(p, pos);
        pos += 2;
        for _ in 0..cnt {
            if pos + 8 > n {
                return Some(jc);
            }
            let ac = rd16be(p, pos);
            let na = rd16be(p, pos + 6);
            pos += 8;
            if pass == 1 {
                jc.methods += 1;
                if ac & 0x0100 != 0 {
                    jc.natives += 1;
                }
            }
            for _ in 0..na {
                if pos + 6 > n {
                    return Some(jc);
                }
                let al = rd32be(p, pos + 2) as usize;
                pos += 6;
                if pos + al > n {
                    return Some(jc);
                }
                pos += al;
            }
        }
    }
    Some(jc)
}

#[derive(Default, Clone)]
pub struct JavaAcc {
    pub cls: Vec<JClass>,
    pub van: Vec<JClass>,
    pub vanilla_total: i32,
    pub third_total: i32,
    pub obf_count: i32,
    pub demo_obf: i32,
    pub mixin_count: i32,
    pub indy_total: i32,
    pub native_total: i32,
    pub bsm_classes: i32,
    pub bsm_first: String,
    pub seen: HashSet<u64>,
    pub lib_only: bool,
}
impl JavaAcc {
    pub fn any(&self) -> bool {
        !self.cls.is_empty() || !self.van.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct JBeh {
    pub module: String,
    pub cls: String,
    pub why: String,
    pub sev: i32,
    pub classes: i32,
    pub indirect: bool,
}

#[derive(Debug, Clone, Default)]
pub struct JavaProfile {
    pub analyzed: bool,
    pub server_plugin: bool,
    pub obfuscated: bool,
    pub agent: bool,
    pub lib_only: bool,
    pub classes_total: i32,
    pub classes_eval: i32,
    pub mixins: i32,
    pub natives: i32,
    pub third_party: i32,
    pub obf_classes: i32,
    pub mod_id: String,
    pub mod_name: String,
    pub mod_ver: String,
    pub loader: String,
    pub obf_note: String,
    pub beh: Vec<JBeh>,
    pub sd_level: i32,
    pub sd_confirmed: bool,
    pub sd_suspect: bool,
    pub sd_notes: Vec<String>,
    pub sd_classes: Vec<String>,
}
impl JavaProfile {
    pub fn red(&self) -> i32 {
        self.beh.iter().filter(|b| b.sev >= 3).count() as i32
    }
    pub fn yel(&self) -> i32 {
        self.beh.iter().filter(|b| b.sev == 2).count() as i32
    }
}

pub fn is_obf_name(n: &str) -> bool {
    let s = match n.rfind('/') {
        None => n,
        Some(i) => &n[i + 1..],
    };
    if s.is_empty() {
        return false;
    }
    if s.len() <= 2 {
        return true;
    }
    if s.len() >= 3 {
        let all_il = s
            .bytes()
            .all(|c| matches!(c, b'I' | b'l' | b'1' | b'O' | b'0' | b'i' | b'L'));
        if all_il {
            return true;
        }
    }
    false
}

pub fn java_add_class(acc: &mut JavaAcc, p: &[u8]) -> i32 {
    let Some(jc) = scan_class_feat(p) else { return 0 };
    let key = fnv64(jc.name.as_bytes())
        .wrapping_mul(1099511628211)
        .wrapping_add(p.len() as u64);
    if !acc.seen.insert(key) {
        return 2;
    }
    if jc.name.starts_with("net/minecraft/") || jc.name.starts_with("com/mojang/") {
        acc.vanilla_total += 1;
        if acc.van.len() < 600 {
            acc.van.push(jc);
        }
        return 1;
    }
    acc.third_total += 1;
    acc.indy_total += jc.indy;
    acc.native_total += jc.natives;
    if jc.mixin {
        acc.mixin_count += 1;
    }
    if jc.demo_obf {
        acc.demo_obf += 1;
    }
    if jc.custom_bsm > 0 {
        acc.bsm_classes += 1;
        if acc.bsm_first.is_empty() {
            acc.bsm_first = jc.name.clone();
        }
    }
    if is_obf_name(&jc.name) {
        acc.obf_count += 1;
    }
    if acc.cls.len() < 80000 {
        acc.cls.push(jc);
    }
    1
}

fn why_list(m: u64, fs: &[usize]) -> String {
    let mut s = String::new();
    for &f in fs {
        if (m >> f) & 1 != 0 {
            if !s.is_empty() {
                s.push_str(" + ");
            }
            s.push_str(JF_NAME[f]);
        }
    }
    s
}

pub struct RuleHit {
    pub module: &'static str,
    pub sev: i32,
    pub why: String,
}

pub fn eval_module_rules(m: u64, indirect: bool, out: &mut Vec<RuleHit>) {
    let h = |f: usize| (m >> f) & 1 != 0;
    let any = |l: &[usize]| l.iter().any(|&f| h(f));
    let atk = any(&[JF_ATK_MGR, JF_ATK_PKT, JF_DO_ATTACK]);
    let cross = h(JF_CROSSHAIR);
    let enthit = h(JF_ENT_HIT);
    let iter = h(JF_ENT_ITER);
    let rot = h(JF_ROT_SET);
    let atan = h(JF_ATAN2);
    let wrap = h(JF_WRAP);
    let ffly = h(JF_FALLFLY);
    let ely = h(JF_ELYTRA);
    let fw = h(JF_FIREWORK) || h(JF_S_FIREWORK);
    let usei = h(JF_USE_ITEM);
    let slot = h(JF_SLOT_CLICK);
    let hot = h(JF_HOTBAR);
    let mut add = |module: &'static str, sev: i32, ev: &[usize]| {
        let sev = if indirect && sev > 2 { 2 } else { sev };
        out.push(RuleHit {
            module,
            sev,
            why: why_list(m, ev),
        });
    };
    if cross && enthit && atk && any(&[JF_COOLDOWN, JF_SWING]) {
        add(
            "TriggerBot",
            3,
            &[
                JF_CROSSHAIR,
                JF_ENT_HIT,
                JF_ATK_MGR,
                JF_ATK_PKT,
                JF_DO_ATTACK,
                JF_COOLDOWN,
                JF_SWING,
            ],
        );
    } else if (cross || h(JF_RAYCAST)) && atk && (enthit || h(JF_COOLDOWN)) {
        add(
            "TriggerBot",
            2,
            &[
                JF_CROSSHAIR,
                JF_RAYCAST,
                JF_ENT_HIT,
                JF_ATK_MGR,
                JF_ATK_PKT,
                JF_DO_ATTACK,
                JF_COOLDOWN,
            ],
        );
    } else if cross && h(JF_KEY_SET) && h(JF_ATK_KEY) {
        add("TriggerBot", 2, &[JF_CROSSHAIR, JF_KEY_SET, JF_ATK_KEY]);
    }
    if iter && atk && h(JF_DIST) && any(&[JF_SWING, JF_ROT_SET, JF_ROT_PKT, JF_COOLDOWN]) {
        add(
            "KillAura",
            3,
            &[
                JF_ENT_ITER,
                JF_ATK_MGR,
                JF_ATK_PKT,
                JF_DO_ATTACK,
                JF_DIST,
                JF_SWING,
                JF_ROT_SET,
                JF_ROT_PKT,
                JF_COOLDOWN,
            ],
        );
    } else if iter && atk {
        add(
            "KillAura",
            2,
            &[JF_ENT_ITER, JF_ATK_MGR, JF_ATK_PKT, JF_DO_ATTACK, JF_DIST],
        );
    }
    if iter && rot && atan && wrap {
        add(
            "AimAssist",
            3,
            &[JF_ENT_ITER, JF_ROT_SET, JF_ATAN2, JF_WRAP, JF_EYE, JF_BBOX],
        );
    } else if rot && atan && wrap && any(&[JF_EYE, JF_BBOX]) && (cross || h(JF_RAYCAST) || enthit) {
        add(
            "AimAssist",
            3,
            &[
                JF_ROT_SET,
                JF_ATAN2,
                JF_WRAP,
                JF_EYE,
                JF_BBOX,
                JF_CROSSHAIR,
                JF_RAYCAST,
                JF_ENT_HIT,
            ],
        );
    } else if rot && iter && (atan || wrap || h(JF_EYE)) {
        add("AimAssist", 2, &[JF_ROT_SET, JF_ENT_ITER, JF_ATAN2, JF_WRAP, JF_EYE]);
    } else if rot && atan && any(&[JF_EYE, JF_BBOX]) {
        add("AimAssist", 2, &[JF_ROT_SET, JF_ATAN2, JF_EYE, JF_BBOX]);
    }
    if h(JF_TOTEM) && any(&[JF_SLOT_CLICK, JF_SWAP_OFF]) && any(&[JF_HEALTH, JF_HANDITEM]) {
        add(
            "AutoTotem",
            3,
            &[JF_TOTEM, JF_SLOT_CLICK, JF_SWAP_OFF, JF_HEALTH, JF_HANDITEM, JF_ITEMCMP],
        );
    } else if h(JF_TOTEM) && (slot || h(JF_SWAP_OFF) || hot) {
        add(
            "AutoTotem",
            2,
            &[JF_TOTEM, JF_SLOT_CLICK, JF_SWAP_OFF, JF_HOTBAR, JF_HEALTH],
        );
    } else if h(JF_S_TOTEM) && slot && h(JF_HEALTH) {
        add("AutoTotem", 2, &[JF_S_TOTEM, JF_SLOT_CLICK, JF_HEALTH]);
    }
    if ffly && iter && rot && any(&[JF_ATAN2, JF_VELOCITY, JF_EYE]) {
        add(
            "ElytraTarget",
            3,
            &[JF_FALLFLY, JF_ENT_ITER, JF_ROT_SET, JF_ATAN2, JF_VELOCITY, JF_EYE],
        );
    } else if ffly && rot && (atan || iter) {
        add("ElytraTarget", 2, &[JF_FALLFLY, JF_ROT_SET, JF_ATAN2, JF_ENT_ITER]);
    } else if (ely || h(JF_S_ELYTRA)) && iter && rot && atan {
        add(
            "ElytraTarget",
            2,
            &[JF_ELYTRA, JF_S_ELYTRA, JF_ENT_ITER, JF_ROT_SET, JF_ATAN2],
        );
    }
    if fw && usei && (cross || h(JF_BLK_HIT)) && (ffly || ely || hot) {
        add(
            "FireworkFix",
            3,
            &[
                JF_FIREWORK,
                JF_S_FIREWORK,
                JF_USE_ITEM,
                JF_CROSSHAIR,
                JF_BLK_HIT,
                JF_FALLFLY,
                JF_ELYTRA,
                JF_HOTBAR,
            ],
        );
    } else if fw && usei && (ffly || ely || hot || h(JF_KEY_SET)) {
        add(
            "FireworkFix",
            2,
            &[
                JF_FIREWORK,
                JF_S_FIREWORK,
                JF_USE_ITEM,
                JF_FALLFLY,
                JF_ELYTRA,
                JF_HOTBAR,
                JF_KEY_SET,
            ],
        );
    }
    if (ely || h(JF_S_ELYTRA)) && h(JF_FF_CMD) && (slot || hot || h(JF_SWAP_OFF)) && (fw || usei) {
        add(
            "ElytraBugFix/ElytraSwap",
            3,
            &[
                JF_ELYTRA,
                JF_FF_CMD,
                JF_SLOT_CLICK,
                JF_HOTBAR,
                JF_SWAP_OFF,
                JF_FIREWORK,
                JF_USE_ITEM,
            ],
        );
    } else if (ely || h(JF_S_ELYTRA)) && h(JF_FF_CMD) && (slot || hot || h(JF_SWAP_OFF)) {
        add(
            "ElytraBugFix/ElytraSwap",
            2,
            &[JF_ELYTRA, JF_FF_CMD, JF_SLOT_CLICK, JF_HOTBAR, JF_SWAP_OFF],
        );
    } else if ely && slot && ffly {
        add("ElytraBugFix/ElytraSwap", 2, &[JF_ELYTRA, JF_SLOT_CLICK, JF_FALLFLY]);
    }
    let weap = any(&[JF_MACE, JF_AXE, JF_SWORD, JF_CRYSTAL]);
    if atk && hot && (cross || enthit || iter) && (weap || h(JF_SHIELD)) && any(&[JF_COOLDOWN, JF_SWING]) {
        add(
            "AutoPreHit",
            3,
            &[
                JF_ATK_MGR,
                JF_ATK_PKT,
                JF_DO_ATTACK,
                JF_HOTBAR,
                JF_CROSSHAIR,
                JF_ENT_HIT,
                JF_ENT_ITER,
                JF_MACE,
                JF_AXE,
                JF_SWORD,
                JF_CRYSTAL,
                JF_SHIELD,
                JF_COOLDOWN,
                JF_SWING,
            ],
        );
    } else if atk && hot && weap {
        add(
            "AutoPreHit",
            2,
            &[
                JF_ATK_MGR,
                JF_ATK_PKT,
                JF_DO_ATTACK,
                JF_HOTBAR,
                JF_MACE,
                JF_AXE,
                JF_SWORD,
                JF_CRYSTAL,
            ],
        );
    }
    if h(JF_CRYSTAL) && atk && any(&[JF_USE_BLOCK, JF_USE_ITEM]) && (iter || cross || h(JF_RAYCAST)) {
        add(
            "AutoCrystal",
            3,
            &[
                JF_CRYSTAL,
                JF_ATK_MGR,
                JF_ATK_PKT,
                JF_DO_ATTACK,
                JF_USE_BLOCK,
                JF_USE_ITEM,
                JF_ENT_ITER,
                JF_CROSSHAIR,
                JF_RAYCAST,
            ],
        );
    } else if h(JF_CRYSTAL) && atk && (iter || cross) {
        add(
            "AutoCrystal",
            2,
            &[
                JF_CRYSTAL,
                JF_ATK_MGR,
                JF_ATK_PKT,
                JF_DO_ATTACK,
                JF_ENT_ITER,
                JF_CROSSHAIR,
            ],
        );
    }
    let click = h(JF_ROBOT) || h(JF_NATIVE_CLICK);
    if (click || (h(JF_KEY_SET) && h(JF_ATK_KEY)) || h(JF_DO_ATTACK))
        && h(JF_RANDOM)
        && any(&[JF_TIME, JF_SLEEP])
        && h(JF_MOUSE_BTN)
    {
        add(
            "AutoClicker",
            3,
            &[
                JF_ROBOT,
                JF_NATIVE_CLICK,
                JF_KEY_SET,
                JF_ATK_KEY,
                JF_DO_ATTACK,
                JF_RANDOM,
                JF_TIME,
                JF_SLEEP,
                JF_MOUSE_BTN,
            ],
        );
    } else if click && h(JF_RANDOM) && any(&[JF_TIME, JF_SLEEP]) {
        add(
            "AutoClicker",
            2,
            &[JF_ROBOT, JF_NATIVE_CLICK, JF_RANDOM, JF_TIME, JF_SLEEP],
        );
    } else if h(JF_KEY_SET) && h(JF_ATK_KEY) && h(JF_RANDOM) && h(JF_TIME) {
        add("AutoClicker", 2, &[JF_KEY_SET, JF_ATK_KEY, JF_RANDOM, JF_TIME]);
    }
    if h(JF_DEFCLASS) && h(JF_CIPHER) {
        add(
            "EncryptedClassLoader (şifreli sınıf yükleyici)",
            2,
            &[JF_DEFCLASS, JF_CIPHER, JF_RESSTREAM],
        );
    }
    if h(JF_AXE) && hot && atk && h(JF_SHIELD) {
        add(
            "ShieldBreaker/AxeSwap",
            if cross || enthit { 3 } else { 2 },
            &[
                JF_AXE,
                JF_HOTBAR,
                JF_ATK_MGR,
                JF_ATK_PKT,
                JF_DO_ATTACK,
                JF_SHIELD,
                JF_CROSSHAIR,
                JF_ENT_HIT,
            ],
        );
    }
}

fn bit(f: usize) -> u64 {
    1u64 << f
}
pub fn anchor_mask() -> u64 {
    bit(JF_ATK_MGR)
        | bit(JF_ATK_PKT)
        | bit(JF_DO_ATTACK)
        | bit(JF_ROT_SET)
        | bit(JF_TOTEM)
        | bit(JF_FIREWORK)
        | bit(JF_ELYTRA)
        | bit(JF_CROSSHAIR)
        | bit(JF_CRYSTAL)
        | bit(JF_SLOT_CLICK)
        | bit(JF_USE_ITEM)
        | bit(JF_ROBOT)
        | bit(JF_FALLFLY)
        | bit(JF_ENT_ITER)
}
pub fn sd_mask() -> u64 {
    bit(JF_SD_OWNPATH)
        | bit(JF_SD_MODPATH)
        | bit(JF_SD_DEL)
        | bit(JF_SD_WRITE)
        | bit(JF_SD_TIME)
        | bit(JF_SD_NET)
        | bit(JF_SD_EXEC)
        | bit(JF_SD_MODHIDE)
        | bit(JF_SD_REFLECT)
        | bit(JF_SD_GC)
        | bit(JF_SD_UNSAFE)
        | bit(JF_S_SDNAME)
        | bit(JF_S_LOGWIPE)
}

pub fn eval_self_destruct(m: u64, jv: &mut JavaProfile, where_: &str, indirect: bool) -> bool {
    let h = |f: usize| (m >> f) & 1 != 0;
    let sd_name = h(JF_S_SDNAME);
    let own = h(JF_SD_OWNPATH) || (h(JF_SD_MODPATH) && sd_name);
    let del = h(JF_SD_DEL);
    let wr = h(JF_SD_WRITE);
    let tm = h(JF_SD_TIME);
    let net = h(JF_SD_NET);
    let ex = h(JF_SD_EXEC);
    let mh = h(JF_SD_MODHIDE);
    let refl = h(JF_SD_REFLECT);
    let wipe = h(JF_S_LOGWIPE);
    let t1 = own && (del || wr);
    let t2 = own && net && wr;
    let t3 = tm && own;
    let t4 = mh && refl;
    let t5 = ex;
    let t7 = wipe;
    let lvl = t1 as i32 + t2 as i32 + t3 as i32 + t4 as i32 + t5 as i32 + t7 as i32;
    let mut conf = (sd_name && (t1 || t2 || t4 || t5)) || (t1 && (t2 || t3 || t4));
    let mut susp = !conf && (sd_name || (own && del) || t4 || (t1 && h(JF_SD_GC)));
    if indirect && conf {
        conf = false;
        susp = true;
    }
    if !(conf || susp) {
        return false;
    }
    if lvl > jv.sd_level {
        jv.sd_level = lvl;
    }
    jv.sd_confirmed = jv.sd_confirmed || conf;
    jv.sd_suspect = jv.sd_suspect || susp;
    if jv.sd_classes.len() < 6 && !jv.sd_classes.iter().any(|c| c == where_) {
        jv.sd_classes.push(where_.to_string());
    }
    true
}

pub fn sd_notes(jm: u64, jv: &mut JavaProfile) {
    let h = |f: usize| (jm >> f) & 1 != 0;
    let own = h(JF_SD_OWNPATH) || (h(JF_SD_MODPATH) && h(JF_S_SDNAME));
    let mut push = |s: &str| jv.sd_notes.push(s.to_string());
    if h(JF_S_SDNAME) {
        push("kodda 'selfdestruct/uninject/replace mod' ifadesi var (kullanıcı tetikli kaldırma özelliği)");
    }
    if own && (h(JF_SD_DEL) || h(JF_SD_WRITE)) {
        push("kendi JAR yolunu bulup (CodeSource/ProtectionDomain) siliyor veya üstüne yazıyor -> mod dosyası başka bir (temiz) dosyayla DEĞİŞTİRİLEBİLİR; diskte hile kalmaz");
    }
    if own && h(JF_SD_NET) && h(JF_SD_WRITE) {
        push("internetten dosya indirip kendi yerine yazıyor (temiz mod ile değiştirme)");
    }
    if h(JF_SD_TIME) && own {
        push("dosya değişiklik tarihini geri yazıyor (setLastModified/setTimes): değiştirilen dosya eski görünür -> iz gizleme");
    }
    if h(JF_SD_MODHIDE) && h(JF_SD_REFLECT) {
        push("loader (Fabric) mod listesine reflection ile erişiyor: kendini mod listesinden çıkarabilir (ModMenu/Mods görünmez)");
    }
    if h(JF_SD_EXEC) {
        push("ProcessBuilder/Runtime.exec: komut satırı ile dosya/iz silme olabilir");
    }
    if h(JF_S_LOGWIPE) {
        push("Windows iz kaynaklarına (Prefetch/Recent/olay günlüğü) ait ifadeler");
    }
    if h(JF_SD_GC) && (own || h(JF_S_SDNAME)) {
        push("System.gc: bellek temizleme denemesi");
    }
    if h(JF_SD_UNSAFE) {
        push("sun.misc.Unsafe kullanıyor (düşük seviye bellek/sınıf manipülasyonu)");
    }
}

fn find_sub(t: &[u8], k: &[u8], from: usize) -> Option<usize> {
    if from > t.len() {
        return None;
    }
    memchr::memmem::find(&t[from..], k).map(|i| i + from)
}

pub fn json_str_val(t: &[u8], key: &str) -> String {
    let k = format!("\"{}\"", key);
    let Some(mut p) = find_sub(t, k.as_bytes(), 0) else {
        return String::new();
    };
    p += k.len();
    while p < t.len() && matches!(t[p], b' ' | b'\t' | b'\r' | b'\n') {
        p += 1;
    }
    if p >= t.len() || t[p] != b':' {
        return String::new();
    }
    p += 1;
    while p < t.len() && matches!(t[p], b' ' | b'\t' | b'\r' | b'\n') {
        p += 1;
    }
    if p >= t.len() || t[p] != b'"' {
        return String::new();
    }
    p += 1;
    let Some(e) = find_byte(t, b'"', p) else {
        return String::new();
    };
    sanitize_j(&t[p..e], 80)
}

pub fn toml_str_val(t: &[u8], key: &str) -> String {
    let mut p = 0usize;
    let k = key.as_bytes();
    while let Some(pp) = find_sub(t, k, p) {
        p = pp;
        let mut q = p + k.len();
        let left_ok = p == 0 || !is_alnum(t[p - 1]);
        while q < t.len() && (t[q] == b' ' || t[q] == b'\t') {
            q += 1;
        }
        if left_ok && q < t.len() && t[q] == b'=' {
            q += 1;
            while q < t.len() && (t[q] == b' ' || t[q] == b'\t') {
                q += 1;
            }
            if q < t.len() && (t[q] == b'"' || t[q] == b'\'') {
                let qc = t[q];
                if let Some(e) = find_byte(t, qc, q + 1) {
                    return sanitize_j(&t[q + 1..e], 80);
                }
            }
        }
        p += k.len();
    }
    String::new()
}

pub fn yaml_str_val(t: &[u8], key: &str) -> String {
    let mut p = 0usize;
    let k = format!("{}:", key);
    let k = k.as_bytes();
    while let Some(pp) = find_sub(t, k, p) {
        p = pp;
        if p == 0 || t[p - 1] == b'\n' {
            let mut q = p + k.len();
            while q < t.len() && matches!(t[q], b' ' | b'\t' | b'"' | b'\'') {
                q += 1;
            }
            let mut e = q;
            while e < t.len() && !matches!(t[e], b'\n' | b'\r' | b'"' | b'\'') {
                e += 1;
            }
            return sanitize_j(&t[q..e], 80);
        }
        p += k.len();
    }
    String::new()
}

struct Agg {
    name: String,
    m: u64,
    deps: Vec<u32>,
    accessor: bool,
}

pub fn java_finish(acc: &JavaAcc, meta: &BTreeMap<String, Vec<u8>>, jv: &mut JavaProfile) {
    jv.analyzed = acc.any();
    jv.lib_only = acc.lib_only;
    for (k, v) in meta {
        let nl = lower_str(k);
        if nl == "fabric.mod.json" {
            jv.loader = "Fabric".into();
            jv.mod_id = json_str_val(v, "id");
            jv.mod_name = json_str_val(v, "name");
            jv.mod_ver = json_str_val(v, "version");
        } else if nl == "quilt.mod.json" && jv.mod_id.is_empty() {
            jv.loader = "Quilt".into();
            jv.mod_id = json_str_val(v, "id");
            jv.mod_name = json_str_val(v, "name");
            jv.mod_ver = json_str_val(v, "version");
        } else if (nl == "meta-inf/mods.toml" || nl == "meta-inf/neoforge.mods.toml") && jv.mod_id.is_empty() {
            jv.loader = if nl.contains("neoforge") {
                "NeoForge".into()
            } else {
                "Forge".into()
            };
            jv.mod_id = toml_str_val(v, "modId");
            jv.mod_name = toml_str_val(v, "displayName");
            jv.mod_ver = toml_str_val(v, "version");
        } else if nl == "mcmod.info" && jv.mod_id.is_empty() {
            jv.loader = "Forge(eski)".into();
            jv.mod_id = json_str_val(v, "modid");
            jv.mod_name = json_str_val(v, "name");
            jv.mod_ver = json_str_val(v, "version");
        } else if nl == "plugin.yml" || nl == "paper-plugin.yml" || nl == "bungee.yml" {
            jv.server_plugin = true;
            if jv.mod_id.is_empty() {
                jv.loader = "Sunucu eklentisi".into();
                jv.mod_id = yaml_str_val(v, "name");
                jv.mod_ver = yaml_str_val(v, "version");
            }
        } else if nl == "meta-inf/manifest.mf" {
            let lt: Vec<u8> = v.iter().map(|&c| low_c(c)).collect();
            let has = |s: &str| memchr::memmem::find(&lt, s.as_bytes()).is_some();
            if has("premain-class") || has("agent-class") || has("launcher-agent-class") {
                jv.agent = true;
            }
        }
    }
    if !jv.analyzed {
        return;
    }
    jv.classes_total = acc.third_total + acc.vanilla_total;
    jv.mixins = acc.mixin_count;
    jv.natives = acc.native_total;
    jv.third_party = acc.third_total;
    jv.obf_classes = acc.obf_count;
    if acc.third_total >= 12 && acc.obf_count * 10 >= acc.third_total * 6 {
        jv.obfuscated = true;
        jv.obf_note = format!(
            "{}/{} sınıf adı karıştırılmış (a/b/c tarzı)",
            acc.obf_count, acc.third_total
        );
    }
    if acc.demo_obf > 0 {
        jv.obfuscated = true;
        if !jv.obf_note.is_empty() {
            jv.obf_note.push_str("; ");
        }
        jv.obf_note
            .push_str("Allatori DEMO filigranı (ALLATORIxDEMO) - ücretsiz obfuscator, hile jarlarında yaygın");
    }
    let mut ev: Vec<&JClass> = acc.cls.iter().collect();
    if acc.vanilla_total < 200 {
        ev.extend(acc.van.iter());
    }
    jv.classes_eval = ev.len() as i32;
    let mut agg_map: BTreeMap<String, Agg> = BTreeMap::new();
    for c in &ev {
        let on = outer_name(&c.name).to_string();
        let g = agg_map.entry(on.clone()).or_insert_with(|| Agg {
            name: on,
            m: 0,
            deps: Vec::new(),
            accessor: true,
        });
        g.m |= c.m;
        g.deps.extend_from_slice(&c.deps);
        if !(c.mixin && c.iface) {
            g.accessor = false;
        }
    }
    let mut aggs: Vec<Agg> = agg_map.into_values().collect();
    {
        let acc_bits = bit(JF_DO_ATTACK) | bit(JF_USE_ITEM);
        let mut acc_mask: HashMap<u32, u64> = HashMap::new();
        for g in &aggs {
            if g.accessor && (g.m & acc_bits) != 0 {
                acc_mask.insert(fnv32(g.name.as_bytes()), g.m & acc_bits);
            }
        }
        if !acc_mask.is_empty() {
            for g in aggs.iter_mut() {
                if g.accessor {
                    continue;
                }
                let mut add = 0u64;
                for hh in &g.deps {
                    if let Some(v) = acc_mask.get(hh) {
                        add |= *v;
                    }
                }
                g.m |= add;
            }
        }
    }
    let mut by_hash: HashMap<u32, usize> = HashMap::new();
    for (i, g) in aggs.iter().enumerate() {
        by_hash.insert(fnv32(g.name.as_bytes()), i);
    }
    let mut best: BTreeMap<String, JBeh> = BTreeMap::new();
    let mut jm: u64 = 0;
    let mut sd_mask_acc: u64 = 0;
    let note = |best: &mut BTreeMap<String, JBeh>, h: &RuleHit, cls: &str, indirect: bool| match best.get_mut(h.module)
    {
        None => {
            best.insert(
                h.module.to_string(),
                JBeh {
                    module: h.module.to_string(),
                    cls: cls.to_string(),
                    why: h.why.clone(),
                    sev: h.sev,
                    classes: 1,
                    indirect,
                },
            );
        }
        Some(b) => {
            if h.sev > b.sev || (h.sev == b.sev && b.indirect && !indirect) {
                b.sev = h.sev;
                b.cls = cls.to_string();
                b.why = h.why.clone();
                b.indirect = indirect;
            }
            b.classes += 1;
        }
    };
    let k_sd = sd_mask();
    let k_anchor = anchor_mask();
    for (gi, g) in aggs.iter().enumerate() {
        jm |= g.m;
        let mut hits = Vec::new();
        eval_module_rules(g.m, false, &mut hits);
        for h in &hits {
            note(&mut best, h, &g.name, false);
        }
        let sd_anchor = bit(JF_SD_OWNPATH) | bit(JF_SD_MODPATH) | bit(JF_S_SDNAME);
        let sd_direct = eval_self_destruct(g.m & k_sd, jv, &g.name, false);
        if sd_direct {
            sd_mask_acc |= g.m & k_sd;
        }
        if g.m & k_anchor != 0 {
            let mut m2 = g.m;
            let mut d = g.deps.clone();
            d.sort_unstable();
            d.dedup();
            for hh in &d {
                if let Some(&ix) = by_hash.get(hh) {
                    if ix != gi {
                        m2 |= aggs[ix].m;
                    }
                }
            }
            if m2 != g.m {
                let mut h2 = Vec::new();
                eval_module_rules(m2, true, &mut h2);
                for h in &h2 {
                    if h.sev <= 2 {
                        let skip = matches!(best.get(h.module), Some(b) if b.sev >= 2);
                        if !skip {
                            note(&mut best, h, &g.name, true);
                        }
                    }
                }
            }
        }
        if !sd_direct && (g.m & sd_anchor) != 0 {
            let mut m2 = g.m;
            for hh in &g.deps {
                if let Some(&ix) = by_hash.get(hh) {
                    if ix != gi {
                        m2 |= aggs[ix].m;
                    }
                }
            }
            if m2 != g.m && eval_self_destruct(m2 & k_sd, jv, &g.name, true) {
                sd_mask_acc |= m2 & k_sd;
            }
        }
    }
    if acc.bsm_classes >= 3 {
        let ctx = jm
            & !(k_sd
                | bit(JF_TIME)
                | bit(JF_RANDOM)
                | bit(JF_SLEEP)
                | bit(JF_RESSTREAM)
                | bit(JF_CIPHER)
                | bit(JF_DEFCLASS));
        if ctx != 0 || !jv.mod_id.is_empty() || acc.mixin_count > 0 {
            let name = "Çağrı gizleme (invokedynamic obfuscation)";
            let b = JBeh {
                module: name.to_string(),
                cls: acc.bsm_first.clone(),
                sev: 2,
                classes: acc.bsm_classes,
                why: format!("{} sınıfta özel invokedynamic bootstrap: Minecraft API çağrıları sabit havuzundan gizlenmiş (Skidfuscator/Paramorphism tarzı), bytecode davranışı tam çözülemedi - ELLE İNCELEYİN", acc.bsm_classes),
                indirect: false,
            };
            best.insert(name.to_string(), b);
        }
    }
    for (_, b) in best {
        jv.beh.push(b);
    }
    jv.beh.sort_by(|a, b| {
        if a.sev != b.sev {
            return b.sev.cmp(&a.sev);
        }
        a.module.cmp(&b.module)
    });
    sd_notes(sd_mask_acc, jv);
    if (jv.sd_confirmed || jv.sd_suspect) && jv.sd_level < 1 && jv.sd_confirmed {
        jv.sd_level = 1;
    }
    if !(jv.sd_confirmed || jv.sd_suspect) {
        jv.sd_notes.clear();
    }
}

pub fn java_beh_line(jv: &JavaProfile, max_n: usize) -> String {
    let mut s = String::new();
    let mut k = 0usize;
    for b in &jv.beh {
        if k >= max_n {
            s.push_str(&format!(", ... +{}", jv.beh.len() - max_n));
            break;
        }
        k += 1;
        if !s.is_empty() {
            s.push_str(", ");
        }
        s.push_str(&b.module);
        s.push_str(if b.sev >= 3 { "(KESİN)" } else { "(şüpheli)" });
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obf_names() {
        assert!(is_obf_name("a/b"));
        assert!(is_obf_name("x/IIIlll"));
        assert!(!is_obf_name("com/foo/Bar"));
    }
    #[test]
    fn outer() {
        assert_eq!(outer_name("a/B$C"), "a/B");
        assert_eq!(outer_name("$x"), "$x");
    }
    #[test]
    fn rules() {
        let m = bit(JF_CROSSHAIR) | bit(JF_ENT_HIT) | bit(JF_ATK_MGR) | bit(JF_SWING);
        let mut o = Vec::new();
        eval_module_rules(m, false, &mut o);
        assert!(o.iter().any(|h| h.module == "TriggerBot" && h.sev == 3));
        let mut o = Vec::new();
        eval_module_rules(m, true, &mut o);
        assert!(o.iter().all(|h| h.sev <= 2));
    }
    #[test]
    fn json_val() {
        assert_eq!(json_str_val(b"{ \"id\" : \"abc\" }", "id"), "abc");
        assert_eq!(toml_str_val(b"modId = \"x1\"", "modId"), "x1");
        assert_eq!(yaml_str_val(b"name: Foo\n", "name"), "Foo");
    }
    #[test]
    fn db_builds() {
        let db = get_jf_db();
        assert!(db.by_name.contains_key(b"attackentity".as_slice()));
    }
}
