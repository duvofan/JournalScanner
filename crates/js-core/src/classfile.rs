use crate::util::*;
use std::collections::BTreeSet;
use std::sync::Arc;

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Member {
    pub owner: String,
    pub name: String,
    pub desc: String,
}

pub type AVP = Arc<AV>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AvKind {
    #[default]
    None,
    Int,
    Str,
    Enum,
    Class,
    Ann,
    List,
}

#[derive(Debug, Clone, Default)]
pub struct AV {
    pub k: AvKind,
    pub iv: i64,
    pub s: String,
    pub s2: String,
    pub r#type: String,
    pub elems: Vec<(String, AVP)>,
    pub list: Vec<AVP>,
}
impl AV {
    pub fn get(&self, key: &str) -> Option<&AV> {
        self.elems.iter().find(|kv| kv.0 == key).map(|kv| kv.1.as_ref())
    }
}
pub fn flatten_values(v: Option<&AV>, out: &mut StrList) {
    let Some(v) = v else { return };
    match v.k {
        AvKind::Str | AvKind::Class => out.push(v.s.clone()),
        AvKind::List => {
            for x in &v.list {
                flatten_values(Some(x.as_ref()), out);
            }
        }
        AvKind::Enum => out.push(v.s2.clone()),
        AvKind::Ann => {
            for kv in &v.elems {
                flatten_values(Some(kv.1.as_ref()), out);
            }
        }
        _ => {}
    }
}

#[derive(Debug, Clone, Default)]
pub struct Indy {
    pub bo: String,
    pub bn: String,
    pub has_impl: bool,
    pub r#impl: Member,
}

pub type OptInt = Option<i64>;

#[derive(Debug, Clone, Default)]
pub struct MethodBody {
    pub name: String,
    pub desc: String,
    pub access: i32,
    pub invokes: Vec<Member>,
    pub gets: Vec<Member>,
    pub puts: Vec<Member>,
    pub news: BTreeSet<String>,
    pub types: BTreeSet<String>,
    pub strs: StrList,
    pub ints: BTreeSet<i64>,
    pub r#loop: bool,
    pub indy: Vec<Indy>,
    pub raw_indy: Vec<i32>,
    pub code_len: u32,
    pub put_c: Vec<(Member, OptInt)>,
    pub inv_c: Vec<(Member, OptInt)>,
}

#[derive(Debug, Clone, Default)]
pub struct Annot {
    pub r#type: String,
    pub elems: Vec<(String, AVP)>,
}
impl Annot {
    pub fn get(&self, key: &str) -> Option<&AV> {
        self.elems.iter().find(|kv| kv.0 == key).map(|kv| kv.1.as_ref())
    }
}
#[derive(Debug, Clone, Default)]
pub struct MethodAnnot {
    pub mname: String,
    pub mdesc: String,
    pub a: Annot,
}

#[derive(Debug, Clone, Default)]
pub struct MRef {
    pub kind: char,
    pub owner: String,
    pub name: String,
    pub desc: String,
}

#[derive(Debug, Clone, Default)]
pub struct ClassInfo {
    pub name: String,
    pub super_: String,
    pub interfaces: StrList,
    pub utf8: StrList,
    pub strings: StrList,
    pub class_refs: BTreeSet<String>,
    pub member_refs: Vec<MRef>,
    pub class_annotations: Vec<Annot>,
    pub method_annotations: Vec<MethodAnnot>,
    pub field_annotations: Vec<MethodAnnot>,
    pub methods: Vec<(String, String)>,
    pub fields: Vec<(String, String)>,
    pub parse_ok: bool,
    pub field_writes: Vec<Member>,
    pub bodies: Vec<Arc<MethodBody>>,
    pub access: i32,
    pub indy_custom: i32,
}

#[derive(Debug, Clone, Default)]
pub struct ClassParseError {
    pub msg: String,
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn eof() -> ClassParseError {
        ClassParseError { msg: "eof".to_string() }
    }
    fn u1(&mut self) -> Result<u32, ClassParseError> {
        let v = *self.b.get(self.p).ok_or_else(Self::eof)?;
        self.p += 1;
        Ok(v as u32)
    }
    fn u2(&mut self) -> Result<u32, ClassParseError> {
        let s = self.b.get(self.p..self.p.saturating_add(2)).ok_or_else(Self::eof)?;
        self.p += 2;
        Ok(u16::from_be_bytes([s[0], s[1]]) as u32)
    }
    fn u4(&mut self) -> Result<u32, ClassParseError> {
        let s = self.b.get(self.p..self.p.saturating_add(4)).ok_or_else(Self::eof)?;
        self.p += 4;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn skip(&mut self, k: usize) -> Result<(), ClassParseError> {
        self.p = self.p.saturating_add(k);
        if self.p > self.b.len() {
            return Err(Self::eof());
        }
        Ok(())
    }
    fn raw(&mut self, k: usize) -> Result<&'a [u8], ClassParseError> {
        let s = self.b.get(self.p..self.p.saturating_add(k)).ok_or_else(Self::eof)?;
        self.p += k;
        Ok(s)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum CpTag {
    #[default]
    None,
    U,
    Int,
    C,
    S,
    F,
    M,
    I,
    Nt,
    Mh,
    Dy,
}

#[derive(Clone, Default)]
struct CpE {
    t: CpTag,
    a: i32,
    b: i32,
    iv: i64,
    si: usize,
}

fn mutf8(raw: &[u8]) -> String {
    let mut r: Vec<u8> = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == 0xC0 && raw.get(i + 1) == Some(&0x80) {
            r.push(0);
            i += 2;
        } else {
            r.push(raw[i]);
            i += 1;
        }
    }
    if let Ok(s) = std::str::from_utf8(&r) {
        return s.to_string();
    }
    let mut w: Vec<u8> = Vec::with_capacity(r.len());
    let mut j = 0;
    while j < r.len() {
        if r[j] == 0xED && matches!(r.get(j + 1), Some(0xA0..=0xBF)) && matches!(r.get(j + 2), Some(0x80..=0xBF)) {
            w.extend_from_slice("\u{FFFD}".as_bytes());
            j += 3;
        } else {
            w.push(r[j]);
            j += 1;
        }
    }
    if let Ok(s) = String::from_utf8(w) {
        return s;
    }
    raw.iter().map(|&c| c as char).collect()
}

const fn build_oplen() -> [i8; 256] {
    let mut v = [1i8; 256];
    let two = [
        0x10usize, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3a, 0xa9, 0xbc,
    ];
    let mut i = 0;
    while i < two.len() {
        v[two[i]] = 2;
        i += 1;
    }
    let mut o = 0x99;
    while o < 0xa9 {
        v[o] = 3;
        o += 1;
    }
    let three = [
        0x11usize, 0x13, 0x14, 0x84, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xbb, 0xbd, 0xc0, 0xc1, 0xc6, 0xc7,
    ];
    i = 0;
    while i < three.len() {
        v[three[i]] = 3;
        i += 1;
    }
    v[0xc5] = 4;
    let five = [0xb9usize, 0xba, 0xc8, 0xc9];
    i = 0;
    while i < five.len() {
        v[five[i]] = 5;
        i += 1;
    }
    let var = [0xaausize, 0xab, 0xc4];
    i = 0;
    while i < var.len() {
        v[var[i]] = 0;
        i += 1;
    }
    o = 0xca;
    while o < 0x100 {
        v[o] = -1;
        o += 1;
    }
    v
}
static OPLEN: [i8; 256] = build_oplen();

const STD_BSM: [&str; 6] = [
    "java/lang/invoke/LambdaMetafactory",
    "java/lang/invoke/StringConcatFactory",
    "java/lang/runtime/ObjectMethods",
    "java/lang/runtime/SwitchBootstraps",
    "java/lang/invoke/ConstantBootstraps",
    "kotlin/jvm/internal/LambdaMetafactory",
];
fn std_bsm(o: &str) -> bool {
    STD_BSM.contains(&o)
}

struct Ctx {
    cp: Vec<CpE>,
    ustore: StrList,
    cpn: i32,
}
impl Ctx {
    fn entry(&self, idx: i32) -> Option<&CpE> {
        if idx > 0 && idx < self.cpn {
            self.cp.get(idx as usize)
        } else {
            None
        }
    }
    fn u(&self, idx: i32) -> Option<&String> {
        let e = self.entry(idx)?;
        if e.t == CpTag::U {
            self.ustore.get(e.si)
        } else {
            None
        }
    }
    fn us(&self, idx: i32) -> &str {
        self.u(idx).map_or("", |s| s.as_str())
    }
    fn c(&self, idx: i32) -> &str {
        match self.entry(idx) {
            Some(e) if e.t == CpTag::C => self.us(e.a),
            _ => "",
        }
    }
    fn member(&self, idx: i32) -> Option<Member> {
        let e = self.entry(idx)?;
        if e.t != CpTag::F && e.t != CpTag::M && e.t != CpTag::I {
            return None;
        }
        let owner = self.c(e.a);
        if owner.is_empty() {
            return None;
        }
        let nt = self.entry(e.b)?;
        if nt.t != CpTag::Nt {
            return None;
        }
        Some(Member {
            owner: owner.to_string(),
            name: self.us(nt.a).to_string(),
            desc: self.us(nt.b).to_string(),
        })
    }
    fn mh_member(&self, idx: i32) -> Option<Member> {
        match self.entry(idx) {
            Some(e) if e.t == CpTag::Mh => self.member(e.b),
            _ => None,
        }
    }
}

fn be16(b: &[u8], p: usize) -> u16 {
    match b.get(p..p.saturating_add(2)) {
        Some(s) => u16::from_be_bytes([s[0], s[1]]),
        None => 0,
    }
}
fn be32(b: &[u8], p: usize) -> u32 {
    match b.get(p..p.saturating_add(4)) {
        Some(s) => u32::from_be_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}

fn walk_code(cx: &Ctx, b: &[u8], start: usize, end: usize, body: &mut MethodBody) {
    let n = b.len();
    let mut p = start.saturating_add(4);
    if p.saturating_add(4) > n {
        return;
    }
    let clen = be32(b, p);
    p += 4;
    let c0 = p;
    let cend = c0.saturating_add(clen as usize).min(end);
    body.code_len = clen;
    let mut last_c: OptInt = None;
    let need = |k: usize| k <= n;
    while p < cend {
        if p >= n {
            return;
        }
        let op = b[p] as u32;
        let mut ln = OPLEN[op as usize] as i32;
        if ln < 0 {
            return;
        }
        let mut cur_c: OptInt = None;
        if (0xb2..=0xb9).contains(&op) {
            if !need(p + 3) {
                return;
            }
            if let Some(m) = cx.member(be16(b, p + 1) as i32) {
                if op == 0xb2 || op == 0xb4 {
                    body.gets.push(m);
                } else if op == 0xb3 || op == 0xb5 {
                    body.puts.push(m.clone());
                    body.put_c.push((m, last_c));
                } else {
                    body.invokes.push(m.clone());
                    body.inv_c.push((m, last_c));
                }
            }
        } else if op == 0xbb || op == 0xc0 || op == 0xc1 || op == 0xbd || op == 0xc5 {
            if !need(p + 3) {
                return;
            }
            let c = cx.c(be16(b, p + 1) as i32);
            if !c.is_empty() {
                if op == 0xbb {
                    body.news.insert(c.to_string());
                } else {
                    body.types.insert(c.to_string());
                }
            }
        } else if op == 0xba {
            if !need(p + 3) {
                return;
            }
            body.raw_indy.push(be16(b, p + 1) as i32);
        } else if op == 0x12 || op == 0x13 {
            if !need(p + if op == 0x12 { 2 } else { 3 }) {
                return;
            }
            let idx = if op == 0x12 {
                b[p + 1] as i32
            } else {
                be16(b, p + 1) as i32
            };
            if let Some(e) = cx.entry(idx) {
                match e.t {
                    CpTag::S => {
                        if let Some(sv) = cx.u(e.a) {
                            body.strs.push(sv.clone());
                        }
                    }
                    CpTag::Int => {
                        body.ints.insert(e.iv);
                        cur_c = Some(e.iv);
                    }
                    CpTag::C => {
                        let c = cx.us(e.a);
                        if !c.is_empty() {
                            body.types.insert(c.to_string());
                        }
                    }
                    _ => {}
                }
            }
        } else if (0x02..=0x08).contains(&op) {
            body.ints.insert(op as i64 - 3);
            cur_c = Some(op as i64 - 3);
        } else if op == 0x10 {
            if !need(p + 2) {
                return;
            }
            let v = b[p + 1] as i8 as i64;
            cur_c = Some(v);
            body.ints.insert(v);
        } else if op == 0x11 {
            if !need(p + 3) {
                return;
            }
            let v = be16(b, p + 1) as i16 as i64;
            cur_c = Some(v);
            body.ints.insert(v);
        } else if op == 0x0b || op == 0x0e {
            cur_c = Some(0);
        } else if op == 0x0c || op == 0x0f {
            cur_c = Some(1);
        } else if (0x99..=0xa7).contains(&op) || op == 0xc6 || op == 0xc7 {
            if !need(p + 3) {
                return;
            }
            if (be16(b, p + 1) as i16) < 0 {
                body.r#loop = true;
            }
        } else if op == 0xc8 {
            if !need(p + 5) {
                return;
            }
            if (be32(b, p + 1) as i32) < 0 {
                body.r#loop = true;
            }
        }
        if ln == 0 {
            if op == 0xc4 {
                if !need(p + 2) {
                    return;
                }
                ln = if b[p + 1] == 0x84 { 6 } else { 4 };
            } else {
                let mut q = p + 1;
                q += (4 - ((q - c0) % 4)) % 4;
                if op == 0xaa {
                    if !need(q + 12) {
                        return;
                    }
                    let lo = be32(b, q + 4) as i32 as i64;
                    let hi = be32(b, q + 8) as i32 as i64;
                    if hi < lo || hi - lo > 65535 {
                        return;
                    }
                    q += 12 + ((hi - lo + 1) as usize) * 4;
                } else {
                    if !need(q + 8) {
                        return;
                    }
                    let np = be32(b, q + 4) as i32;
                    if !(0..=65535).contains(&np) {
                        return;
                    }
                    q += 8 + (np as usize) * 8;
                }
                ln = (q - p) as i32;
            }
        }
        last_c = cur_c;
        p += ln as usize;
    }
}

const MAX_ANN_DEPTH: u32 = 512;

struct Bsm {
    mh: i32,
    args: Vec<i32>,
}

struct Parser<'a> {
    r: Reader<'a>,
    cx: Ctx,
    bsms: Vec<Bsm>,
}
impl Parser<'_> {
    fn ev(&mut self, depth: u32) -> Result<AVP, ClassParseError> {
        let mut v = AV::default();
        let tag = self.r.u1()? as u8;
        if tag != 0 && b"BCDFIJSZ".contains(&tag) {
            let idx = self.r.u2()? as i32;
            if b"IBSCZ".contains(&tag) {
                if let Some(e) = self.cx.entry(idx) {
                    if e.t == CpTag::Int {
                        v.k = AvKind::Int;
                        v.iv = e.iv;
                    }
                }
            }
            return Ok(Arc::new(v));
        }
        match tag {
            b's' => {
                let idx = self.r.u2()? as i32;
                if let Some(s) = self.cx.u(idx) {
                    v.k = AvKind::Str;
                    v.s = s.clone();
                }
                Ok(Arc::new(v))
            }
            b'e' => {
                v.k = AvKind::Enum;
                let a = self.r.u2()? as i32;
                v.s = self.cx.us(a).to_string();
                let b = self.r.u2()? as i32;
                v.s2 = self.cx.us(b).to_string();
                Ok(Arc::new(v))
            }
            b'c' => {
                v.k = AvKind::Class;
                let a = self.r.u2()? as i32;
                v.s = self.cx.us(a).to_string();
                Ok(Arc::new(v))
            }
            b'@' => Ok(Arc::new(self.annotation(depth + 1)?)),
            b'[' => {
                v.k = AvKind::List;
                let cnt = self.r.u2()?;
                if depth >= MAX_ANN_DEPTH {
                    return Err(ClassParseError {
                        msg: "annotation too deep".to_string(),
                    });
                }
                for _ in 0..cnt {
                    let x = self.ev(depth + 1)?;
                    v.list.push(x);
                }
                Ok(Arc::new(v))
            }
            _ => Err(ClassParseError {
                msg: "bad element tag".to_string(),
            }),
        }
    }

    fn annotation(&mut self, depth: u32) -> Result<AV, ClassParseError> {
        if depth >= MAX_ANN_DEPTH {
            return Err(ClassParseError {
                msg: "annotation too deep".to_string(),
            });
        }
        let mut v = AV {
            k: AvKind::Ann,
            ..Default::default()
        };
        let t = self.r.u2()? as i32;
        v.r#type = self.cx.us(t).to_string();
        let cnt = self.r.u2()?;
        for _ in 0..cnt {
            let ki = self.r.u2()? as i32;
            let key = self.cx.us(ki).to_string();
            let val = self.ev(depth + 1)?;
            match v.elems.iter_mut().find(|kv| kv.0 == key) {
                Some(kv) => kv.1 = val,
                None => v.elems.push((key, val)),
            }
        }
        Ok(v)
    }

    fn bootstrap(&mut self) -> Result<(), ClassParseError> {
        let nb = self.r.u2()?;
        for _ in 0..nb {
            let mh = self.r.u2()? as i32;
            let na = self.r.u2()?;
            let mut args = Vec::new();
            for _ in 0..na {
                args.push(self.r.u2()? as i32);
            }
            self.bsms.push(Bsm { mh, args });
        }
        Ok(())
    }

    fn annotations(&mut self, sink: &mut Vec<Annot>) -> Result<(), ClassParseError> {
        let na = self.r.u2()?;
        for _ in 0..na {
            let a = self.annotation(0)?;
            sink.push(Annot {
                r#type: a.r#type,
                elems: a.elems,
            });
        }
        Ok(())
    }

    fn attributes(
        &mut self,
        sink: &mut Vec<Annot>,
        mut code: Option<&mut MethodBody>,
        is_class: bool,
    ) -> Result<(), ClassParseError> {
        let cnt = self.r.u2()?;
        for _ in 0..cnt {
            let ni = self.r.u2()? as i32;
            let ln = self.r.u4()?;
            let end = self.r.p.saturating_add(ln as usize);
            let an = self.cx.us(ni);
            let is_code = an == "Code";
            let is_bsm = an == "BootstrapMethods";
            let is_ann = an == "RuntimeVisibleAnnotations" || an == "RuntimeInvisibleAnnotations";
            if let (true, Some(body)) = (is_code, code.as_deref_mut()) {
                walk_code(&self.cx, self.r.b, self.r.p, end, body);
            } else if code.is_none() && is_class && is_bsm {
                let _ = self.bootstrap();
            } else if is_ann {
                let _ = self.annotations(sink);
            }
            self.r.p = end;
        }
        Ok(())
    }
}

pub fn parse_class(data: &[u8]) -> Result<Arc<ClassInfo>, ClassParseError> {
    let mut ci = ClassInfo::default();
    let mut r = Reader { b: data, p: 0 };
    if data.len() < 10 || r.u4()? != 0xCAFE_BABE {
        return Err(ClassParseError {
            msg: "not a class".to_string(),
        });
    }
    r.u2()?;
    r.u2()?;
    let n = r.u2()? as i32;
    let mut cx = Ctx {
        cp: vec![CpE::default(); n.max(1) as usize],
        ustore: Vec::new(),
        cpn: n,
    };
    let mut i: i32 = 1;
    while i < n {
        let tag = r.u1()?;
        let idx0 = i as usize;
        let mut e = CpE::default();
        match tag {
            1 => {
                let ln = r.u2()? as usize;
                let s = mutf8(r.raw(ln)?);
                e.t = CpTag::U;
                e.si = cx.ustore.len();
                cx.ustore.push(s);
            }
            3 => {
                let v = r.raw(4)?;
                e.t = CpTag::Int;
                e.iv = i32::from_be_bytes([v[0], v[1], v[2], v[3]]) as i64;
            }
            4 => r.skip(4)?,
            5 | 6 => {
                r.skip(8)?;
                i += 1;
            }
            7 => {
                e.t = CpTag::C;
                e.a = r.u2()? as i32;
            }
            8 => {
                e.t = CpTag::S;
                e.a = r.u2()? as i32;
            }
            9..=11 => {
                e.t = match tag {
                    9 => CpTag::F,
                    10 => CpTag::M,
                    _ => CpTag::I,
                };
                e.a = r.u2()? as i32;
                e.b = r.u2()? as i32;
            }
            12 => {
                e.t = CpTag::Nt;
                e.a = r.u2()? as i32;
                e.b = r.u2()? as i32;
            }
            15 => {
                e.t = CpTag::Mh;
                e.a = r.u1()? as i32;
                e.b = r.u2()? as i32;
            }
            16 => r.skip(2)?,
            17 | 18 => {
                e.t = CpTag::Dy;
                e.a = r.u2()? as i32;
                e.b = r.u2()? as i32;
            }
            19 | 20 => r.skip(2)?,
            _ => {
                return Err(ClassParseError {
                    msg: format!("bad cp tag {}", tag),
                })
            }
        }
        if let Some(d) = cx.cp.get_mut(idx0) {
            *d = e;
        }
        i += 1;
    }
    for k in 1..n {
        let e = cx.cp[k as usize].clone();
        match e.t {
            CpTag::C => {
                if let Some(nm) = cx.u(e.a) {
                    if !nm.is_empty() {
                        ci.class_refs.insert(nm.clone());
                    }
                }
            }
            CpTag::S => {
                if let Some(s) = cx.u(e.a) {
                    ci.strings.push(s.clone());
                }
            }
            CpTag::F | CpTag::M | CpTag::I => {
                let owner = cx.c(e.a);
                if !owner.is_empty() && e.b > 0 && e.b < n {
                    if let Some(nt) = cx.cp.get(e.b as usize) {
                        if nt.t == CpTag::Nt {
                            let kind = match e.t {
                                CpTag::F => 'F',
                                CpTag::M => 'M',
                                _ => 'I',
                            };
                            ci.member_refs.push(MRef {
                                kind,
                                owner: owner.to_string(),
                                name: cx.us(nt.a).to_string(),
                                desc: cx.us(nt.b).to_string(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    ci.access = r.u2()? as i32;
    let t = r.u2()? as i32;
    ci.name = cx.c(t).to_string();
    let t = r.u2()? as i32;
    ci.super_ = cx.c(t).to_string();
    let ni = r.u2()?;
    for _ in 0..ni {
        let t = r.u2()? as i32;
        ci.interfaces.push(cx.c(t).to_string());
    }

    let mut ps = Parser {
        r,
        cx,
        bsms: Vec::new(),
    };
    let mut bodies: Vec<MethodBody> = Vec::new();
    let mut class_sink: Vec<Annot> = Vec::new();

    let res: Result<(), ClassParseError> = (|| {
        let nf = ps.r.u2()?;
        for _ in 0..nf {
            ps.r.u2()?;
            let a = ps.r.u2()? as i32;
            let fname = ps.cx.us(a).to_string();
            let a = ps.r.u2()? as i32;
            let fdesc = ps.cx.us(a).to_string();
            ci.fields.push((fname.clone(), fdesc.clone()));
            let mut anns = Vec::new();
            ps.attributes(&mut anns, None, false)?;
            for a in anns {
                ci.field_annotations.push(MethodAnnot {
                    mname: fname.clone(),
                    mdesc: fdesc.clone(),
                    a,
                });
            }
        }
        let nm = ps.r.u2()?;
        for _ in 0..nm {
            let macc = ps.r.u2()? as i32;
            let a = ps.r.u2()? as i32;
            let mname = ps.cx.us(a).to_string();
            let a = ps.r.u2()? as i32;
            let mdesc = ps.cx.us(a).to_string();
            ci.methods.push((mname.clone(), mdesc.clone()));
            bodies.push(MethodBody {
                name: mname.clone(),
                desc: mdesc.clone(),
                access: macc,
                ..Default::default()
            });
            let mut anns = Vec::new();
            ps.attributes(&mut anns, bodies.last_mut(), false)?;
            for a in anns {
                ci.method_annotations.push(MethodAnnot {
                    mname: mname.clone(),
                    mdesc: mdesc.clone(),
                    a,
                });
            }
        }
        ps.attributes(&mut class_sink, None, true)?;
        ci.class_annotations = std::mem::take(&mut class_sink);
        ci.parse_ok = true;
        Ok(())
    })();
    if res.is_err() {
        ci.parse_ok = false;
    }

    let cx = &ps.cx;
    let bsms = &ps.bsms;
    let mut seen_w: BTreeSet<Member> = BTreeSet::new();
    for b in bodies.iter_mut() {
        let raw = std::mem::take(&mut b.raw_indy);
        for idx in raw {
            let Some(e) = cx.entry(idx) else { continue };
            if e.t != CpTag::Dy || e.a as usize >= bsms.len() {
                continue;
            }
            let bm = &bsms[e.a as usize];
            let mut ind = Indy::default();
            match cx.mh_member(bm.mh) {
                Some(bmm) => {
                    ind.bo = bmm.owner;
                    ind.bn = bmm.name;
                }
                None => {
                    ind.bo = "?".to_string();
                    ind.bn = "?".to_string();
                }
            }
            if std_bsm(&ind.bo) {
                let mut has = false;
                let mut imp = Member::default();
                for &a in &bm.args {
                    if let Some(ae) = cx.entry(a) {
                        if ae.t == CpTag::Mh {
                            let m = cx.member(ae.b);
                            has = m.is_some();
                            if let Some(m) = m {
                                imp = m;
                            }
                        }
                    }
                }
                ind.has_impl = has;
                if has {
                    ind.r#impl = imp;
                }
            } else {
                ci.indy_custom += 1;
            }
            b.indy.push(ind);
        }
        for w in &b.puts {
            if seen_w.insert(w.clone()) {
                ci.field_writes.push(w.clone());
            }
        }
    }
    ci.bodies = bodies.into_iter().map(Arc::new).collect();
    ci.utf8 = std::mem::take(&mut ps.cx.ustore);
    Ok(Arc::new(ci))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct B {
        cp: Vec<u8>,
        n: u16,
    }
    impl B {
        fn new() -> Self {
            B { cp: Vec::new(), n: 1 }
        }
        fn utf8(&mut self, s: &str) -> u16 {
            self.cp.push(1);
            self.cp.extend_from_slice(&(s.len() as u16).to_be_bytes());
            self.cp.extend_from_slice(s.as_bytes());
            self.n += 1;
            self.n - 1
        }
        fn two(&mut self, tag: u8, a: u16, b: u16) -> u16 {
            self.cp.push(tag);
            self.cp.extend_from_slice(&a.to_be_bytes());
            self.cp.extend_from_slice(&b.to_be_bytes());
            self.n += 1;
            self.n - 1
        }
        fn one(&mut self, tag: u8, a: u16) -> u16 {
            self.cp.push(tag);
            self.cp.extend_from_slice(&a.to_be_bytes());
            self.n += 1;
            self.n - 1
        }
        fn mh(&mut self, kind: u8, r: u16) -> u16 {
            self.cp.push(15);
            self.cp.push(kind);
            self.cp.extend_from_slice(&r.to_be_bytes());
            self.n += 1;
            self.n - 1
        }
        fn int(&mut self, v: i32) -> u16 {
            self.cp.push(3);
            self.cp.extend_from_slice(&v.to_be_bytes());
            self.n += 1;
            self.n - 1
        }
        fn long(&mut self, v: i64) -> u16 {
            self.cp.push(5);
            self.cp.extend_from_slice(&v.to_be_bytes());
            self.n += 2;
            self.n - 2
        }
        fn class(&mut self, name: &str) -> u16 {
            let u = self.utf8(name);
            self.one(7, u)
        }
        fn mref(&mut self, tag: u8, owner: &str, name: &str, desc: &str) -> u16 {
            let c = self.class(owner);
            let n = self.utf8(name);
            let d = self.utf8(desc);
            let nt = self.two(12, n, d);
            self.two(tag, c, nt)
        }
        fn head(&self, this: u16, sup: u16) -> Vec<u8> {
            let mut v = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52];
            v.extend_from_slice(&self.n.to_be_bytes());
            v.extend_from_slice(&self.cp);
            v.extend_from_slice(&0x21u16.to_be_bytes());
            v.extend_from_slice(&this.to_be_bytes());
            v.extend_from_slice(&sup.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v
        }
    }
    fn u2(v: &mut Vec<u8>, x: u16) {
        v.extend_from_slice(&x.to_be_bytes());
    }
    fn u4(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_be_bytes());
    }
    fn class_with_code(b: &mut B, code: &[u8]) -> Vec<u8> {
        let this = b.class("a/B");
        let sup = b.class("java/lang/Object");
        let code_n = b.utf8("Code");
        let mn = b.utf8("run");
        let md = b.utf8("()V");
        let mut v = b.head(this, sup);
        u2(&mut v, 0); // alan
        u2(&mut v, 1); // metot
        u2(&mut v, 1);
        u2(&mut v, mn);
        u2(&mut v, md);
        u2(&mut v, 1); // öznitelik
        u2(&mut v, code_n);
        u4(&mut v, 12 + code.len() as u32);
        u2(&mut v, 2);
        u2(&mut v, 2);
        u4(&mut v, code.len() as u32);
        v.extend_from_slice(code);
        u2(&mut v, 0); // istisna tablosu
        u2(&mut v, 0); // öznitelik
        u2(&mut v, 0); // sınıf öznitelik
        v
    }

    #[test]
    fn not_a_class() {
        assert!(parse_class(b"").is_err());
        assert!(parse_class(b"hello world!").is_err());
        assert!(parse_class(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 0]).is_err());
    }

    #[test]
    fn basic_names_and_code() {
        let mut b = B::new();
        let get = b.mref(9, "x/Y", "f", "I");
        let put = b.mref(9, "x/Y", "g", "I");
        let inv = b.mref(10, "x/Z", "m", "()V");
        let s = b.utf8("merhaba");
        let sc = b.one(8, s);
        let ic = b.int(1234567);
        let mut code = vec![0xb2];
        code.extend_from_slice(&get.to_be_bytes());
        code.extend_from_slice(&[0x10, 0xfe]); // bipush -2
        code.push(0xb3);
        code.extend_from_slice(&put.to_be_bytes());
        code.push(0xb6);
        code.extend_from_slice(&inv.to_be_bytes());
        code.extend_from_slice(&[0x12, sc as u8]);
        code.extend_from_slice(&[0x12, ic as u8]);
        code.extend_from_slice(&[0xa7, 0xff, 0xf0]); // geri dal -> loop
        code.push(0xb1);
        let data = class_with_code(&mut b, &code);
        let ci = parse_class(&data).unwrap();
        assert!(ci.parse_ok);
        assert_eq!(ci.name, "a/B");
        assert_eq!(ci.super_, "java/lang/Object");
        assert_eq!(ci.methods, vec![("run".to_string(), "()V".to_string())]);
        let body = &ci.bodies[0];
        assert_eq!(
            body.gets[0],
            Member {
                owner: "x/Y".into(),
                name: "f".into(),
                desc: "I".into()
            }
        );
        assert_eq!(body.puts[0].name, "g");
        assert_eq!(body.put_c[0].1, Some(-2));
        assert_eq!(body.invokes[0].name, "m");
        assert!(body.strs.contains(&"merhaba".to_string()));
        assert!(body.ints.contains(&1234567) && body.ints.contains(&-2));
        assert!(body.r#loop);
        assert_eq!(body.code_len, code.len() as u32);
        assert_eq!(ci.field_writes.len(), 1);
        assert!(ci.strings.contains(&"merhaba".to_string()));
        assert!(ci.class_refs.contains("x/Z"));
        assert!(ci.member_refs.iter().any(|m| m.kind == 'M' && m.name == "m"));
        assert!(ci.utf8.contains(&"Code".to_string()));
    }

    #[test]
    fn wide_long_and_switch() {
        let mut b = B::new();
        b.long(5); // iki yuva
        let mut code = vec![0xc4, 0x84, 0, 1, 0, 2]; // wide iinc
        code.extend_from_slice(&[0xc4, 0x15, 0, 1]); // wide iload
        code.push(0xaa); // tableswitch, p = 10 -> hizalama
        let q = code.len();
        let pad = (4 - (q % 4)) % 4;
        code.extend(std::iter::repeat_n(0, pad));
        u4(&mut code, 0);
        u4(&mut code, 0);
        u4(&mut code, 1);
        u4(&mut code, 0);
        u4(&mut code, 0);
        code.push(0x05); // iconst_2
        let data = class_with_code(&mut b, &code);
        let ci = parse_class(&data).unwrap();
        assert!(ci.bodies[0].ints.contains(&2));
    }

    #[test]
    fn invalid_opcode_stops() {
        let mut b = B::new();
        let data = class_with_code(&mut b, &[0x05, 0xff, 0x06]);
        let ci = parse_class(&data).unwrap();
        assert!(ci.bodies[0].ints.contains(&2));
        assert!(!ci.bodies[0].ints.contains(&3));
    }

    #[test]
    fn invokedynamic_resolution() {
        let mut b = B::new();
        let imp = b.mref(10, "p/Q", "lambda$0", "()V");
        let mh_impl = b.mh(6, imp);
        let bsm_ref = b.mref(10, "java/lang/invoke/LambdaMetafactory", "metafactory", "()V");
        let mh_bsm = b.mh(6, bsm_ref);
        let nm = b.utf8("run");
        let ds = b.utf8("()V");
        let nt = b.two(12, nm, ds);
        let dy = b.two(18, 0, nt);
        let this = b.class("a/B");
        let sup = b.class("java/lang/Object");
        let code_n = b.utf8("Code");
        let bsm_n = b.utf8("BootstrapMethods");
        let mn = b.utf8("run");
        let md = b.utf8("()V");
        let mut code = vec![0xba];
        code.extend_from_slice(&dy.to_be_bytes());
        code.extend_from_slice(&[0, 0]);
        let mut v = b.head(this, sup);
        u2(&mut v, 0);
        u2(&mut v, 1);
        u2(&mut v, 1);
        u2(&mut v, mn);
        u2(&mut v, md);
        u2(&mut v, 1);
        u2(&mut v, code_n);
        u4(&mut v, 12 + code.len() as u32);
        u2(&mut v, 2);
        u2(&mut v, 2);
        u4(&mut v, code.len() as u32);
        v.extend_from_slice(&code);
        u2(&mut v, 0);
        u2(&mut v, 0);
        u2(&mut v, 1); // sınıf öznitelikleri
        u2(&mut v, bsm_n);
        u4(&mut v, 8);
        u2(&mut v, 1);
        u2(&mut v, mh_bsm);
        u2(&mut v, 1);
        u2(&mut v, mh_impl);
        let ci = parse_class(&v).unwrap();
        assert!(ci.parse_ok);
        let ind = &ci.bodies[0].indy[0];
        assert_eq!(ind.bo, "java/lang/invoke/LambdaMetafactory");
        assert!(ind.has_impl);
        assert_eq!(ind.r#impl.name, "lambda$0");
        assert_eq!(ci.indy_custom, 0);
        assert!(ci.bodies[0].raw_indy.is_empty());
    }

    #[test]
    fn annotations_and_dedup() {
        let mut b = B::new();
        let this = b.class("a/B");
        let sup = b.class("java/lang/Object");
        let rva = b.utf8("RuntimeVisibleAnnotations");
        let t = b.utf8("LFoo;");
        let k = b.utf8("v");
        let sv = b.utf8("değer");
        let sv2 = b.utf8("değer2");
        let mut v = b.head(this, sup);
        u2(&mut v, 0);
        u2(&mut v, 0);
        u2(&mut v, 1);
        u2(&mut v, rva);
        let mut body = Vec::new();
        u2(&mut body, 1);
        u2(&mut body, t);
        u2(&mut body, 2); // iki eleman, aynı anahtar
        u2(&mut body, k);
        body.push(b's');
        u2(&mut body, sv);
        u2(&mut body, k);
        body.push(b's');
        u2(&mut body, sv2);
        u4(&mut v, body.len() as u32);
        v.extend_from_slice(&body);
        let ci = parse_class(&v).unwrap();
        assert!(ci.parse_ok);
        assert_eq!(ci.class_annotations.len(), 1);
        let a = &ci.class_annotations[0];
        assert_eq!(a.r#type, "LFoo;");
        assert_eq!(a.elems.len(), 1);
        assert_eq!(a.get("v").unwrap().s, "değer2");
        let mut out = Vec::new();
        flatten_values(a.get("v"), &mut out);
        assert_eq!(out, vec!["değer2".to_string()]);
    }

    #[test]
    fn deep_annotation_nesting_is_safe() {
        let mut b = B::new();
        let this = b.class("a/B");
        let sup = b.class("java/lang/Object");
        let rva = b.utf8("RuntimeVisibleAnnotations");
        let mut v = b.head(this, sup);
        u2(&mut v, 0);
        u2(&mut v, 0);
        u2(&mut v, 1);
        u2(&mut v, rva);
        let mut body = Vec::new();
        u2(&mut body, 1);
        u2(&mut body, 0);
        u2(&mut body, 1);
        u2(&mut body, 0);
        for _ in 0..100_000 {
            body.push(b'[');
            u2(&mut body, 1);
        }
        u4(&mut v, body.len() as u32);
        v.extend_from_slice(&body);
        let ci = parse_class(&v).unwrap();
        assert!(ci.parse_ok);
        assert!(ci.class_annotations.is_empty());
    }

    #[test]
    fn huge_counts_do_not_allocate() {
        let v = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0xff, 0xff, 1, 0xff, 0xff];
        assert!(parse_class(&v).is_err());
        let v = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 3, 99, 0, 0];
        assert!(parse_class(&v).is_err());
    }

    #[test]
    fn every_truncation_and_mutation_is_safe() {
        let mut b = B::new();
        let get = b.mref(9, "x/Y", "f", "I");
        let mut code = vec![0xb2];
        code.extend_from_slice(&get.to_be_bytes());
        code.extend_from_slice(&[0xaa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]);
        let data = class_with_code(&mut b, &code);
        assert!(parse_class(&data).is_ok());
        for k in 0..data.len() {
            let _ = parse_class(&data[..k]);
        }
        let mut seed: u32 = 12345;
        for _ in 0..4000 {
            let mut d = data.clone();
            for _ in 0..3 {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                let pos = (seed >> 8) as usize % d.len();
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                d[pos] = (seed >> 16) as u8;
            }
            let _ = parse_class(&d);
        }
    }
}
