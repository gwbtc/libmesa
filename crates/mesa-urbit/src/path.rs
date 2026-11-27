//! Urbit-Mesa path rendering for comet identities and small fixture names.
//! Syllables pinned to hoon.hoon 9f437ff097a0e3836fea7875a568b6192eef6a27.
use crate::Error;
const PREFIX: &str = "dozmarbinwansamlitsighidfidlissogdirwacsabwissibrigsoldopmodfoglidhopdardorlorhodfolrintogsilmirholpaslacrovlivdalsatlibtabhanticpidtorbolfosdotlosdilforpilramtirwintadbicdifrocwidbisdasmidloprilnardapmolsanlocnovsitnidtipsicropwitnatpanminritpodmottamtolsavposnapnopsomfinfonbanmorworsipronnorbotwicsocwatdolmagpicdavbidbaltimtasmalligsivtagpadsaldivdactansidfabtarmonranniswolmispallasdismaprabtobrollatlonnodnavfignomnibpagsopralbilhaddocridmocpacravripfaltodtiltinhapmicfanpattaclabmogsimsonpinlomrictapfirhasbosbatpochactidhavsaplindibhosdabbitbarracparloddosbortochilmactomdigfilfasmithobharmighinradmashalraglagfadtopmophabnilnosmilfopfamdatnoldinhatnacrisfotribhocnimlarfitwalrapsarnalmoslandondanladdovrivbacpollaptalpitnambonrostonfodponsovnocsorlavmatmipfip";
const SUFFIX: &str = "zodnecbudwessevpersutletfulpensytdurwepserwylsunrypsyxdyrnuphebpeglupdepdysputlughecryttyvsydnexlunmeplutseppesdelsulpedtemledtulmetwenbynhexfebpyldulhetmevruttylwydtepbesdexsefwycburderneppurrysrebdennutsubpetrulsynregtydsupsemwynrecmegnetsecmulnymtevwebsummutnyxrextebfushepbenmuswyxsymselrucdecwexsyrwetdylmynmesdetbetbeltuxtugmyrpelsyptermebsetdutdegtexsurfeltudnuxruxrenwytnubmedlytdusnebrumtynseglyxpunresredfunrevrefmectedrusbexlebduxrynnumpyxrygryxfeptyrtustyclegnemfermertenlusnussyltecmexpubrymtucfyllepdebbermughuttunbylsudpemdevlurdefbusbeprunmelpexdytbyttyplevmylwedducfurfexnulluclennerlexrupnedlecrydlydfenwelnydhusrelrudneshesfetdesretdunlernyrsebhulrylludremlysfynwerrycsugnysnyllyndyndemluxfedsedbecmunlyrtesmudnytbyrsenwegfyrmurtelreptegpecnelnevfes";
/// Groundwire IDs are comet-width. Planet/moon obfuscation is outside this
/// profile; rejecting those names prevents accidental Azimuth-ID support.
pub fn ship(id: u128) -> Result<String, Error> {
    if (65536..=u64::MAX as u128).contains(&id) {
        return Err(Error::Unsupported);
    }
    if id < 256 {
        return Ok(format!(
            "~{}",
            &SUFFIX[id as usize * 3..id as usize * 3 + 3]
        ));
    }
    let count = (128 - id.leading_zeros() as usize).div_ceil(16);
    let mut out = String::from("~");
    for i in (0..count).rev() {
        if i != count - 1 {
            out.push('-');
            if (i + 1) % 4 == 0 {
                out.push('-');
            }
        }
        let word = (id >> (16 * i)) as u16;
        let p = (word >> 8) as usize * 3;
        let s = (word & 255) as usize * 3;
        out.push_str(&PREFIX[p..p + 3]);
        out.push_str(&SUFFIX[s..s + 3]);
    }
    Ok(out)
}
pub fn parse_ship(text: &str) -> Result<u128, Error> {
    if text.len() > 57 || !text.starts_with('~') {
        return Err(Error::Coordinate);
    }
    let compact = text[1..].replace('-', "");
    let mut id = 0u128;
    if compact.len() == 3 {
        id = SUFFIX
            .as_bytes()
            .as_chunks::<3>()
            .0
            .iter()
            .position(|s| s == compact.as_bytes())
            .ok_or(Error::Coordinate)? as u128;
    } else {
        if compact.is_empty() || !compact.len().is_multiple_of(6) || compact.len() > 48 {
            return Err(Error::Coordinate);
        }
        for chunk in compact.as_bytes().as_chunks::<6>().0 {
            let p = PREFIX
                .as_bytes()
                .as_chunks::<3>()
                .0
                .iter()
                .position(|s| s == &chunk[..3])
                .ok_or(Error::Coordinate)?;
            let s = SUFFIX
                .as_bytes()
                .as_chunks::<3>()
                .0
                .iter()
                .position(|s| s == &chunk[3..])
                .ok_or(Error::Coordinate)?;
            id = (id << 16) | ((p as u128) << 8) | s as u128;
        }
    }
    if ship(id)? != text {
        return Err(Error::Coordinate);
    }
    Ok(id)
}
pub fn decimal(n: u64) -> String {
    group(&n.to_string(), 3, '.')
}
fn group(s: &str, width: usize, separator: char) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(width) {
            out.push(separator);
        }
        out.push(c);
    }
    out
}
pub fn parse_decimal(s: &str) -> Result<u64, Error> {
    if s.len() > 26 {
        return Err(Error::Coordinate);
    }
    let n = s.replace('.', "").parse().map_err(|_| Error::Coordinate)?;
    if decimal(n) != s {
        return Err(Error::Coordinate);
    }
    Ok(n)
}
pub fn uv(bytes: &[u8]) -> String {
    let last = bytes.iter().rposition(|b| *b != 0);
    let bits = last.map_or(0, |i| i * 8 + 8 - bytes[i].leading_zeros() as usize);
    let alphabet = b"0123456789abcdefghijklmnopqrstuv";
    let mut digits = String::new();
    for i in (0..bits.div_ceil(5).max(1)).rev() {
        let offset = i * 5;
        let mut d = 0;
        for b in 0..5 {
            if bytes
                .get((offset + b) / 8)
                .is_some_and(|x| x & (1 << ((offset + b) % 8)) != 0)
            {
                d |= 1 << b;
            }
        }
        digits.push(alphabet[d] as char);
    }
    format!("0v{}", group(&digits, 5, '.'))
}
pub fn parse_uv(s: &str, max: usize) -> Result<Vec<u8>, Error> {
    if s.len() > max.saturating_mul(2).saturating_add(8) || !s.starts_with("0v") {
        return Err(Error::Limit);
    }
    let digits = s[2..].replace('.', "");
    let mut out = vec![0; (digits.len() * 5).div_ceil(8)];
    if out.len() > max.saturating_add(1) {
        return Err(Error::Limit);
    }
    for (i, b) in digits.bytes().rev().enumerate() {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'v' => b - b'a' + 10,
            _ => return Err(Error::Encoding),
        };
        for bit in 0..5 {
            if d & (1 << bit) != 0 {
                out[(i * 5 + bit) / 8] |= 1 << ((i * 5 + bit) % 8);
            }
        }
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    if out.len() > max || uv(&out) != s {
        return Err(Error::Encoding);
    }
    Ok(out)
}
/// The binding uses the beam's case `1`; fragment coordinates do not enter it.
pub fn beam_prefix(publisher: u128, _rift: u32) -> Result<Vec<u8>, Error> {
    Ok(format!("/{}//1/", ship(publisher)?).into_bytes())
}
pub fn public(life: u32, inner: &str) -> Result<Vec<u8>, Error> {
    if life == 0 || !inner.starts_with('/') || inner.len() > 1024 {
        return Err(Error::Coordinate);
    }
    Ok(format!("publ/{}{inner}", decimal(life as u64)).into_bytes())
}
pub fn private(
    server_life: u32,
    client: u128,
    client_life: u32,
    sealed: &[u8],
) -> Result<Vec<u8>, Error> {
    if server_life == 0 || client_life == 0 || sealed.len() > 1024 {
        return Err(Error::Coordinate);
    }
    Ok(format!(
        "chum/{}/{}/{}/{}",
        decimal(server_life as u64),
        ship(client)?,
        decimal(client_life as u64),
        uv(sealed)
    )
    .into_bytes())
}
pub fn proof(receiver: u128, receiver_life: u32) -> Result<Vec<u8>, Error> {
    if receiver_life == 0 {
        return Err(Error::Coordinate);
    }
    public(
        1,
        &format!(
            "/a/x/1//pawn/proof/1/{}/{}",
            ship(receiver)?,
            decimal(receiver_life as u64)
        ),
    )
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Load {
    Poke,
    Ack,
    Explanation,
    Cork,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowPath {
    pub bone: u64,
    pub backward: bool,
    pub receiver: u128,
    pub sequence: Option<u64>,
    pub load: Load,
}
impl FlowPath {
    pub fn render(&self) -> Result<String, Error> {
        let load = match self.load {
            Load::Poke => "poke",
            Load::Ack => "ack",
            Load::Explanation => "naxp",
            Load::Cork => "cork",
        };
        if self.bone == 0
            || (self.load == Load::Cork) != self.sequence.is_none()
            || self.sequence == Some(0)
        {
            return Err(Error::Coordinate);
        }
        let mut out = format!(
            "/a/x/1//flow/{}/{}/{}/{}",
            decimal(self.bone),
            load,
            if self.backward { "bak" } else { "for" },
            ship(self.receiver)?
        );
        if let Some(s) = self.sequence {
            out.push('/');
            out.push_str(&decimal(s));
        }
        Ok(out)
    }
    pub fn parse(s: &str) -> Result<Self, Error> {
        if s.len() > 256 {
            return Err(Error::Limit);
        }
        let parts: Vec<_> = s.split('/').collect();
        if !(10..=11).contains(&parts.len()) || parts[..6] != ["", "a", "x", "1", "", "flow"] {
            return Err(Error::Shape);
        }
        let load = match parts[7] {
            "poke" => Load::Poke,
            "ack" => Load::Ack,
            "naxp" => Load::Explanation,
            "cork" => Load::Cork,
            _ => return Err(Error::Unsupported),
        };
        let p = Self {
            bone: parse_decimal(parts[6])?,
            backward: match parts[8] {
                "bak" => true,
                "for" => false,
                _ => return Err(Error::Shape),
            },
            receiver: parse_ship(parts[9])?,
            sequence: if parts.len() == 11 {
                Some(parse_decimal(parts[10])?)
            } else {
                None
            },
            load,
        };
        if p.render()? != s {
            return Err(Error::Shape);
        }
        Ok(p)
    }
}
