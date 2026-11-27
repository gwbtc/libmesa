//! Bounded marked gages. Every exported payload is an owned immutable buffer.
use crate::{Buffer, Error};
use mesa_noun::{
    bits::Bits,
    serial::{self, Limits, Node, Noun},
};

enum Build {
    Atom(Vec<u8>),
    Cell(usize, usize),
}
pub(crate) struct Builder(Vec<Build>);
impl Builder {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }
    pub(crate) fn atom(&mut self, mut bytes: Vec<u8>) -> usize {
        while bytes.last() == Some(&0) {
            bytes.pop();
        }
        let i = self.0.len();
        self.0.push(Build::Atom(bytes));
        i
    }
    pub(crate) fn text(&mut self, s: &str) -> usize {
        self.atom(s.as_bytes().to_vec())
    }
    pub(crate) fn uint(&mut self, n: u64) -> usize {
        self.atom(n.to_le_bytes().to_vec())
    }
    pub(crate) fn cell(&mut self, a: usize, b: usize) -> usize {
        let i = self.0.len();
        self.0.push(Build::Cell(a, b));
        i
    }
    pub(crate) fn tuple(&mut self, xs: &[usize]) -> usize {
        let mut tail = *xs.last().unwrap();
        for x in xs[..xs.len() - 1].iter().rev() {
            tail = self.cell(*x, tail);
        }
        tail
    }
    pub(crate) fn finish(&self, root: usize, max: usize) -> Result<Buffer, Error> {
        let limits = limits(max)?;
        let nodes = self
            .0
            .iter()
            .map(|n| match n {
                Build::Atom(a) => Bits::from_atom_bytes(a)
                    .map(Node::Atom)
                    .map_err(|_| Error::Encoding),
                Build::Cell(h, t) => Ok(Node::Cell { head: *h, tail: *t }),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let noun = Noun::from_nodes(nodes, root, limits).map_err(|_| Error::Limit)?;
        let jam = serial::jam(&noun, limits).map_err(|_| Error::Limit)?;
        Ok(jam.bytes.into())
    }
}
pub(crate) fn limits(max: usize) -> Result<Limits, Error> {
    if max == 0 || max > 1024 * 1024 {
        return Err(Error::Limit);
    }
    Ok(Limits {
        max_input_bits: max * 8,
        max_output_bits: max * 8,
        max_atom_bits: max * 8,
        ..Default::default()
    })
}
pub(crate) fn cell(n: &Noun<'_>, id: usize) -> Result<(usize, usize), Error> {
    match n.node(id) {
        Some(Node::Cell { head, tail }) => Ok((head, tail)),
        _ => Err(Error::Shape),
    }
}
pub(crate) fn atom(n: &Noun<'_>, id: usize, max: usize) -> Result<Vec<u8>, Error> {
    match n.node(id) {
        Some(Node::Atom(b)) => Ok(b
            .to_atom(max)
            .map_err(|_| Error::Limit)?
            .as_le_bytes()
            .to_vec()),
        _ => Err(Error::Shape),
    }
}
pub(crate) fn uint(n: &Noun<'_>, id: usize) -> Result<u64, Error> {
    let a = atom(n, id, 8)?;
    let mut bytes = [0; 8];
    bytes[..a.len()].copy_from_slice(&a);
    Ok(u64::from_le_bytes(bytes))
}
pub(crate) fn is(n: &Noun<'_>, id: usize, s: &[u8]) -> bool {
    atom(n, id, s.len()).is_ok_and(|v| v == s)
}
/// `[noun octs width atom]`; width preserves high zero bytes across jam/cue.
pub fn encode_bytes(bytes: &Buffer, max: usize) -> Result<Buffer, Error> {
    if bytes.len() > max {
        return Err(Error::Limit);
    }
    let mut b = Builder(Vec::new());
    let noun = b.text("noun");
    let octs = b.text("octs");
    let width = b.uint(bytes.len() as u64);
    let dat = bytes.with_bytes(|x| b.atom(x.to_vec()));
    let root = b.tuple(&[noun, octs, width, dat]);
    b.finish(root, max)
}
pub fn decode_bytes(bytes: &Buffer, max: usize) -> Result<Buffer, Error> {
    if bytes.len() > max {
        return Err(Error::Limit);
    }
    bytes.with_bytes(|bytes| {
        let n = serial::cue(
            Bits::from_atom_bytes(bytes).map_err(|_| Error::Encoding)?,
            limits(max)?,
        )
        .map_err(|_| Error::Encoding)?;
        let (mark, rest) = cell(&n, n.root())?;
        let (octs, rest) = cell(&n, rest)?;
        let (width, dat) = cell(&n, rest)?;
        if !is(&n, mark, b"noun") || !is(&n, octs, b"octs") {
            return Err(Error::Shape);
        }
        let width = usize::try_from(uint(&n, width)?).map_err(|_| Error::Limit)?;
        if width > max {
            return Err(Error::Limit);
        }
        let data = atom(&n, dat, width)?;
        Buffer::new(data, width).map_err(|_| Error::Shape)
    })
}
/// Urbit boolean %.y is zero. `[message ack nack]` uses true for rejection.
pub fn encode_ack(rejected: bool, max: usize) -> Result<Buffer, Error> {
    let mut b = Builder(Vec::new());
    let m = b.text("message");
    let a = b.text("ack");
    let n = b.uint(u64::from(!rejected));
    let root = b.tuple(&[m, a, n]);
    b.finish(root, max)
}
pub fn decode_ack(bytes: &Buffer, max: usize) -> Result<bool, Error> {
    if bytes.len() > max {
        return Err(Error::Limit);
    }
    bytes.with_bytes(|bytes| {
        let n = serial::cue(
            Bits::from_atom_bytes(bytes).map_err(|_| Error::Encoding)?,
            limits(max)?,
        )
        .map_err(|_| Error::Encoding)?;
        let (m, rest) = cell(&n, n.root())?;
        let (a, nack) = cell(&n, rest)?;
        if !is(&n, m, b"message") || !is(&n, a, b"ack") {
            return Err(Error::Shape);
        }
        match uint(&n, nack)? {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(Error::Shape),
        }
    })
}
/// Ordinary Gall byte-service plea: `[message plea g /ge/agent 0 m noun octs wid dat]`.
pub fn encode_plea(agent: &str, bytes: &Buffer, max: usize) -> Result<Buffer, Error> {
    if agent.is_empty()
        || agent.len() > 64
        || !agent
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'-' || b.is_ascii_digit())
        || bytes.len() > max
    {
        return Err(Error::Limit);
    }
    let mut b = Builder::new();
    let message = b.text("message");
    let plea = b.text("plea");
    let g = b.text("g");
    let ge = b.text("ge");
    let agent = b.text(agent);
    let nil = b.uint(0);
    let path = b.tuple(&[ge, agent, nil]);
    let version = b.uint(0);
    let m = b.text("m");
    let noun = b.text("noun");
    let octs = b.text("octs");
    let width = b.uint(bytes.len() as u64);
    let dat = b.atom(bytes.dat().to_vec());
    let root = b.tuple(&[message, plea, g, path, version, m, noun, octs, width, dat]);
    b.finish(root, max)
}
pub fn decode_plea(bytes: &Buffer, max: usize) -> Result<(String, Buffer), Error> {
    if bytes.len() > max {
        return Err(Error::Limit);
    }
    bytes.with_bytes(|bytes| {
        let n = serial::cue(
            Bits::from_atom_bytes(bytes).map_err(|_| Error::Encoding)?,
            limits(max)?,
        )
        .map_err(|_| Error::Encoding)?;
        let mut rest = n.root();
        for tag in [b"message".as_slice(), b"plea", b"g"] {
            let (head, tail) = cell(&n, rest)?;
            if !is(&n, head, tag) {
                return Err(Error::Shape);
            }
            rest = tail;
        }
        let (path, tail) = cell(&n, rest)?;
        rest = tail;
        let (ge, tail) = cell(&n, path)?;
        let (agent, nil) = cell(&n, tail)?;
        if !is(&n, ge, b"ge") || uint(&n, nil)? != 0 {
            return Err(Error::Shape);
        }
        let agent = String::from_utf8(atom(&n, agent, 64)?).map_err(|_| Error::Shape)?;
        let (version, tail) = cell(&n, rest)?;
        if uint(&n, version)? != 0 {
            return Err(Error::Shape);
        }
        rest = tail;
        for tag in [b"m".as_slice(), b"noun", b"octs"] {
            let (head, tail) = cell(&n, rest)?;
            if !is(&n, head, tag) {
                return Err(Error::Shape);
            }
            rest = tail;
        }
        let (wid, dat) = cell(&n, rest)?;
        let wid = usize::try_from(uint(&n, wid)?).map_err(|_| Error::Limit)?;
        if wid > max {
            return Err(Error::Limit);
        }
        let data = Buffer::new(atom(&n, dat, wid)?, wid).map_err(|_| Error::Shape)?;
        Ok((agent, data))
    })
}
pub fn encode_cork(max: usize) -> Result<Buffer, Error> {
    let mut b = Builder::new();
    let m = b.text("message");
    let p = b.text("plea");
    let nil = b.uint(0);
    let f = b.text("flow");
    let path = b.cell(f, nil);
    let c = b.text("cork");
    let root = b.tuple(&[m, p, nil, path, c, nil]);
    b.finish(root, max)
}
pub fn encode_gone(max: usize) -> Result<Buffer, Error> {
    let mut b = Builder::new();
    let m = b.text("message");
    let g = b.text("gone");
    let nil = b.uint(0);
    let root = b.tuple(&[m, g, nil]);
    b.finish(root, max)
}
pub fn encode_boon(bytes: &Buffer, max: usize) -> Result<Buffer, Error> {
    if bytes.len() > max {
        return Err(Error::Limit);
    }
    let mut b = Builder::new();
    let m = b.text("message");
    let boon = b.text("boon");
    let d = b.text("d");
    let n = b.text("noun");
    let o = b.text("octs");
    let w = b.uint(bytes.len() as u64);
    let a = b.atom(bytes.dat().to_vec());
    let root = b.tuple(&[m, boon, d, n, o, w, a]);
    b.finish(root, max)
}
pub fn decode_boon(bytes: &Buffer, max: usize) -> Result<Buffer, Error> {
    if bytes.len() > max {
        return Err(Error::Limit);
    }
    bytes.with_bytes(|bytes| {
        let n = serial::cue(
            Bits::from_atom_bytes(bytes).map_err(|_| Error::Encoding)?,
            limits(max)?,
        )
        .map_err(|_| Error::Encoding)?;
        let mut rest = n.root();
        for tag in [b"message".as_slice(), b"boon", b"d", b"noun", b"octs"] {
            let (head, tail) = cell(&n, rest)?;
            if !is(&n, head, tag) {
                return Err(Error::Shape);
            }
            rest = tail;
        }
        let (wid, dat) = cell(&n, rest)?;
        let wid = usize::try_from(uint(&n, wid)?).map_err(|_| Error::Limit)?;
        if wid > max {
            return Err(Error::Limit);
        }
        Buffer::new(atom(&n, dat, wid)?, wid).map_err(|_| Error::Shape)
    })
}
/// Minimal explicit rejection. Hosts may retain another validated, bounded
/// Urbit-Mesa `%nax` gage verbatim; the core never interprets its noun shape.
pub fn rejection(max: usize) -> Result<Buffer, Error> {
    let mut b = Builder::new();
    let m = b.text("message");
    let n = b.text("nax");
    let e = b.text("exit");
    let nil = b.uint(0);
    let root = b.tuple(&[m, n, e, nil]);
    b.finish(root, max)
}
pub fn validate_rejection(bytes: &Buffer, max: usize) -> Result<(), Error> {
    if bytes.len() > max {
        return Err(Error::Limit);
    }
    bytes.with_bytes(|bytes| {
        let n = serial::cue(
            Bits::from_atom_bytes(bytes).map_err(|_| Error::Encoding)?,
            limits(max)?,
        )
        .map_err(|_| Error::Encoding)?;
        let (m, rest) = cell(&n, n.root())?;
        let (nax, error) = cell(&n, rest)?;
        let (mote, _tang) = cell(&n, error)?;
        atom(&n, mote, 64)?;
        if !is(&n, m, b"message") || !is(&n, nax, b"nax") {
            return Err(Error::Shape);
        }
        Ok(())
    })
}
