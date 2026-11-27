//! Explicit wire selection. Mesa-v1 domains come from an installed credential;
//! they are never inferred from an unauthenticated publisher or route.
use crate::{mesa_v1 as m, *};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Profile {
    #[default]
    MesaV1,
    LibmesaExpV2,
}
impl Profile {
    pub fn encode(self, packet: &Packet<'_>, limits: Limits) -> Result<Vec<u8>, Error> {
        if self == Self::LibmesaExpV2 {
            return encode(packet, limits);
        }
        fn name(n: Name<'_>) -> m::Name<'_> {
            m::Name {
                ship: n.publisher.0,
                rift: n.rift,
                bloq: n.bloq,
                fragment: match n.fragment {
                    Fragment::Init => m::Fragment::Init,
                    Fragment::Auth(i) => m::Fragment::Auth(i),
                    Fragment::Data(i) => m::Fragment::Data(i),
                },
                path: n.path,
            }
        }
        fn data(d: Data<'_>) -> Result<m::Data<'_>, Error> {
            Ok(m::Data {
                total_bytes: d.total_bytes,
                fragment: d.fragment,
                auth: match d.auth {
                    Auth::Signature(s) => {
                        m::Auth::Signature(s.try_into().map_err(|_| Error::Limit)?)
                    }
                    Auth::None => m::Auth::None,
                    Auth::Mac(s) => m::Auth::Mac(s),
                    Auth::Pair(p) => m::Auth::Pair(p),
                },
            })
        }
        let body = match packet.body {
            Body::Peek(n) => m::Body::Peek(name(n)),
            Body::Page {
                name: n,
                data: d,
                next,
            } => m::Body::Page {
                name: name(n),
                data: data(d)?,
                next,
            },
            Body::Poke {
                ack,
                payload,
                data: d,
            } => m::Body::Poke {
                ack: name(ack),
                payload: name(payload),
                data: data(d)?,
            },
        };
        m::encode(
            &m::Packet {
                hop: packet.hop,
                body,
            },
            m::Checksum::VereBytes,
            native_limits(limits),
        )
        .map_err(|_| Error::Limit)
    }
    pub fn decode<'a>(
        self,
        bytes: &'a [u8],
        limits: Limits,
        domain: DomainTag<'a>,
    ) -> Result<Packet<'a>, Error> {
        if self == Self::LibmesaExpV2 {
            return decode(bytes, limits);
        }
        let p = m::decode(bytes, m::Checksum::VereBytes, native_limits(limits))
            .map_err(|_| Error::Header)?;
        let name = |n: m::Name<'a>| Name {
            publisher: PeerId(n.ship),
            domain,
            rift: n.rift,
            bloq: n.bloq,
            fragment: match n.fragment {
                m::Fragment::Init => Fragment::Init,
                m::Fragment::Auth(i) => Fragment::Auth(i),
                m::Fragment::Data(i) => Fragment::Data(i),
            },
            path: n.path,
        };
        let data = |d: m::Data<'a>| Data {
            total_bytes: d.total_bytes,
            fragment: d.fragment,
            auth: match d.auth {
                m::Auth::Signature(s) => Auth::Signature(s),
                m::Auth::None => Auth::None,
                m::Auth::Mac(s) => Auth::Mac(s),
                m::Auth::Pair(p) => Auth::Pair(p),
            },
        };
        Ok(Packet {
            hop: p.hop,
            body: match p.body {
                m::Body::Peek(n) => Body::Peek(name(n)),
                m::Body::Page {
                    name: n,
                    data: d,
                    next,
                } => Body::Page {
                    name: name(n),
                    data: data(d),
                    next,
                },
                m::Body::Poke {
                    ack,
                    payload,
                    data: d,
                } => Body::Poke {
                    ack: name(ack),
                    payload: name(payload),
                    data: data(d),
                },
            },
        })
    }
}
fn native_limits(l: Limits) -> m::Limits {
    m::Limits {
        max_packet: l.max_packet,
        max_path: l.max_path,
        max_fragment: l.max_fragment,
    }
}
