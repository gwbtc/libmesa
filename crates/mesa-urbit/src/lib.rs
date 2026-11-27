//! Urbit-Mesa conventions at the edge of noun-free Mesa mechanisms.
//! The UDP composition uses the shared transport adapter. Hosts own clocks,
//! storage transactions, and verifier decisions; CORE and FLOW own mechanisms.
pub mod admission;
pub mod contact;
pub mod gage;
pub mod identity_control;
pub mod path;
pub mod session;
pub mod udp;
pub use mesa_bytes::Buffer;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Limit,
    Encoding,
    Shape,
    Coordinate,
    Unsupported,
}
