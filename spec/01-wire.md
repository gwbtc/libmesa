# libmesa spec — 1: Wire format (pact layer)

> **Skeleton.** Ground truth today: `lull.hoon` `++pact` (`plot` encoders)
> and `vere/pkg/vere/io/mesa/pact.c` (etch/sift). This chapter makes the
> format normative; divergence between those two sources is a finding.

## Outline

1. **Framing.** All integers little-endian; bit-granular packing (LSB-first).
   Datagram N-1s: one pact per datagram. Stream N-1s: length-prefixed pacts
   (policy, ch. 7).
2. **Header (64 bits).** reserved(2) · next(2) · ver(3)=1 · type(2)
   {%page=1 %peek=2 %poke=3} · hop(3, saturating) · mug(20, truncated murmur3
   over body) · cookie(32)=`0x67e0.0200`.
3. **Name.** meta byte {rank(2) · rift-len(2) · nit(1) · tau(1) · frag-len(2)}
   · ship(2/4/8/16 B by rank) · rift · bloq(1 B) · fragment · path-len(2 B) ·
   path bytes. Name↔beam mapping (`/ax/~her//1/mess/<rift>/pact/...`).
4. **Data.** meta byte · total-bytes · auth block {sign=64 B ed25519 ·
   hmac=16 B · pair=2×32 B blake3 · none} · fragment-length · fragment.
5. **Packet bodies.** %peek = name; %poke = ack-name + poke-name + data;
   %page = name + data + next-hop trailer (none / 6-byte v4 lane / reserved).
6. **Fragmentation & LSS.** Leaf size = `2^bloq` bytes (bloq 13 = 1024 MTI
   default over datagrams); fragment 0 carries the proof (%auth) for
   multi-fragment messages; blake3 lockstep-streaming Merkle; root binds
   path + content (what signatures/MACs actually cover).
7. **Malformed-input requirements.** Bounded parsing before any allocation or
   crypto: the `+mat` 20-bit bounded-scan rule; jam-shape validation before
   cue (`+open-jam-shaped`); mug check before body parse. (Kernel commits
   `382243cd7c`, `efe63a546e` are the motivating CVE-class bugs.)
8. **Vectors.** `../vectors/pact/` — roundtrip + adversarial (extract via
   `PACT_TEST` and fakeship dojo).
