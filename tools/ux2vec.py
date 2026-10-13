#!/usr/bin/env python3
"""Convert dojo-printed @ux atoms into wire-byte-order vector JSON.

A dojo @ux prints the atom's value big-endian with dot grouping. The wire
is the atom's little-endian bytes, zero-padded to the explicit length that
fax:plot reported. Edit BATCH, run, and the script rewrites OUT.
"""

import json
import pathlib

OUT = pathlib.Path(__file__).resolve().parent.parent / "vectors" / "pact" / "v0-basic.json"


def ux_to_le_hex(ux: str, length: int | None = None) -> str:
    val = ux.replace("0x", "").replace(".", "")
    if len(val) % 2:
        val = "0" + val
    data = bytes.fromhex(val)[::-1]  # value hex is BE; wire is LE bytes
    if length is not None:
        assert len(data) <= length, f"{len(data)} > {length}"
        data = data + b"\x00" * (length - len(data))
    return data.hex()


BATCH = [
    {
        "name": "peek-publ-galaxy",
        "type": "peek",
        "hoon": "[hop=0 %peek [[~zod 1] [13 ~] /publ/1/a/x/1//foo/bar]]",
        "len": 36,
        "wire_ux": "0x7261.622f.6f6f.662f.2f31.2f78.2f61.2f31.2f6c.6275.7000.150d.0100.0010.67e0.0200.212c.8110",
        "jam_ux": "0x5.c985.89e0.3bdb.d99e.0338.d07c.7070.f071.a0ec.6275.70f8.0da4.1725.d6ca.cae1.f019",
    },
    {
        "name": "peek-comet-datafrag",
        "type": "peek",
        "hoon": "[hop=0 %peek [[`@p`(dec (bex 128)) 1] [13 %data 5] /chum/5/~sampel-palnet/3/0va.bcdef]]",
        "len": 63,
        "wire_ux": "0x66.6564.6362.2e61.7630.2f33.2f74.656e.6c61.702d.6c65.706d.6173.7e2f.352f.6d75.6863.0021.050d.01ff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ff03.67e0.0200.4002.5110",
        "jam_ux": "0xb332.b231.b117.30bb.180f.0073.a0f4.656e.6c61.702d.6c65.706d.6173.7ebe.00eb.41da.ead0.c7f0.1b8c.2e8c.2c9f.01d2.0b9f.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffe0.2005.d6ca.cae1.f019",
    },
    {
        "name": "peek-rift-1byte",
        "type": "peek",
        "hoon": "[hop=0 %peek [[~sampel-palnet 255] [0 ~] /a]]",
        "len": 18,
        "wire_ux": "0x6100.0100.ff60.daf1.3f11.67e0.0200.2294.0110",
        "jam_ux": "0x161.e0d2.ff88.306d.789f.fc05.d6ca.cae1.f019",
    },
    {
        "name": "peek-rift-2byte",
        "type": "peek",
        "hoon": "[hop=0 %peek [[~sampel-palnet 256] [0 ~] /a]]",
        "len": 19,
        "wire_ux": "0x61.0001.0001.0060.daf1.3f15.67e0.0200.699a.d110",
        "jam_ux": "0x2c3.c1a5.8018.306d.789f.fc05.d6ca.cae1.f019",
    },
    {
        "name": "page-sig-single",
        "type": "page",
        "hoon": "[hop=0 %page [[~zod 1] [13 ~] /publ/1/m] [tob=5 [%& %& `@uxJ`(fil 3 64 0xab)] dat=0xde.adbe.ef01] ~]",
        "len": 95,
        "wire_ux": "0xde.adbe.ef01.05ab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.ab05.406d.2f31.2f6c.6275.7000.080d.0100.0010.67e0.0200.e840.7090",
        "jam_ux": "0xb7a.b6fb.bc05.1015.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7560.0800.996e.16db.c1c6.83b1.89d5.c3e0.3690.5c95.cace.c2e1.f019",
    },
    {
        "name": "page-next-if-hop3",
        "type": "page",
        "hoon": "[hop=3 %page [[~zod 1] [13 ~] /publ/1/m] [tob=5 [%& %& `@uxJ`(fil 3 64 0xab)] dat=0xde.adbe.ef01] ~[[%if .192.168.1.10 1.337]]]",
        "len": 101,
        "wire_ux": "0x5.39c0.a801.0ade.adbe.ef01.05ab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.ab05.406d.2f31.2f6c.6275.7000.080d.0100.0010.67e0.0200.cb79.c694",
        "jam_ux": "0xa9cb.8302.a004.2810.0e66.9f02.ef56.df77.80a2.02ae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.aeae.ac01.0013.2dc2.db78.38d0.7631.3ab8.7c06.d20b.92b9.59d8.5c3e.03a1",
    },
    {
        "name": "page-lss-pair-frag",
        "type": "page",
        "hoon": "[hop=0 %page [[~zod 1] [13 %data 1] /publ/1/m] [tob=1.040 [%| ~ (fil 3 32 0x11) (fil 3 32 0x22)] dat=(fil 3 16 0x33)] ~]",
        "len": 108,
        "wire_ux": "0x3333.3333.3333.3333.3333.3333.3333.3333.1022.2222.2222.2222.2222.2222.2222.2222.2222.2222.2222.2222.2222.2222.2222.2222.2211.1111.1111.1111.1111.1111.1111.1111.1111.1111.1111.1111.1111.1111.1111.1111.1104.104d.6d2f.312f.6c62.7570.0008.010d.0100.0000.67e0.0200.b32b.8090",
        "jam_ux": "0x2cc.cccc.cccc.cccc.cccc.cccc.cccc.cccc.cfe8.0444.4444.4444.4444.4444.4444.4444.4444.4444.4444.4444.4444.4444.4444.4444.4444.5fa0.0888.8888.8888.8888.8888.8888.8888.8888.8888.8888.8888.8888.8888.8888.8888.8888.fd80.19c5.820e.05b6.f071.a0ec.6275.70f8.0e61.7461.64f8.0e90.5c95.cace.c2e1.f019",
    },
    {
        "name": "poke-hmac",
        "type": "poke",
        "hoon": "[hop=0 %poke [[~zod 1] [13 ~] /flow/ack] [[`@p`(dec (bex 128)) 1] [13 ~] /flow/poke] [tob=4 [%& %| `@uxH`(fil 3 16 0x77)] dat=0xcafe.0042]]",
        "len": 76,
        "wire_ux": "0xcafe.0042.0477.7777.7777.7777.7777.7777.7777.7777.7704.4865.6b6f.702f.776f.6c66.0009.0d01.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.136b.6361.2f77.6f6c.6600.080d.0100.0010.67e0.0200.dd83.4190",
        "jam_ux": "0x195.fc00.8408.0eee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.ffc0.3196.61b6.6cfe.37ea.373f.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffc0.400a.dad8.d85e.03dd.bdb1.9be0.3690.5c95.cad6.dee1.f019",
    },
    {
        "name": "peek-hop-saturate",
        "type": "peek",
        "hoon": "[hop=9 %peek [[~zod 1] [13 ~] /a]]  :: encode-only: en clamps hop to 7",
        "len": 16,
        "wire_ux": "0x6100.010d.0100.0010.67e0.0200.438a.1f10",
        "jam_ux": "0x2c.3c1b.482e.4bad.9595.c3e0.3241",
        "hop_on_wire": 7,
        "roundtrip": False,
    },
    {
        "name": "page-short-final-frag",
        "type": "page",
        "hoon": "[hop=0 %page [[~zod 1] [13 ~] /publ/1/z] [tob=4 [%& %& `@uxJ`(fil 3 64 0xab)] dat=0xde] ~]",
        "len": 91,
        "wire_ux": "0xde.01ab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.abab.ab04.407a.2f31.2f6c.6275.7000.080d.0100.0010.67e0.0200.7e8b.e090",
        "jam_ux": "0xb7.8415.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7575.7560.0800.9966.16f5.c1c6.83b1.89d5.c3e0.3690.5c95.cace.c2e1.f019",
    },
]


def main() -> None:
    out = []
    for v in BATCH:
        out.append(
            {
                "name": v["name"],
                "type": v["type"],
                "hoon": v["hoon"],
                "len": v["len"],
                "wire": ux_to_le_hex(v["wire_ux"], v["len"]),
                "jam": ux_to_le_hex(v["jam_ux"]),
                "roundtrip": v.get("roundtrip", True),
                **({"hop_on_wire": v["hop_on_wire"]} if "hop_on_wire" in v else {}),
            }
        )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {len(out)} vectors to {OUT}")


if __name__ == "__main__":
    main()
