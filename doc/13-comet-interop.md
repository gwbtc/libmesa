# Urbit interoperability status

The earlier deadline and v1 adapter proposal are superseded. The implemented
[experimental v2 prototype](../interop/README.md) runs a Hoon Gall endpoint
inside a fake Urbit and exchanges authenticated named reads with Rust over a
UDP/Lick byte bridge. It preserves the native Ames v1 stack.

The prototype uses preconfigured public test keys and a pinned boot pill. It
requires no comet, generalized PKI, Jael changes, verifier runtime, or enrollment.
The replay instructions, exact bounds, acceptance matrix, and evidence receipts
are in the prototype README. Native Ames integration and Urbit application
messaging remain later phases.
