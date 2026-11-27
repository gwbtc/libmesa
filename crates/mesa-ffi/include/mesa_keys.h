#ifndef LIBMESA_KEYS_H
#define LIBMESA_KEYS_H
#include "mesa_pki.h"
#include "mesa_transport.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Component ABI 1. One serialized caller per mutable handle, including its
 * selected PKI and engine handles. No I/O or clock reads in key submission.
 * All buffers retain exact width. See spec/17-local-activation.md. */
typedef struct mesa_keys mesa_keys;
typedef struct mesa_packet mesa_packet;
typedef struct mesa_secret mesa_secret;
typedef struct {
  uint32_t version;
  uint8_t peer[16], domain[64], incarnation[16], host_epoch[16];
  size_t history, operations;
  uint64_t timeout;
  size_t checkpoint_bytes, max_keys, max_objects;
} mesa_keys_options;
typedef struct {
  uint8_t backend[16], object[16];
  uint64_t version;
} mesa_key_ref;
enum {
  MESA_KEYS_IMPORT_SEED = 1,
  MESA_KEYS_PREPARE = 2,
  MESA_KEYS_COMMIT = 3,
  MESA_KEYS_CANCEL = 4,
  MESA_KEYS_ADVANCE = 5,
  MESA_KEYS_RECONCILE = 6,
  MESA_KEYS_PIN = 7,
  MESA_KEYS_UNPIN = 8,
  MESA_KEYS_RETIRE = 9,
  MESA_KEYS_DELETE = 10,
  MESA_KEYS_SYNC_CORE = 11,
  MESA_KEYS_PLAN_FLOW = 12,
  MESA_KEYS_SYNC_FLOW = 13,
  MESA_KEYS_ROOT = 14,
  MESA_KEYS_AGREE = 15,
  MESA_KEYS_EXECUTE = 16,
  MESA_KEYS_SIGNATURE = 17,
  MESA_KEYS_CANCEL_OPERATION = 18,
  MESA_KEYS_IMPORT_RING = 19,
  MESA_KEYS_QUIESCE_FLOW = 20,
  MESA_KEYS_MESA_ROOT = 21
};
/* MESA_ROOT: data=path, seed=immutable namespace prefix (public bytes in this
 * event only), root=ROOT hash. Existing ROOT is explicitly libmesa-exp-v2.
 * Both are trusted protocol-module operations, never packet-chosen signing. */
/* Zero initialize. IMPORT_SEED: trusted profile supplies peer/life/rift/key,
 * data=full public pass/evidence, seed=32 exact bytes; grants no authority.
 * IMPORT_RING: data=current-layout suite-C ring, peer/life/rift; available only
 * with cargo feature suite-c. Layout selection requires trusted provenance.
 * PREPARE: reference. Host durably writes key object BEFORE manifest, then
 * confirms token with COMMIT. A proposal closes prior output immediately.
 * CANCEL: token. ADVANCE: value monotonic tick. RECONCILE: after PKI mutations,
 * before engine work. PIN: id/reference, UNPIN: id. RETIRE: historical
 * reference; commit its proposal before DELETE. Backend deletion must be
 * replay-safe. SYNC_CORE: selected engine; returns cancellations and current
 * engine timer. QUIESCE_FLOW emits transient cancellation outcomes. Drain
 * pending FLOW persistence/delivery while closed. PLAN_FLOW takes reference
 * and a quiescent engine. Persist retired message outcomes with its manifest.
 * SYNC_FLOW: fresh incarnation for rebuilt engine; subsequent
 * mesa_engine_submit calls use that incarnation. ROOT:
 * data=path,value=total,root; trusted protocol-module request only. AGREE:
 * peer. EXECUTE/SIGNATURE/CANCEL_OPERATION: exact incarnation/id/generation
 * from REQUEST. EXECUTE uses software custody; SIGNATURE supplies backend
 * reply. Reconcile current authority before dispatch and completion. No packet
 * may choose an arbitrary signing transcript. Old/stale work never authorizes
 * use. */
typedef struct {
  uint32_t tag;
  uint64_t cookie;
  mesa_key_ref reference;
  mesa_commit_token token;
  uint64_t value, id, generation;
  uint8_t incarnation[16], peer[16];
  uint32_t life, rift;
  uint8_t public_key[32];
  const mesa_buffer *data, *seed;
  uint8_t root[32], signature[64];
} mesa_key_event;
enum {
  MESA_KEYS_PERSIST = 301,
  MESA_KEYS_REQUEST = 302,
  MESA_KEYS_COMPLETED = 303,
  MESA_KEYS_TIMER = 304
};
/* Uses mesa_batch/mesa_result. Every consumed input has MESA_EVENT_RESULT
 * (100), including a rejected input; stop on first rejection. Budget pressure
 * leaves a resumable prefix. A batch is NOT an atomic transaction.
 * PERSIST: data=manifest,aux=retired MessageId array JSON,token,value=base
 * revision. REQUEST: id,value=generation,token.incarnation; data=owned scoped
 * transcript, aux=agreement peer key (empty for signing). Retain public active
 * key/ref from the activation snapshot for an external signing backend.
 * COMPLETED: data=64 byte signature or opaque secret accessible with
 * mesa_batch_secret. TIMER: flag=deadline present,value=next tick. Count=0
 * drains timer only. Reserve at least 7 records and checkpoint_bytes+1 MiB per
 * key-only event; with an engine add its step envelope. Too-small first budget
 * mutates nothing. Reopen keys after restore; readiness is always quiescent
 * until fresh authority and a new durable activation. floor/host_epoch come
 * from protected external host state, not from the checkpoint being restored.
 */
int mesa_keys_new(const mesa_keys_options *, const mesa_buffer *checkpoint,
                  uint64_t floor, mesa_keys **);
void mesa_keys_free(mesa_keys *);
int mesa_keys_submit(mesa_keys *, const mesa_pki *, mesa_engine *,
                     const mesa_key_event *, size_t, const mesa_budget *,
                     const mesa_batch **);
int mesa_keys_view(const mesa_keys *, uint32_t view,
                   const mesa_buffer **); /* 0 config; 1 snapshot; owned */
/* Send capabilities retain immutable buffers and stay revoked after rotation or
 * engine destruction. Use this send path in activation-managed compositions.
 * Legacy raw-byte send APIs cannot fence caller-retained bytes. */
int mesa_batch_packet(const mesa_batch *, size_t, const mesa_packet **);
void mesa_packet_retain(const mesa_packet *);
void mesa_packet_release(const mesa_packet *);
int mesa_udp_endpoint_send_packet(mesa_udp_endpoint *, const mesa_packet *);
/* Batched fenced sends: <=64 inputs, one result per consumed packet, at most
 * one syscall per input. IO stops the batch; stale/pressure records continue.
 */
int mesa_udp_endpoint_send_packets(mesa_udp_endpoint *,
                                   const mesa_packet *const *, size_t,
                                   const mesa_budget *, const mesa_batch **);
int mesa_batch_secret(const mesa_batch *, size_t, const mesa_secret **);
void mesa_secret_retain(const mesa_secret *);
void mesa_secret_release(const mesa_secret *);
#ifdef __cplusplus
}
#endif
#endif
