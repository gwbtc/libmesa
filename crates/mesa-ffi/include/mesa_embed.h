#ifndef LIBMESA_EMBED_H
#define LIBMESA_EMBED_H
#include "mesa.h"
#ifdef __cplusplus
extern "C" {
#endif

/* ABI 2 selects Mesa-v1; ABI 1 selects explicit experimental compatibility.
 * All integer fields are native C values except 16-byte identities and
 * incarnations, which are little-endian. Zero-initialize events/results.
 * See spec/14-c-embedding.md and spec/18-mesa-profile.md for contracts. */
typedef struct mesa_buffer mesa_buffer;
typedef struct mesa_engine mesa_engine;
typedef struct mesa_batch mesa_batch;
typedef struct {
  size_t max_results, max_result_bytes, max_steps;
} mesa_budget;
/* Conservative allowance before every engine/internal service step. */
enum { MESA_STEP_RECORDS = 1024, MESA_STEP_BYTES = 4194304 };
enum {
  MESA_LIMIT = 5,
  MESA_CLOSED = 6,
  MESA_STALE = 7,
  MESA_EVENT_ERROR = 8,
  MESA_IO = 9
};
enum { MESA_CORE = 1, MESA_FLOW = 2 };
enum { MESA_FIXED = 0, MESA_EXPONENTIAL = 1, MESA_AIMD = 1 };
enum { MESA_MAX_BUFFER = 8388608, MESA_MAX_BATCH_EVENTS = 16 };
typedef struct {
  uint8_t id[16];
  uint8_t domain[64]; /* NUL-terminated canonical domain, zero padded. */
  uint32_t life, rift;
  uint64_t key;
  uint32_t allowed; /* 0 or 1 */
} mesa_peer;
typedef struct {
  uint64_t handle;
  uint8_t public_key[32];
} mesa_key;
typedef struct {
  uint64_t flow;
  mesa_peer peer;
  uint64_t attachment;
  uint32_t attached;
} mesa_flow_config;
typedef struct {
  uint32_t abi_version, kind;
  mesa_peer local;
  uint8_t seed[32]; /* copied into protected key storage; never in descriptor */
  uint8_t incarnation[16]; /* nonzero; host MUST never reuse across lifetimes */
  uint64_t retry_initial, retry_maximum, read_timeout;
  uint32_t max_attempts, retry_mode, congestion_mode;
  uint32_t peer_window_initial, peer_window_maximum, max_batch_events;
} mesa_options;
typedef struct {
  uint8_t sender[16], receiver[16];
  uint32_t sender_rift, receiver_rift;
  uint64_t flow, sequence;
} mesa_message_id;
typedef struct {
  uint8_t incarnation[16];
  uint64_t revision;
} mesa_commit_token;

enum {
  MESA_INSTALL_PEER = 1,
  MESA_REMOTE_BREACH = 2,
  MESA_SET_SERVICE = 3,
  MESA_SET_ATTACHMENT = 4,
  MESA_BIND = 5,
  MESA_UNBIND = 6,
  MESA_RETIRE_BEFORE = 7,
  MESA_READ = 8,
  MESA_CANCEL = 9,
  MESA_ADVANCE_TO = 10,
  MESA_RECEIVE = 11,
  MESA_ENQUEUE = 12,
  MESA_DECIDE = 13,
  MESA_COMMITTED = 14,
  MESA_RESUME = 15,
  MESA_INVALIDATE_EPOCH = 16,
  MESA_CLOSE = 17,
  MESA_INSTALL_CREDENTIAL = 18,
  MESA_REPLACE_ATTACHMENT = 19,
  MESA_BIND_PRIVATE = 20, MESA_READ_PRIVATE = 21, MESA_READ_POKE = 22,
  MESA_POKE = 23, MESA_SEND_PAGE = 24,
  MESA_SEAL_PATH = 25, MESA_OPEN_PATH = 26,
  MESA_ENCRYPT_OBJECT = 27, MESA_DECRYPT_OBJECT = 28,
  MESA_RELEASE_PROTOCOL_OBJECT = 29
};
/* Mesa-v1 events: BIND_PRIVATE data=path,aux=payload,peer.id=reader.
 * READ_PRIVATE uses READ fields. READ_POKE data=remote ACK path,aux=local
 * payload path,id=read ID,peer.id. POKE data=local payload path,aux=ACK path,
 * peer.id. SEND_PAGE data=local path,peer.id. All paths <=320 bytes.
 * Mutation, cancellation, batch and buffer contracts match existing events. */
/* Native byte protection (CORE only, current installed peer.id): SEAL_PATH
 * data=plaintext path; OPEN_PATH data=sealed path (each <=256 bytes).
 * ENCRYPT_OBJECT/DECRYPT_OBJECT data=sealed path IV,aux=object bytes.
 * DECRYPT_OBJECT requires a completed authenticated READ_PRIVATE result.
 * These operations return MESA_PROTECTED_BUFFER in data, change no engine state,
 * and perform no I/O. They are fenced while credentials are quiescent. */
/* RELEASE_PROTOCOL_OBJECT: data=path. Trusted service-module operation only:
 * the caller MUST already own a durable sequence/closure fence forbidding reuse
 * of this logical object. Fails while a READ_POKE references it. Unlike UNBIND,
 * releases the transient binding slot; it does not create a raw name tombstone. */
/* Field usage:
 * INSTALL_CREDENTIAL (CORE): peer,sequence=expected generation,id=new generation,
 * flag=breach (0/1). Invalidates old reads; does not verify authority. Keys must
 * already exist. Once used, legacy INSTALL/REMOTE_BREACH are rejected for peer.
 * REPLACE_ATTACHMENT (CORE): peer.id,sequence=expected generation,id=new
 * generation,flag=attached (0/1). New generation is also attachment ID. Once
 * used, legacy SET_ATTACHMENT is rejected. Generations strictly increase.
 * INSTALL/REMOTE_BREACH: peer. SERVICE: peer.id,value=0/1.
 * ATTACHMENT: peer.id,value=attachment,flag=present (0/1).
 * BIND: data=path,aux=payload (public only). UNBIND: data=path.
 * RETIRE: data=prefix,aux=suffix. READ: id=read ID,peer.id,data=path.
 * CANCEL: id. ADVANCE: value=tick. RECEIVE:
 * peer.id,value=attachment,data=packet. ENQUEUE: id=flow,sequence,data=payload.
 * DECIDE: message,outcome (-1=accept, 0..65535=reject code). COMMITTED: token.
 * RESUME: id=flow. INVALIDATE: peer.id,value=new rift. CLOSE: no fields. cookie
 * is echoed in every result caused by the event (except final TIMER).
 * Zero-initialize events; only the fields listed above are inspected. Inputs
 * remain caller-owned; calls never consume references. */
typedef struct {
  uint32_t tag, flag;
  uint64_t cookie, id, sequence, value;
  mesa_peer peer;
  const mesa_buffer *data, *aux;
  mesa_message_id message;
  mesa_commit_token token;
  int32_t outcome;
} mesa_event;
enum {
  MESA_EVENT_RESULT = 100,
  MESA_SEND = 101,
  MESA_READ_FINISHED = 102,
  MESA_DROPPED = 103,
  MESA_TIMER = 104,
  MESA_PROTECTED_BUFFER = 114,
  MESA_COMMIT = 105,
  MESA_DELIVER = 106,
  MESA_ENQUEUED = 107,
  MESA_DELIVERY_COMMITTED = 108,
  MESA_SETTLED = 109,
  MESA_STALLED = 110,
  MESA_ANNOUNCEMENT_STALLED = 111,
  MESA_EPOCH_INVALIDATED = 112,
  MESA_HANDLE_CLOSED = 113
};
enum {
  MESA_READ_CANCELLED = 201,
  MESA_READ_TIMEOUT = 202,
  MESA_READ_RETRIES = 203,
  MESA_READ_BLOCKED = 204,
  MESA_READ_RESET = 205,
  MESA_READ_RESOURCE = 206
};
enum {
  MESA_CHANGE_ENQUEUE = 1,
  MESA_CHANGE_DELIVER = 2,
  MESA_CHANGE_SETTLE = 3,
  MESA_CHANGE_RETIRE_RECEIVED = 4,
  MESA_CHANGE_RETIRE_SENT = 5
};
/* EVENT_RESULT.status: 0 or error; data is diagnostic UTF-8 on error.
 * SEND: peer,attachment,data. READ_FINISHED: id,status,data (NULL on failure).
 * TIMER: flag=armed,value=absolute tick; one final replacement per batch.
 * COMMIT: commit holds a named proposal and owned checkpoint/payload buffers.
 * Commit checkpoint and application effect atomically with base_revision CAS
 * and incarnation fencing BEFORE ack. DELIVER: proposal, message,data; decide
 * before committing its application effect. STALLED:
 * id=flow,sequence,detail=read kind (0..3),data=diagnostic UTF-8. DROPPED:
 * data=diagnostic. ANNOUNCEMENT_STALLED: message,detail=read kind.
 * EPOCH_INVALIDATED: peer,value=new rift. Other completion records:
 * message,outcome. All returned buffers own references, even after batch/handle
 * release. */
typedef struct {
  mesa_commit_token token;
  uint64_t base_revision, revision;
  uint32_t change;
  mesa_message_id message;
  int32_t outcome;
  const mesa_buffer *checkpoint, *payload;
} mesa_commit_proposal;
typedef struct {
  uint32_t tag, flag;
  int32_t status;
  uint32_t detail;
  size_t event_index;
  uint64_t cookie, id, sequence, attachment, value;
  uint8_t peer[16];
  const mesa_buffer *data, *aux;
  mesa_message_id message;
  mesa_commit_token token;
  int32_t outcome;
  mesa_commit_proposal commit;
} mesa_result;

/* Buffer constructor copies and normalizes dat; dat_len <= wid <= 8 MiB.
 * NULL dat is permitted only for dat_len=0. Width never causes allocation here.
 * All public buffer handles are immutable and atomically reference-counted.
 * dat() exposes canonical storage ONLY, not wid readable bytes. Its pointer is
 * valid while the caller retains the buffer. copy() zero-extends a bounded
 * range. Neither accessor allocates. Release(NULL) and retain(NULL) are no-ops.
 */
int32_t mesa_buffer_new(const uint8_t *dat, size_t dat_len, size_t wid,
                        const mesa_buffer **out);
const mesa_buffer *mesa_buffer_retain(const mesa_buffer *buffer);
void mesa_buffer_release(const mesa_buffer *buffer);
int32_t mesa_buffer_dat(const mesa_buffer *buffer, const uint8_t **dat,
                        size_t *dat_len, size_t *wid);
int32_t mesa_buffer_copy(const mesa_buffer *buffer, size_t offset, uint8_t *out,
                         size_t len);

/* Additive CORE configuration, version 1. No change to mesa_options layout.
 * Bounds: peers 1..256, reads 1..1024, bindings 1..65536, window 1..16,
 * reads*window <=4096; object 1..1MiB, binding/reassembly object..64MiB,
 * unverified 1KiB..8MiB. Wire remains v2 public, 1472-byte packets, bloq 13.
 * describe reports the per-event reservation; do not assume MESA_STEP_* for
 * configured engines. These capacities bound work as well as memory. */
typedef struct {
  uint32_t version, max_peers, max_reads, max_bindings, window;
  size_t max_object_bytes, max_binding_bytes, max_reassembly_bytes,
      max_unverified_bytes;
} mesa_resources;
int32_t mesa_resources_default(mesa_resources *out);
/* CORE only, <=256 fixed public keys. No checkpoint or flow parameters. */
int32_t mesa_engine_create_configured(const mesa_options *, const mesa_resources *,
    const mesa_key *, size_t key_count, mesa_engine **out);
/* Owned immutable version-1 JSON view of mutable CORE state. Contains revision,
 * timer, resource use, counters and peer/credential/attachment generations.
 * Does not mutate the engine or configuration descriptor; no seeds. */
int32_t mesa_engine_snapshot(const mesa_engine *, const mesa_buffer **out);

/* Default creation is Mesa-v1, ABI 2. Experimental restore selects ABI 1. */
int32_t mesa_options_default(mesa_options *out);
int32_t mesa_options_exp_v2(mesa_options *out);
int32_t mesa_key_from_seed(const uint8_t seed[32], uint8_t public_key[32]);
/* At most 16 key entries and 4 flow entries. Core mode requires no flows or
 * checkpoint. Flow mode requires flows; NULL checkpoint creates revision zero.
 * Checkpoints are opaque versioned bytes (currently flow format 2 JSON).
 * Keys are fixed at construction; peer updates select already installed
 * handles. No clocks, sockets, storage calls, worker threads, or host
 * callbacks. */
/* ABI 2 raw Mesa-v1 engine. Set options.abi_version=2, kind=MESA_CORE.
 * Namespace prefixes are immutable profile bytes, copied during creation.
 * They grant no peer authority. No checkpoint or noun conversion is implicit.
 * ABI 1 constructors remain explicitly libmesa-exp-v2. */
typedef struct { uint8_t peer[16]; const mesa_buffer *prefix; } mesa_namespace;
int32_t mesa_engine_create_mesa(const mesa_options *, const mesa_resources *, const mesa_key *, size_t,
                              const mesa_namespace *, size_t, mesa_engine **);
int32_t mesa_engine_create(const mesa_options *options, const mesa_key *keys,
                           size_t key_count, const mesa_flow_config *flows,
                           size_t flow_count, const mesa_buffer *checkpoint,
                           mesa_engine **out);
/* Immutable public configuration JSON; never contains the seed. Owned output.
 */
int32_t mesa_engine_describe(const mesa_engine *handle,
                             const mesa_buffer **out);
/* Last acknowledged committed checkpoint, NOT a pending proposal. Recovery must
 * load the newest checkpoint from the host's store, including commits whose ack
 * was lost. Live export is not a substitute for that recovery read. */
int32_t mesa_engine_checkpoint(const mesa_engine *handle,
                               const mesa_buffer **out);
/* Only one caller may access a handle at a time; no reentry. Batches/buffers
 * may be retained and read on other threads. Event time is the last ADVANCE_TO.
 * Advance time before packets at a deadline. Incarnation must match the handle.
 * max_steps bounds processed events (1..64); count <= 16. Before each event
 * reserve the descriptor's step_records/step_bytes plus one final TIMER slot.
 * If budgets cannot fit the first event, return CAPACITY, out=NULL, no
 * mutation. Otherwise return an owned batch for the processed prefix. A
 * rejected event has EVENT_RESULT(error), counts as processed, and stops the
 * batch. Earlier successful events remain applied. A capacity stop does not
 * process the next event. No hidden output queue or silent action loss.
 * Budgets <= 16385 records/64 MiB; input count <= configured max_batch_events.
 * PANIC poisons the handle: only describe/release remain valid. OOM may abort.
 */
int32_t mesa_engine_submit(mesa_engine *handle, const uint8_t incarnation[16],
                           const mesa_event *events, size_t count,
                           const mesa_budget *budget, const mesa_batch **out);
const mesa_batch *mesa_batch_retain(const mesa_batch *batch);
void mesa_batch_release(const mesa_batch *batch);
int32_t mesa_batch_info(const mesa_batch *batch, size_t *processed,
                        size_t *results, size_t *bytes);
/* get() copies a result and retains all its buffers. Release those owned
 * references with result_release(); overwriting a live result without release
 * leaks it. */
int32_t mesa_batch_get(const mesa_batch *batch, size_t index, mesa_result *out);
void mesa_result_release(mesa_result *result);
/* Release has no callbacks/results. Submit CLOSE first for explicit
 * cancellation results. A pending flow commit remains the host's responsibility
 * after close. */
void mesa_engine_release(mesa_engine *handle);
#ifdef __cplusplus
}
#endif
#endif
