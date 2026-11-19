#ifndef LIBMESA_PKI_H
#define LIBMESA_PKI_H
#include "mesa_embed.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Phase-4 component ABI 1. See spec/16-authority-admission.md.
 * One serialized caller per mutable handle. No I/O, callbacks or hidden loop.
 * Buffers are immutable, refcounted, exact-width mesa_buffer handles.
 * This is an authority/component boundary, NOT a native packet API. Shrine's
 * network ingress will enter Mesa's transport/profile composition in phase 6.
 * Native decoding and Shrine integration are not implemented by this API. */
typedef struct mesa_pki mesa_pki;
typedef struct mesa_pki_batch mesa_pki_batch;
enum { MESA_PKI_RAW=1, MESA_PKI_JAEL=2 };
typedef struct {
  uint32_t version;
  uint8_t incarnation[16]; /* fresh nonzero value for every handle/restart */
  size_t max_domains, max_peers, max_history;
  size_t max_evidence_bytes, max_checkpoint_bytes, max_pending, max_pending_bytes; /* checkpoint <=8 MiB in C */
  size_t max_packet;
  uint64_t request_timeout, retry_after;
  uint32_t attempts;
  size_t work_per_tick, max_subscriptions, dispatches;
  uint64_t dispatch_interval;
} mesa_pki_options;
typedef struct {
  uint8_t domain_hash[32]; /* obtained from mesa_pki_provider; preserve exactly */
  uint8_t incarnation[16];
  uint64_t generation, request;
  uint8_t peer[16];
  uint64_t base_revision;
  uint8_t digest[32];
} mesa_pki_ticket;
enum {
  MESA_PKI_REGISTER=1, MESA_PKI_STATUS=2, MESA_PKI_LIFECYCLE=3,
  MESA_PKI_PROFILE_CANDIDATE=4, MESA_PKI_RESOLVE=5, MESA_PKI_COMPLETE=6,
  MESA_PKI_WITHDRAW=7, MESA_PKI_OPERATOR_BLOCK=8, MESA_PKI_COMMIT=9,
  MESA_PKI_CANCEL=10, MESA_PKI_ADVANCE=11, MESA_PKI_SUBSCRIBE=12,
  MESA_PKI_UNSUBSCRIBE=13, MESA_PKI_AUTHORIZED_POINT=14,
  MESA_PKI_REFRESH_EVIDENCE=15,
  MESA_PKI_RESOLVE_PEER=16, MESA_PKI_RESOLVED=17
};
/* Zero-initialize. All domains are canonical NUL-terminated, zero-padded.
 * REGISTER: domain, expected old generation (0 if new), value new generation.
 * STATUS: domain, ticket provider domain binding/incarnation/generation; flags bit0 available,
 *         bit1 ready. Availability alone neither revokes nor restores permission.
 * LIFECYCLE: domain, provider; value 1 suspend, 2 remove. Revive/register with a
 *            larger generation; removed/suspended history is retained.
 * PROFILE_CANDIDATE: Mesa profile component supplies peer/domain/life/rift/key/
 *                   evidence AFTER screening. Embedding applications do not
 *                   parse incoming packets to populate this event.
 * RESOLVE: same fields, separate administrative/outbound entry point.
 * COMPLETE: domain, exact ticket; value 0 accepted, 1 rejected, 2 unavailable.
 *           Accept flags bit0 sponsor present, bit1 fief present. Provider
 *           attests validity of these scope relationships as well as currency.
 * WITHDRAW: domain, provider, peer, expected peer revision (0 if unknown).
 * OPERATOR_BLOCK: peer, flags 0 clear / 1 block. COMMIT: token.
 * CANCEL: value request ID. ADVANCE: value monotonic tick.
 * SUBSCRIBE/UNSUBSCRIBE: peer. AUTHORIZED_POINT (RAW only): trusted provider,
 *           candidate fields, expected peer revision, accepted scope flags.
 * RAW accepts REGISTER/STATUS/LIFECYCLE/WITHDRAW/OPERATOR_BLOCK/COMMIT/
 * AUTHORIZED_POINT. JAEL accepts all except AUTHORIZED_POINT.
 * REFRESH_EVIDENCE: exact accepted name/domain/key/life/rift with new evidence.
 * RAW requires provider and expected revision; JAEL dispatches verification.
 * This updates the point, not private-key activation. Both modes support it.
 * RESOLVE_PEER (JAEL): domain, peer. Emits LOOKUP with correlated ticket.
 * RESOLVED (JAEL): exact ticket, candidate fields, scope flags. Negative lookup
 *                 outcomes use COMPLETE. Candidate must match requested name/domain.
 * Provider credentials are host capabilities, never copied from network input. */
typedef struct {
  uint32_t tag, flags;
  uint8_t domain[64], peer[16];
  uint32_t life, rift;
  uint8_t public_key[32];
  const mesa_buffer *evidence;
  uint64_t expected, value;
  mesa_pki_ticket ticket;
  mesa_commit_token token;
  uint8_t sponsor[16], fief[16];
} mesa_pki_event;
enum {
  MESA_PKI_VERIFY=101, MESA_PKI_PERSIST=102, MESA_PKI_CHANGED=103,
  MESA_PKI_FINISHED=104, MESA_PKI_SOLICIT=105, MESA_PKI_TIMER=106,
  MESA_PKI_ERROR=107, MESA_PKI_LOOKUP=108
};
/* VERIFY: owned data=evidence, full candidate and ticket. PERSIST: owned
 * data=checkpoint, token, value=base committed revision. Write proposals in
 * order; a newer full snapshot supersedes older tokens. Confirm latest token
 * after durable write. Do not let a delayed write overwrite a newer snapshot.
 * CHANGED: peer/value revision; query current policy, never replay permission.
 * FINISHED: value=request, flags 1 rejected / 2 timeout / 3 cancelled / 4 stale.
 * SOLICIT: peer, to the Mesa profile (not application delivery).
 * TIMER: flags 1 if deadline exists, value deadline. ERROR: status.
 * Batch get acquires data; release record even after batch/handle destruction. */
typedef struct {
  uint32_t tag;
  int32_t status;
  size_t event_index;
  uint8_t peer[16], domain[64];
  uint32_t life, rift;
  uint8_t public_key[32];
  mesa_pki_ticket ticket;
  mesa_commit_token token;
  uint64_t value;
  uint32_t flags;
  const mesa_buffer *data;
} mesa_pki_record;
int32_t mesa_pki_options_default(mesa_pki_options *out);
int32_t mesa_pki_create(uint32_t kind, const mesa_pki_options *options,
                        const mesa_buffer *checkpoint, mesa_pki **out);
void mesa_pki_release(mesa_pki *handle);
/* Capture a registered provider capability for host-side verifier routing.
 * Domain binding prevents equal generations in different domains from aliasing.
 * A ticket is not a secret credential and must never be trusted from a packet. */
int32_t mesa_pki_provider(const mesa_pki *, const uint8_t domain[64], mesa_pki_ticket *out);
/* At most 64 events. Prefix semantics: errors consume their event and stop;
 * capacity before first event returns MESA_CAPACITY without mutation. Reserve
 * records >= max_pending+max_subscriptions+work_per_tick+4, bytes >=
 * max_checkpoint_bytes+max_pending_bytes+max_evidence_bytes per JAEL event.
 * RAW reserves 2 records and max_checkpoint_bytes. Batches own all outputs. */
int32_t mesa_pki_step(mesa_pki *, const mesa_pki_event *, size_t count,
                      const mesa_budget *, const mesa_pki_batch **out);
int32_t mesa_pki_batch_info(const mesa_pki_batch *, size_t *processed, size_t *count);
int32_t mesa_pki_batch_get(const mesa_pki_batch *, size_t index, mesa_pki_record *out);
void mesa_pki_record_release(mesa_pki_record *);
void mesa_pki_batch_release(const mesa_pki_batch *);
/* Owned immutable options, suitable for importing once into a host plan. */
int32_t mesa_pki_describe(const mesa_pki *, const mesa_buffer **out);
/* Owned JSON state + explicit policy view. Observation, not a checkpoint. */
int32_t mesa_pki_snapshot(const mesa_pki *, const mesa_buffer **out);
/* Apply current authority, never a queued permission, to CORE. Call for affected
 * peers after every transition and before further engine work. Pending proposals
 * close existing gates; committed points provision keys atomically. Returns
 * ordinary mesa_batch records (including cancelled reads and timer changes).
 * A bridge error must stop service until reconciled. FLOW/native control is
 * separate; this call neither creates routes nor authenticates public peeks. */
int32_t mesa_pki_sync_core(const mesa_pki *, mesa_engine *, const uint8_t peer[16],
                          const mesa_budget *, const mesa_batch **out);
#ifdef __cplusplus
}
#endif
#endif
