#ifndef LIBMESA_INBOX_H
#define LIBMESA_INBOX_H
#include "mesa_embed.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct mesa_inbox_service mesa_inbox_service;
enum {
  MESA_SERVICE_PENDING = 114,
  MESA_INBOX_READY = 115,
  MESA_STORAGE_ERROR = 116,
  MESA_INBOX_ENTRY = 117
};
/* Persistent FLOW engine and SQLite inbox, no sockets or hidden threads.
 * path is a UTF-8 buffer without embedded NUL. options.kind must be FLOW;
 * incarnation comes from the database; options.incarnation is ignored.
 * create refuses an existing path; open refuses missing/incompatible state.
 * These calls perform synchronous storage I/O. The store fences older owners.
 */
int32_t mesa_inbox_create(const mesa_options *, const mesa_key *,
                          size_t key_count, const mesa_flow_config *,
                          size_t flow_count, const mesa_buffer *path,
                          mesa_inbox_service **out);
int32_t mesa_inbox_open(const mesa_options *, const mesa_key *,
                        size_t key_count, const mesa_flow_config *,
                        size_t flow_count, const mesa_buffer *path,
                        mesa_inbox_service **out);
int32_t mesa_inbox_describe(const mesa_inbox_service *,
                            const mesa_buffer **out);
/* Accepts INSTALL_PEER, SERVICE, ATTACHMENT, ADVANCE, RECEIVE, ENQUEUE, RESUME,
 * INVALIDATE, CLOSE. Delivery decisions and commit confirmations are internal.
 * max_steps bounds external events AND internal decide/persist/confirm steps.
 * Drain pending work first; count=0 progresses it. SERVICE_PENDING means more
 * internal work remains. A processed enqueue event is not yet durable; ENQUEUED
 * means the commit is confirmed. Recovered checkpoint/outcomes are
 * authoritative. INBOX_READY carries message/outcome; scan is authoritative
 * after lost notices. Storage errors return STORAGE_ERROR alongside prior
 * results and stop mutation; release and reopen the authoritative store before
 * continuing. Never ack error. No input is consumed if CAPACITY is returned
 * without a batch. A batch can process zero external inputs while progressing
 * internal work. Receipt acceptance means durable inbox insertion, not
 * application execution. */
int32_t mesa_inbox_submit(mesa_inbox_service *, const mesa_event *,
                          size_t count, const mesa_budget *,
                          const mesa_batch **out);
/* Opaque latest DURABLE checkpoint, including persistence before lost confirm.
 * Revision/sequence recovery only: never roll back or replace the live
 * database. */
int32_t mesa_inbox_checkpoint(mesa_inbox_service *, const mesa_buffer **out);
/* after_revision=0 starts/restarts the scan; limit 1..64. INBOX_ENTRY contains
 * message,data,value=revision. Excludes consumed entries; never deletes
 * history. */
int32_t mesa_inbox_scan(mesa_inbox_service *, uint64_t after_revision,
                        size_t limit, const mesa_batch **out);
int32_t mesa_inbox_mark_consumed(mesa_inbox_service *, const mesa_message_id *,
                                 size_t count);
/* Durable sender recovery; SETTLED entries carry value=commit revision. */
int32_t mesa_inbox_outcomes(mesa_inbox_service *, uint64_t after_revision,
                            size_t limit, const mesa_batch **out);
typedef struct {
  uint64_t revision, next_sequence, send_floor, receive_floor;
  size_t pending_messages;
} mesa_flow_progress;
/* Next sequence and outbox count from latest durable checkpoint. No parsing. */
int32_t mesa_inbox_flow_progress(mesa_inbox_service *, uint64_t flow,
                                 mesa_flow_progress *out);
void mesa_inbox_release(mesa_inbox_service *);
#ifdef __cplusplus
}
#endif
#endif
