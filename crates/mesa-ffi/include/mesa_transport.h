#ifndef LIBMESA_TRANSPORT_H
#define LIBMESA_TRANSPORT_H
#include "mesa_embed.h"
#ifdef __cplusplus
extern "C" {
#endif
/* POSIX adapters. No engine, time, persistence, connect/accept, or threads.
 * Constructors duplicate fd; callers still own their fd. Nonblocking mode is
 * shared by the duplicate and original. TCP also enables TCP_NODELAY. */
typedef struct mesa_transport mesa_transport;
typedef struct {
  uint8_t address[16];
  uint32_t ipv6;
  uint16_t port;
} mesa_address;
typedef struct {
  uint8_t peer[16];
  uint64_t attachment;
  size_t max_packet_bytes, queue_bytes;
} mesa_transport_config;
typedef struct {
  size_t max_packet_bytes;
  uint32_t reliable, ordered,
      framing; /* framing: 0 datagram, 1 length prefix */
  int32_t
      fd; /* borrowed duplicate for readiness registration; never close it */
} mesa_transport_caps;
enum { MESA_SEND_PACKET = 1, MESA_RECEIVE_PACKET = 2, MESA_FLUSH = 3 };
enum {
  MESA_PACKET = 200,
  MESA_TRANSPORT_RESULT = 201,
  MESA_READINESS = 202,
  MESA_DISCONNECTED = 203
};
typedef struct {
  uint32_t tag;
  uint64_t cookie;
  const mesa_buffer *packet;
} mesa_transport_command;
int32_t mesa_transport_udp(int32_t fd, const mesa_address *next_hop,
                           const mesa_transport_config *, mesa_transport **out);
int32_t mesa_transport_tcp(int32_t fd, const mesa_transport_config *,
                           mesa_transport **out);
int32_t mesa_transport_capabilities(const mesa_transport *,
                                    mesa_transport_caps *out);
int32_t mesa_transport_describe(const mesa_transport *,
                                const mesa_buffer **out);
/* Prefix acceptance; count <=64, max_steps commands. Reserve 2 records plus
 * max_packet_bytes before each command and one final readiness record.
 * SEND_PACKET produces status OK for admission or CAPACITY for local loss.
 * RECEIVE_PACKET makes one bounded receive attempt, possibly returning PACKET.
 * FLUSH makes at most 64 write attempts, gathering up to 64 queued TCP frames
 * per write. No syscall per buffer retain/release or capabilities query.
 * READINESS.flag bits: 1 readable, 2 writable; value=queued stream bytes.
 * PACKET uses peer,attachment,data. A local source claim is not authentication.
 * Hard I/O errors return DISCONNECTED alongside earlier results; then CLOSED.
 * PANIC poisons this handle; only describe/release remain valid. */
int32_t mesa_transport_submit(mesa_transport *, const mesa_transport_command *,
                              size_t count, const mesa_budget *,
                              const mesa_batch **out);
void mesa_transport_release(mesa_transport *);
#ifdef __cplusplus
}
#endif
#endif
