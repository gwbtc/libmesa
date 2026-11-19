#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "mesa_embed.h"
#include "mesa_transport.h"
#include <assert.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define OK(x)                                                                  \
  do {                                                                         \
    int rc = (x);                                                              \
    if (rc) {                                                                  \
      fprintf(stderr, "line %d: %s = %d\n", __LINE__, #x, rc);                 \
      abort();                                                                 \
    }                                                                          \
  } while (0)
#define N 3
#define WIDTH (1024 * 1024)
static const mesa_budget full = {16385, 64 * 1024 * 1024, 64};
static mesa_options options[N];
static mesa_key keys[N];
static mesa_engine *engine[N];
static mesa_udp_endpoint *endpoint[N];
static mesa_address address[N];
static const mesa_buffer *descriptions[N], *retained, *payload;
static uint8_t expected[WIDTH];
static size_t host_batch = 16, completed, engine_calls, endpoint_calls,
              received_bytes, host_copy_bytes;
static uint64_t tick, last_completion;
static size_t generated, lost, duplicated;
static int failures_enabled;
static size_t timed_out;
static uint64_t prior_retries;
static uint64_t deadlines[N];
static int armed[N];
struct outgoing {
  int from;
  uint8_t peer[16];
  uint64_t generation;
  const mesa_buffer *bytes;
};
static struct outgoing queue[32768];
static size_t queued;
static const mesa_buffer *buffer(const void *p, size_t n, size_t width) {
  const mesa_buffer *b = NULL;
  OK(mesa_buffer_new(p, n, width, &b));
  host_copy_bytes += n;
  return b;
}
static int same(const mesa_buffer *a, const mesa_buffer *b) {
  const uint8_t *x, *y;
  size_t xn, yn, xw, yw;
  OK(mesa_buffer_dat(a, &x, &xn, &xw));
  OK(mesa_buffer_dat(b, &y, &yn, &yw));
  return xn == yn && xw == yw && !memcmp(x, y, xn);
}
static uint64_t field(const mesa_buffer *b, const char *name) {
  const uint8_t *p;
  size_t n, w;
  OK(mesa_buffer_dat(b, &p, &n, &w));
  char *s = calloc(w + 1, 1);
  assert(s);
  OK(mesa_buffer_copy(b, 0, (uint8_t *)s, w));
  char needle[100];
  snprintf(needle, sizeof needle, "\"%s\":", name);
  char *found = strstr(s, needle);
  assert(found);
  uint64_t v = strtoull(found + strlen(needle), NULL, 10);
  free(s);
  return v;
}
static void enqueue(int from, const mesa_result *r) {
  assert(queued < 32768);
  struct outgoing *o = &queue[queued++];
  o->from = from;
  memcpy(o->peer, r->peer, 16);
  o->generation = r->attachment;
  o->bytes = mesa_buffer_retain(r->data);
}
static void collect(int from, const mesa_batch *batch) {
  size_t done, n, bytes;
  OK(mesa_batch_info(batch, &done, &n, &bytes));
  for (size_t j = 0; j < n; j++) {
    mesa_result r = {0};
    OK(mesa_batch_get(batch, j, &r));
    if (r.tag == MESA_EVENT_RESULT) {
      if (r.status) {
        fprintf(stderr, "engine error %d at %zu\n", r.status, r.event_index);
        abort();
      }
    }
    if (r.tag == MESA_TIMER) {
      armed[from] = r.flag;
      deadlines[from] = r.value;
    }
    if (r.tag == MESA_SEND)
      enqueue(from, &r);
    if (r.tag == MESA_READ_FINISHED) {
      if (r.id == 99) {
        assert(r.status == MESA_READ_TIMEOUT);
        timed_out++;
        mesa_result_release(&r);
        continue;
      }
      assert(r.status == 0);
      uint8_t *copy = malloc(WIDTH);
      assert(copy);
      OK(mesa_buffer_copy(r.data, 0, copy, WIDTH));
      host_copy_bytes += WIDTH;
      assert(!memcmp(copy, expected, WIDTH));
      free(copy);
      completed++;
      last_completion = tick;
      mesa_buffer_release(retained);
      retained = mesa_buffer_retain(r.data);
    }
    mesa_result_release(&r);
  }
}
static const mesa_batch *submit(int i, const mesa_event *events, size_t count,
                                const mesa_budget *budget) {
  const mesa_batch *b = NULL;
  engine_calls++;
  OK(mesa_engine_submit(engine[i], options[i].incarnation, events, count,
                        budget, &b));
  return b;
}
static void step(int i, const mesa_event *events, size_t count) {
  while (count) {
    size_t chunk = count < host_batch ? count : host_batch;
    const mesa_batch *b = submit(i, events, chunk, &full);
    size_t done, n, bytes;
    OK(mesa_batch_info(b, &done, &n, &bytes));
    assert(done > 0);
    collect(i, b);
    mesa_batch_release(b);
    events += done;
    count -= done;
  }
}
static int event_status(int i, const mesa_event *event) {
  const mesa_batch *b = submit(i, event, 1, &full);
  mesa_result r = {0};
  OK(mesa_batch_get(b, 0, &r));
  assert(r.tag == MESA_EVENT_RESULT);
  int status = r.status;
  mesa_result_release(&r);
  mesa_batch_release(b);
  return status;
}
static int udp_status(int i, const mesa_udp_command *c) {
  const mesa_batch *b = NULL;
  endpoint_calls++;
  OK(mesa_udp_endpoint_submit(endpoint[i], c, 1, &full, &b));
  mesa_result r = {0};
  OK(mesa_batch_get(b, 0, &r));
  assert(r.tag == MESA_TRANSPORT_RESULT);
  int status = r.status;
  mesa_result_release(&r);
  mesa_batch_release(b);
  return status;
}
static void setup(void) {
  for (int i = 0; i < N; i++) {
    OK(mesa_options_default(&options[i]));
    options[i].local.id[0] = (uint8_t)(i + 1);
    memcpy(options[i].local.domain, "gw-btc", 7);
    options[i].local.key = (uint64_t)i + 1;
    memset(options[i].seed, i + 1, 32);
    options[i].incarnation[0] = (uint8_t)(i + 1);
    options[i].read_timeout = 20000;
    options[i].retry_initial = 20;
    options[i].max_attempts = 200;
    options[i].retry_mode = MESA_EXPONENTIAL;
    options[i].retry_maximum = 160;
    options[i].congestion_mode = MESA_AIMD;
    options[i].peer_window_initial = 4;
    options[i].peer_window_maximum = 16;
    keys[i].handle = (uint64_t)i + 1;
    OK(mesa_key_from_seed(options[i].seed, keys[i].public_key));
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    int bytes = 64 * 1024;
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof bytes) == 0);
    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(fd, (struct sockaddr *)&local, sizeof local) == 0);
    socklen_t size = sizeof local;
    assert(getsockname(fd, (struct sockaddr *)&local, &size) == 0);
    address[i].address[0] = 127;
    address[i].address[3] = 1;
    address[i].port = ntohs(local.sin_port);
    mesa_udp_options udp = {1, 4, 1472};
    OK(mesa_udp_endpoint_new(fd, &udp, &endpoint[i]));
    close(fd);
  }
  mesa_resources resources;
  OK(mesa_resources_default(&resources));
  resources.max_object_bytes = WIDTH;
  resources.max_binding_bytes = 64 * 1024 * 1024;
  resources.max_reassembly_bytes = 64 * 1024 * 1024;
  resources.max_reads = 1024;
  resources.max_bindings = 65536;
  for (int i = 0; i < N; i++) {
    OK(mesa_engine_create_configured(&options[i], &resources, keys, N,
                                     &engine[i]));
    OK(mesa_engine_describe(engine[i], &descriptions[i]));
    assert(field(descriptions[i], "object_bytes") == WIDTH);
    for (int j = 0; j < N; j++)
      if (j != i) {
        mesa_udp_command route = {0};
        route.tag = MESA_UDP_SET_ROUTE;
        route.flag = 1;
        route.peer[0] = (uint8_t)(j + 1);
        route.generation = 1;
        route.address = address[j];
        assert(udp_status(i, &route) == 0);
        mesa_event events[2] = {0};
        events[0].tag = MESA_INSTALL_CREDENTIAL;
        events[0].peer = options[j].local;
        events[0].id = 1;
        events[1].tag = MESA_REPLACE_ATTACHMENT;
        events[1].peer = options[j].local;
        events[1].id = 1;
        events[1].flag = 1;
        step(i, events, 2);
      }
  }
  for (size_t j = 0; j < WIDTH - 32; j++)
    expected[j] = (uint8_t)(j % 251); /* width must retain 32 zeros */
  payload = buffer(expected, WIDTH, WIDTH);
}
static void negatives(void) {
  mesa_resources invalid;
  OK(mesa_resources_default(&invalid));
  invalid.max_reads = 1025;
  mesa_engine *bad = (mesa_engine *)(uintptr_t)1;
  assert(mesa_engine_create_configured(&options[0], &invalid, keys, N, &bad) ==
             MESA_ARGUMENT &&
         bad == NULL);
  const mesa_buffer *before = NULL, *after = NULL;
  OK(mesa_engine_snapshot(engine[0], &before));
  mesa_event events[2] = {0};
  events[0].tag = MESA_ADVANCE_TO;
  events[0].value = 1;
  events[1].tag = MESA_ADVANCE_TO;
  events[1].value = 0;
  const mesa_batch *batch = NULL;
  mesa_budget tiny = {1, 1, 1};
  assert(mesa_engine_submit(engine[0], options[0].incarnation, events, 2, &tiny,
                            &batch) == MESA_CAPACITY &&
         batch == NULL);
  OK(mesa_engine_snapshot(engine[0], &after));
  assert(same(before, after));
  mesa_buffer_release(after);
  mesa_budget one = full;
  one.max_steps = 1;
  batch = submit(0, events, 2, &one);
  size_t done, n, bytes;
  OK(mesa_batch_info(batch, &done, &n, &bytes));
  assert(done == 1);
  mesa_batch_release(batch);
  assert(event_status(0, &events[1]) == MESA_EVENT_ERROR);
  mesa_event stale = {0};
  stale.tag = MESA_INSTALL_CREDENTIAL;
  stale.peer = options[1].local;
  stale.id = 2;
  stale.sequence = 0;
  assert(event_status(0, &stale) == MESA_STALE);
  mesa_buffer_release(before);
  /* Zero-input observation has no mutation and needs only the timer record. */
  OK(mesa_engine_snapshot(engine[0], &before));
  mesa_budget poll = {1, 0, 1};
  batch = submit(0, NULL, 0, &poll);
  mesa_batch_release(batch);
  OK(mesa_engine_snapshot(engine[0], &after));
  assert(same(before, after));
  mesa_buffer_release(before);
  mesa_buffer_release(after);
}
static void flush(void) {
  while (queued) {
    mesa_udp_command cmds[64];
    struct outgoing held[64];
    size_t n = 0;
    /* Reverse global output order to exercise reordering, then group one
     * endpoint. */
    int from = queue[queued - 1].from;
    while (queued && n < host_batch && queue[queued - 1].from == from) {
      struct outgoing o = queue[--queued];
      generated++;
      if (failures_enabled && generated % 23 == 1) {
        lost++;
        mesa_buffer_release(o.bytes);
        continue;
      }
      held[n] = o;
      cmds[n] = (mesa_udp_command){0};
      cmds[n].tag = MESA_UDP_SEND;
      cmds[n].generation = o.generation;
      memcpy(cmds[n].peer, o.peer, 16);
      cmds[n].packet = o.bytes;
      n++;
    }
    if (n) {
      const mesa_batch *b = NULL;
      endpoint_calls++;
      OK(mesa_udp_endpoint_submit(endpoint[from], cmds, n, &full, &b));
      size_t done, nr, bytes;
      OK(mesa_batch_info(b, &done, &nr, &bytes));
      assert(done == n);
      for (size_t j = 0; j < nr; j++) {
        mesa_result r = {0};
        OK(mesa_batch_get(b, j, &r));
        if (r.tag == MESA_TRANSPORT_RESULT)
          assert(r.status == 0 || r.status == MESA_CAPACITY);
        mesa_result_release(&r);
      }
      mesa_batch_release(b);
      if (failures_enabled && generated % 31 == 0) {
        assert(udp_status(from, &cmds[0]) == 0);
        duplicated++;
      }
      for (size_t j = 0; j < n; j++)
        mesa_buffer_release(held[j].bytes);
    }
  }
}
static void receive_at(int i) {
  mesa_udp_command cmds[64] = {0};
  for (size_t j = 0; j < host_batch; j++)
    cmds[j].tag = MESA_UDP_RECEIVE;
  const mesa_batch *b = NULL;
  endpoint_calls++;
  OK(mesa_udp_endpoint_submit(endpoint[i], cmds, host_batch, &full, &b));
  size_t done, n, bytes;
  OK(mesa_batch_info(b, &done, &n, &bytes));
  mesa_event events[16];
  size_t ne = 0;
  for (size_t j = 0; j < n; j++) {
    mesa_result r = {0};
    OK(mesa_batch_get(b, j, &r));
    if (r.tag == MESA_PACKET) {
      events[ne] = (mesa_event){0};
      events[ne].tag = MESA_RECEIVE;
      memcpy(events[ne].peer.id, r.peer, 16);
      events[ne].value = r.attachment;
      events[ne].data = mesa_buffer_retain(r.data);
      ne++;
      const uint8_t *p;
      size_t len, width;
      OK(mesa_buffer_dat(r.data, &p, &len, &width));
      received_bytes += width;
    }
    if (r.tag == MESA_TRANSPORT_RESULT)
      assert(r.status == 0);
    mesa_result_release(&r);
  }
  mesa_batch_release(b);
  step(i, events, ne);
  for (size_t j = 0; j < ne; j++)
    mesa_buffer_release(events[j].data);
}
static uint64_t next_tick(size_t before) {
  if (queued || received_bytes != before)
    return tick + 1;
  uint64_t next = UINT64_MAX;
  for (int i = 0; i < N; i++)
    if (armed[i] && deadlines[i] > tick && deadlines[i] < next)
      next = deadlines[i];
  return next == UINT64_MAX ? tick + 1 : next;
}
static void transfer(void) {
  /* An unavailable binding shares one peer window with useful work. */
  const mesa_buffer *missing = buffer("missing", 7, 7);
  mesa_event stalled = {0};
  stalled.tag = MESA_READ;
  stalled.id = 99;
  stalled.peer = options[1].local;
  stalled.data = missing;
  step(0, &stalled, 1);
  mesa_buffer_release(missing);
  const mesa_buffer *path = buffer("value", 5, 5);
  for (int i = 0; i < N; i++) {
    mesa_event bind = {0};
    bind.tag = MESA_BIND;
    bind.data = path;
    bind.aux = payload;
    step(i, &bind, 1);
    mesa_event reads[2] = {0};
    size_t n = 0;
    for (int j = 0; j < N; j++)
      if (j != i) {
        reads[n].tag = MESA_READ;
        reads[n].peer = options[j].local;
        reads[n].id = (uint64_t)j + 1;
        reads[n].data = path;
        n++;
      }
    step(i, reads, n);
  }
  failures_enabled = 1;
  for (tick = 2; tick < 20000 && completed < 6;) {
    size_t before = received_bytes;
    for (int i = 0; i < N; i++) {
      mesa_event time = {0};
      time.tag = MESA_ADVANCE_TO;
      time.value = tick;
      step(i, &time, 1);
    }
    for (int round = 0; round < 4; round++) {
      flush();
      for (int i = 0; i < N; i++)
        receive_at(i);
    }
    tick = next_tick(before);
  }
  assert(completed == 6);
  mesa_event deadline = {0};
  deadline.tag = MESA_ADVANCE_TO;
  deadline.value = 30000;
  step(0, &deadline, 1);
  assert(timed_out == 1);
  assert(lost > 0);
  assert(duplicated > 0);
  flush();
  for (int i = 0; i < N; i++) {
    const mesa_buffer *snapshot = NULL, *description = NULL;
    OK(mesa_engine_snapshot(engine[i], &snapshot));
    assert(field(snapshot, "reads") == 0);
    assert(field(snapshot, "reassembly_bytes") == 0);
    mesa_buffer_release(snapshot);
    OK(mesa_engine_describe(engine[i], &description));
    assert(same(descriptions[i], description));
    mesa_buffer_release(description);
  }
  mesa_buffer_release(path);
}
static void route_replacement(void) {
  mesa_udp_command route = {0};
  route.tag = MESA_UDP_SET_ROUTE;
  route.peer[0] = 2;
  route.expected_generation = 1;
  route.generation = 2;
  assert(udp_status(0, &route) == 0);
  route.expected_generation = 2;
  route.generation = 3;
  route.flag = 1;
  route.address = address[1];
  assert(udp_status(0, &route) == 0);
  const mesa_buffer *before = NULL, *after = NULL;
  OK(mesa_udp_endpoint_snapshot(endpoint[0], &before));
  const mesa_buffer *packet = buffer("12345678", 8, 8);
  mesa_udp_command stale = {0};
  stale.tag = MESA_UDP_SEND;
  stale.peer[0] = 2;
  stale.generation = 1;
  stale.packet = packet;
  assert(udp_status(0, &stale) == MESA_STALE);
  OK(mesa_udp_endpoint_snapshot(endpoint[0], &after));
  assert(same(before, after));
  mesa_buffer_release(before);
  mesa_buffer_release(after);
  mesa_buffer_release(packet);
  mesa_event replace = {0};
  replace.tag = MESA_REPLACE_ATTACHMENT;
  replace.peer = options[1].local;
  replace.sequence = 1;
  replace.id = 3;
  replace.flag = 1;
  step(0, &replace, 1);
  assert(event_status(0, &replace) == MESA_STALE);
}
static void restart_reader_host(void) {
  /* CORE has no hidden checkpoint. The host rebuilds bindings and permanent
   * retirement fences from durable publication history, with a fresh handle
   * incarnation. This is not PKI activation or an application inbox. */
  const mesa_buffer *snapshot = NULL;
  OK(mesa_engine_snapshot(engine[0], &snapshot));
  prior_retries = field(snapshot, "retransmissions");
  mesa_buffer_release(snapshot);
  mesa_engine_release(engine[0]);
  options[0].incarnation[1] = 1;
  mesa_resources r;
  OK(mesa_resources_default(&r));
  r.max_object_bytes = WIDTH;
  OK(mesa_engine_create_configured(&options[0], &r, keys, N, &engine[0]));
  assert(field(descriptions[0], "object_bytes") ==
         WIDTH); /* retained after destroy */
  for (int j = 1; j < N; j++) {
    mesa_event events[2] = {0};
    events[0].tag = MESA_INSTALL_CREDENTIAL;
    events[0].peer = options[j].local;
    events[0].id = 1;
    events[1].tag = MESA_REPLACE_ATTACHMENT;
    events[1].peer = options[j].local;
    events[1].id = (j == 1 ? 3 : 1);
    events[1].flag = 1;
    step(0, events, 2);
  }
  const mesa_buffer *path = buffer("value", 5, 5);
  mesa_event bind = {0};
  bind.tag = MESA_BIND;
  bind.data = path;
  bind.aux = payload;
  step(0, &bind, 1);
  for (int i = 0; i < N; i++) {
    mesa_event advance = {0};
    advance.tag = MESA_ADVANCE_TO;
    advance.value = 30000;
    step(i, &advance, 1);
  }
  mesa_event read = {0};
  read.tag = MESA_READ;
  read.id = 77;
  read.peer = options[0].local;
  read.data = path;
  step(1, &read, 1);
  failures_enabled = 0;
  for (tick = 30001; tick < 45000 && completed < 7;) {
    size_t before = received_bytes;
    for (int i = 0; i < N; i++) {
      mesa_event time = {0};
      time.tag = MESA_ADVANCE_TO;
      time.value = tick;
      step(i, &time, 1);
    }
    for (int round = 0; round < 4; round++) {
      flush();
      for (int i = 0; i < N; i++)
        receive_at(i);
    }
    tick = next_tick(before);
  }
  assert(completed == 7);
  flush();
  mesa_buffer_release(path);
}
int main(int argc, char **argv) {
  if (argc == 2) {
    host_batch = (size_t)strtoul(argv[1], NULL, 10);
  }
  assert(host_batch == 1 || host_batch == 16);
  struct timespec start, end;
  assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
  setup();
  negatives();
  transfer();
  route_replacement();
  restart_reader_host();
  uint64_t sends = 0, receives = 0, retries = prior_retries;
  for (int i = 0; i < N; i++) {
    const mesa_buffer *s = NULL;
    OK(mesa_udp_endpoint_snapshot(endpoint[i], &s));
    sends += field(s, "send_calls");
    receives += field(s, "receive_calls");
    mesa_buffer_release(s);
    OK(mesa_engine_snapshot(engine[i], &s));
    retries += field(s, "retransmissions");
    mesa_buffer_release(s);
    mesa_engine_release(engine[i]);
    mesa_udp_endpoint_release(endpoint[i]);
    mesa_buffer_release(descriptions[i]);
  }
  uint8_t tail[32];
  OK(mesa_buffer_copy(retained, WIDTH - 32, tail, 32));
  for (size_t i = 0; i < 32; i++)
    assert(tail[i] == 0);
  mesa_buffer_release(retained);
  mesa_buffer_release(payload);
  assert(queued == 0);
  assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
  double seconds = (double)(end.tv_sec - start.tv_sec) +
                   (double)(end.tv_nsec - start.tv_nsec) / 1e9;
  printf("{\"batch\":%zu,\"completed\":%zu,\"payload_bytes\":%d,\"engine_"
         "calls\":%zu,\"endpoint_calls\":%zu,\"send_syscalls\":%" PRIu64
         ",\"receive_syscalls\":%" PRIu64
         ",\"received_packet_bytes\":%zu,\"explicit_host_copy_bytes\":%zu,"
         "\"lost\":%zu,\"duplicates\":%zu,\"retries\":%" PRIu64
         ",\"last_completion_tick\":%" PRIu64 ",\"wall_seconds\":%.6f}\n",
         host_batch, completed, WIDTH, engine_calls, endpoint_calls, sends,
         receives, received_bytes, host_copy_bytes, lost, duplicated, retries,
         last_completion, seconds);
  return 0;
}
