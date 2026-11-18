#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "mesa_embed.h"
#include "mesa_inbox.h"
#include "mesa_transport.h"
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define OK(x)                                                                  \
  do {                                                                         \
    int rc_ = (x);                                                             \
    if (rc_ != 0) {                                                            \
      fprintf(stderr, "%s:%d: %s => %d\n", __FILE__, __LINE__, #x, rc_);       \
      abort();                                                                 \
    }                                                                          \
  } while (0)
static const mesa_budget full = {16385, 64 * 1024 * 1024, 64};
static const mesa_budget one = {16385, 64 * 1024 * 1024, 1};
static mesa_options opt[2];
static mesa_key keys[2];
static mesa_flow_config flows[2];
static mesa_engine *engines[2];
static mesa_inbox_service *services[2];
static const mesa_buffer *finished;
static int finished_status, finished_count;
static int pending[2], ready_count, enqueued_count;
static unsigned sends;
static int faults;
struct packet {
  int destination;
  const mesa_buffer *bytes;
};
static struct packet packets[16384];
static size_t npackets;
static const mesa_buffer *buf(const void *data, size_t n, size_t wid) {
  const mesa_buffer *b = NULL;
  OK(mesa_buffer_new(data, n, wid, &b));
  return b;
}
static void setup(void) {
  for (int i = 0; i < 2; i++) {
    OK(mesa_options_default(&opt[i]));
    opt[i].local.id[0] = (uint8_t)(i + 1);
    memcpy(opt[i].local.domain, "gw-btc", 7);
    opt[i].local.key = (uint64_t)i + 1;
    memset(opt[i].seed, i + 1, 32);
    opt[i].incarnation[0] = (uint8_t)(i + 1);
    opt[i].retry_initial = 5;
    opt[i].read_timeout = 5000;
    opt[i].max_attempts = 30;
    opt[i].congestion_mode = MESA_AIMD;
    opt[i].peer_window_initial = 2;
    opt[i].peer_window_maximum = 16;
    keys[i].handle = opt[i].local.key;
    OK(mesa_key_from_seed(opt[i].seed, keys[i].public_key));
  }
  for (int i = 0; i < 2; i++)
    flows[i] = (mesa_flow_config){
        .flow = 7, .peer = opt[1 - i].local, .attachment = 7, .attached = 1};
}
static void queue(int destination, const mesa_buffer *b) {
  assert(npackets < 16384);
  packets[npackets++] = (struct packet){destination, mesa_buffer_retain(b)};
}
static void collect(const mesa_batch *batch, int source) {
  size_t processed, n, bytes;
  OK(mesa_batch_info(batch, &processed, &n, &bytes));
  for (size_t j = 0; j < n; j++) {
    mesa_result r = {0};
    OK(mesa_batch_get(batch, j, &r));
    switch (r.tag) {
    case MESA_EVENT_RESULT:
      assert(r.status == 0);
      break;
    case MESA_SEND:
      sends++;
      if (!faults || sends % 17 != 1)
        queue(1 - source, r.data);
      if (faults && sends % 11 == 0)
        queue(1 - source, r.data);
      break;
    case MESA_READ_FINISHED:
      finished_count++;
      finished_status = r.status;
      mesa_buffer_release(finished);
      finished = mesa_buffer_retain(r.data);
      break;
    case MESA_SERVICE_PENDING:
      pending[source] = 1;
      break;
    case MESA_INBOX_READY:
      ready_count++;
      break;
    case MESA_ENQUEUED:
      enqueued_count++;
      break;
    case MESA_STORAGE_ERROR:
      fprintf(stderr, "unexpected storage error\n");
      abort();
    default:
      break;
    }
    mesa_result_release(&r);
  }
  mesa_batch_release(batch);
}
static void step(int i, const mesa_event *e, size_t n) {
  const mesa_batch *b = NULL;
  OK(mesa_engine_submit(engines[i], opt[i].incarnation, e, n, &full, &b));
  collect(b, i);
}
static size_t service_step(int i, const mesa_event *e, size_t n,
                           const mesa_budget *budget) {
  const mesa_batch *b = NULL;
  pending[i] = 0;
  OK(mesa_inbox_submit(services[i], e, n, budget, &b));
  size_t processed, results, bytes;
  OK(mesa_batch_info(b, &processed, &results, &bytes));
  collect(b, i);
  return processed;
}
static void clear_packets(void) {
  while (npackets)
    mesa_buffer_release(packets[--npackets].bytes);
}
static void receive_one(int service, const mesa_budget *budget) {
  size_t index = faults ? npackets / 2 : 0;
  struct packet p = packets[index];
  memmove(&packets[index], &packets[index + 1],
          (--npackets - index) * sizeof p);
  mesa_event e = {0};
  e.tag = MESA_RECEIVE;
  e.peer.id[0] = (uint8_t)(2 - p.destination);
  e.value = 7;
  e.data = p.bytes;
  if (service) {
    if (service_step(p.destination, &e, 1, budget) == 0)
      queue(p.destination, p.bytes);
  } else
    step(p.destination, &e, 1);
  mesa_buffer_release(p.bytes);
}
static void *share_buffer(void *arg) {
  const mesa_buffer *b = arg;
  for (int i = 0; i < 1000; i++) {
    const mesa_buffer *copy = mesa_buffer_retain(b);
    uint8_t bytes[6];
    OK(mesa_buffer_copy(copy, 0, bytes, 6));
    assert(bytes[0] == 1 && bytes[5] == 0);
    mesa_buffer_release(copy);
  }
  return NULL;
}
static void buffers_and_core(void) {
  const uint8_t data[] = {1, 2};
  const mesa_buffer *b = buf(data, 2, 6);
  const uint8_t *dat;
  size_t len, wid;
  OK(mesa_buffer_dat(b, &dat, &len, &wid));
  assert(len == 2 && wid == 6 && dat[1] == 2);
  uint8_t copy[6];
  OK(mesa_buffer_copy(b, 0, copy, 6));
  assert(copy[0] == 1 && copy[5] == 0);
  assert(mesa_buffer_copy(b, 5, copy, 2) == MESA_ARGUMENT);
  pthread_t threads[4];
  for (int i = 0; i < 4; i++)
    assert(pthread_create(&threads[i], NULL, share_buffer, (void *)b) == 0);
  for (int i = 0; i < 4; i++)
    assert(pthread_join(threads[i], NULL) == 0);
  const mesa_buffer *empty = buf(NULL, 0, 0), *zeroes = buf(NULL, 0, 65536);
  OK(mesa_buffer_dat(empty, &dat, &len, &wid));
  assert(len == 0 && wid == 0);
  OK(mesa_buffer_dat(zeroes, &dat, &len, &wid));
  assert(len == 0 && wid == 65536);
  mesa_buffer_release(empty);
  mesa_buffer_release(zeroes);
  const mesa_buffer *saved = mesa_buffer_retain(b);
  mesa_buffer_release(b);
  OK(mesa_buffer_copy(saved, 2, copy, 4));
  assert(copy[0] == 0);
  mesa_buffer_release(saved);
  for (int i = 0; i < 2; i++) {
    OK(mesa_engine_create(&opt[i], &keys[1 - i], 1, NULL, 0, NULL,
                          &engines[i]));
    mesa_event e[2] = {0};
    e[0].tag = MESA_INSTALL_PEER;
    e[0].peer = opt[1 - i].local;
    e[1].tag = MESA_SET_ATTACHMENT;
    e[1].peer = opt[1 - i].local;
    e[1].flag = 1;
    e[1].value = 7;
    step(i, e, 2);
  }
  const mesa_buffer *description = NULL;
  OK(mesa_engine_describe(engines[0], &description));
  const mesa_buffer *path = buf("/example", 8, 8);
  uint8_t data2[17425];
  for (size_t i = 0; i < sizeof data2; i++)
    data2[i] = (uint8_t)(i % 251);
  const mesa_buffer *payload = buf(data2, sizeof data2, sizeof data2 + 100);
  mesa_event bind = {0};
  bind.tag = MESA_BIND;
  bind.data = path;
  bind.aux = payload;
  step(1, &bind, 1);
  mesa_buffer_release(payload);
  mesa_event read = {0};
  read.tag = MESA_READ;
  read.id = 40;
  read.peer = opt[1].local;
  read.data = path;
  const mesa_batch *batch = NULL;
  mesa_budget zero = {0, 0, 1};
  assert(mesa_engine_submit(engines[0], opt[0].incarnation, &read, 1, &zero,
                            &batch) == MESA_CAPACITY &&
         batch == NULL);
  uint8_t stale[16] = {99};
  assert(mesa_engine_submit(engines[0], stale, &read, 1, &full, &batch) ==
         MESA_STALE);
  faults = 1;
  step(0, &read, 1);
  mesa_buffer_release(path);
  for (uint64_t tick = 1; tick < 4000 && !finished_count; tick++) {
    if (npackets)
      receive_one(0, &full);
    if (tick % 10 == 0) {
      mesa_event advance = {0};
      advance.tag = MESA_ADVANCE_TO;
      advance.value = tick;
      step(0, &advance, 1);
      step(1, &advance, 1);
    }
  }
  assert(finished_count == 1 && finished_status == 0 && finished);
  const mesa_buffer *completed_payload = mesa_buffer_retain(finished);
  uint8_t recovered[17525];
  OK(mesa_buffer_copy(finished, 0, recovered, sizeof recovered));
  assert(!memcmp(recovered, data2, sizeof data2));
  for (size_t i = sizeof data2; i < sizeof recovered; i++)
    assert(recovered[i] == 0);
  faults = 0;
  clear_packets();
  /* Semantic failure stops at its index; later events remain untouched. */
  mesa_event events[3] = {0};
  events[0].tag = MESA_ADVANCE_TO;
  events[0].value = 4000;
  events[1].tag = 999;
  events[2].tag = MESA_CLOSE;
  OK(mesa_engine_submit(engines[0], opt[0].incarnation, events, 3, &full,
                        &batch));
  size_t processed, n, bytes;
  OK(mesa_batch_info(batch, &processed, &n, &bytes));
  assert(processed == 2);
  mesa_batch_release(batch);
  /* Result capacity stops before the next event, independently of work budget.
   */
  mesa_budget tight = {MESA_STEP_RECORDS + 1, MESA_STEP_BYTES, 64};
  events[0].value = 4000;
  events[1] = events[0];
  OK(mesa_engine_submit(engines[0], opt[0].incarnation, events, 2, &tight,
                        &batch));
  OK(mesa_batch_info(batch, &processed, &n, &bytes));
  assert(processed == 1);
  mesa_batch_release(batch);
  /* Work prefix: close has not run. */
  events[0].value = 4001;
  events[1] = events[0];
  events[1].value = 4002;
  OK(mesa_engine_submit(engines[0], opt[0].incarnation, events, 2, &one,
                        &batch));
  OK(mesa_batch_info(batch, &processed, &n, &bytes));
  assert(processed == 1);
  mesa_batch_release(batch);
  path = buf("/absent", 7, 7);
  read.data = path;
  read.id = 41;
  step(0, &read, 1);
  mesa_event cancel = {0};
  cancel.tag = MESA_CANCEL;
  cancel.id = 41;
  step(0, &cancel, 1);
  assert(finished_status == MESA_READ_CANCELLED);
  read.id = 42;
  step(0, &read, 1);
  mesa_event advance = {0};
  advance.tag = MESA_ADVANCE_TO;
  advance.value = 10000;
  step(0, &advance, 1);
  assert(finished_status == MESA_READ_TIMEOUT);
  read.id = 43;
  step(0, &read, 1);
  mesa_buffer_release(path);
  const mesa_buffer *description2 = NULL;
  OK(mesa_engine_describe(engines[0], &description2));
  const uint8_t *a, *c;
  size_t an, aw, cn, cw;
  OK(mesa_buffer_dat(description, &a, &an, &aw));
  OK(mesa_buffer_dat(description2, &c, &cn, &cw));
  assert(an == cn && aw == cw && !memcmp(a, c, an));
  mesa_event close = {0};
  close.tag = MESA_CLOSE;
  step(0, &close, 1);
  assert(finished_status == MESA_READ_CANCELLED);
  assert(mesa_engine_submit(engines[0], opt[0].incarnation, NULL, 0, &full,
                            &batch) == MESA_CLOSED);
  mesa_engine_release(engines[0]);
  mesa_engine_release(engines[1]);
  clear_packets();
  OK(mesa_buffer_copy(completed_payload, 0, recovered, sizeof recovered));
  assert(!memcmp(recovered, data2, sizeof data2));
  mesa_buffer_release(completed_payload);
  OK(mesa_buffer_dat(description, &a, &an, &aw));
  assert(an > 0);
  mesa_buffer_release(description);
  mesa_buffer_release(description2);
  mesa_buffer_release(finished);
  finished = NULL;
}
static void explicit_transactions(void) {
  mesa_options o = opt[0];
  o.kind = MESA_FLOW;
  mesa_engine *h = NULL;
  OK(mesa_engine_create(&o, &keys[1], 1, &flows[0], 1, NULL, &h));
  const mesa_buffer *payload = buf("durable", 7, 12);
  mesa_event e = {0};
  e.tag = MESA_ENQUEUE;
  e.id = 7;
  e.data = payload;
  const mesa_batch *b;
  OK(mesa_engine_submit(h, o.incarnation, &e, 1, &full, &b));
  mesa_buffer_release(payload);
  size_t p, n, z;
  OK(mesa_batch_info(b, &p, &n, &z));
  mesa_commit_token token = {0};
  const mesa_buffer *checkpoint = NULL;
  for (size_t i = 0; i < n; i++) {
    mesa_result r = {0};
    OK(mesa_batch_get(b, i, &r));
    if (r.tag == MESA_COMMIT) {
      assert(r.commit.change == MESA_CHANGE_ENQUEUE && r.commit.revision == 1 &&
             r.commit.base_revision == 0);
      token = r.commit.token;
      checkpoint = mesa_buffer_retain(r.commit.checkpoint);
    }
    mesa_result_release(&r);
  }
  assert(checkpoint);
  mesa_batch_release(b);
  mesa_engine_release(h);
  /* Host committed the proposed snapshot but lost its confirmation. */
  o.incarnation[0] = 77;
  OK(mesa_engine_create(&o, &keys[1], 1, &flows[0], 1, checkpoint, &h));
  mesa_buffer_release(checkpoint);
  e = (mesa_event){0};
  e.tag = MESA_COMMITTED;
  e.token = token;
  OK(mesa_engine_submit(h, o.incarnation, &e, 1, &full, &b));
  mesa_result r = {0};
  OK(mesa_batch_get(b, 0, &r));
  assert(r.tag == MESA_EVENT_RESULT && r.status != 0);
  mesa_result_release(&r);
  mesa_batch_release(b);
  mesa_engine_release(h);
}
static int udp_socket(struct sockaddr_in *address) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  assert(fd >= 0);
  *address = (struct sockaddr_in){
      .sin_family = AF_INET, .sin_addr.s_addr = htonl(UINT32_C(0x7f000001))};
  assert(bind(fd, (struct sockaddr *)address, sizeof *address) == 0);
  socklen_t n = sizeof *address;
  assert(getsockname(fd, (struct sockaddr *)address, &n) == 0);
  return fd;
}
static void transport_pair(int tcp) {
  int fd[2];
  struct sockaddr_in addr[2];
  if (!tcp) {
    fd[0] = udp_socket(&addr[0]);
    fd[1] = udp_socket(&addr[1]);
  } else {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    addr[0] = (struct sockaddr_in){
        .sin_family = AF_INET, .sin_addr.s_addr = htonl(UINT32_C(0x7f000001))};
    assert(bind(listener, (struct sockaddr *)&addr[0], sizeof addr[0]) == 0);
    socklen_t n = sizeof addr[0];
    assert(getsockname(listener, (struct sockaddr *)&addr[0], &n) == 0);
    assert(listen(listener, 1) == 0);
    fd[0] = socket(AF_INET, SOCK_STREAM, 0);
    assert(connect(fd[0], (struct sockaddr *)&addr[0], sizeof addr[0]) == 0);
    fd[1] = accept(listener, NULL, NULL);
    assert(fd[1] >= 0);
    close(listener);
  }
  mesa_transport *t[2];
  for (int i = 0; i < 2; i++) {
    mesa_transport_config c = {
        .attachment = 7, .max_packet_bytes = 1472, .queue_bytes = 1476};
    c.peer[0] = (uint8_t)(2 - i);
    if (tcp)
      OK(mesa_transport_tcp(fd[i], &c, &t[i]));
    else {
      mesa_address a = {.address = {127, 0, 0, 1},
                        .port = ntohs(addr[1 - i].sin_port)};
      OK(mesa_transport_udp(fd[i], &a, &c, &t[i]));
    }
    close(fd[i]);
    mesa_transport_caps caps;
    OK(mesa_transport_capabilities(t[i], &caps));
    assert(caps.reliable == (uint32_t)tcp && caps.fd >= 0);
  }
  const mesa_buffer *payload = buf("12345678", 8, 1472);
  mesa_transport_command commands[2] = {
      {.tag = MESA_SEND_PACKET, .packet = payload},
      {.tag = MESA_SEND_PACKET, .packet = payload}};
  const mesa_batch *b;
  OK(mesa_transport_submit(t[0], commands, 2, &full, &b));
  if (tcp) {
    mesa_result r = {0};
    OK(mesa_batch_get(b, 1, &r));
    assert(r.status == MESA_CAPACITY);
    mesa_result_release(&r);
  }
  mesa_batch_release(b);
  mesa_buffer_release(payload);
  mesa_transport_command flush = {.tag = MESA_FLUSH};
  OK(mesa_transport_submit(t[0], &flush, 1, &full, &b));
  mesa_batch_release(b);
  const mesa_buffer *received = NULL;
  for (int j = 0; j < 10000 && !received; j++) {
    mesa_transport_command receive = {.tag = MESA_RECEIVE_PACKET};
    OK(mesa_transport_submit(t[1], &receive, 1, &full, &b));
    size_t p, n, z;
    OK(mesa_batch_info(b, &p, &n, &z));
    for (size_t i = 0; i < n; i++) {
      mesa_result r = {0};
      OK(mesa_batch_get(b, i, &r));
      if (r.tag == MESA_PACKET)
        received = mesa_buffer_retain(r.data);
      mesa_result_release(&r);
    }
    mesa_batch_release(b);
  }
  assert(received);
  mesa_transport_release(t[0]);
  mesa_transport_release(t[1]);
  uint8_t bytes[1472];
  OK(mesa_buffer_copy(received, 0, bytes, sizeof bytes));
  assert(!memcmp(bytes, "12345678", 8) && bytes[1471] == 0);
  mesa_buffer_release(received);
}
static size_t inbox_count(int i, mesa_message_id *id) {
  const mesa_batch *b;
  OK(mesa_inbox_scan(services[i], 0, 64, &b));
  size_t p, n, z;
  OK(mesa_batch_info(b, &p, &n, &z));
  if (n && id) {
    mesa_result r = {0};
    OK(mesa_batch_get(b, 0, &r));
    *id = r.message;
    uint8_t data[12];
    OK(mesa_buffer_copy(r.data, 0, data, 12));
    assert(!memcmp(data, "hello", 5) && data[11] == 0);
    mesa_result_release(&r);
  }
  mesa_batch_release(b);
  return n;
}
static void open_services(const char *directory, int create) {
  for (int i = 0; i < 2; i++) {
    char path[512];
    snprintf(path, sizeof path, "%s/peer%d.db", directory, i);
    const mesa_buffer *p = buf(path, strlen(path), strlen(path));
    mesa_options o = opt[i];
    o.kind = MESA_FLOW;
    if (create)
      OK(mesa_inbox_create(&o, &keys[1 - i], 1, &flows[i], 1, p, &services[i]));
    else
      OK(mesa_inbox_open(&o, &keys[1 - i], 1, &flows[i], 1, p, &services[i]));
    mesa_buffer_release(p);
  }
}
static void enqueue_message(const mesa_budget *budget) {
  const mesa_buffer *p = buf("hello", 5, 12);
  mesa_event e = {0};
  e.tag = MESA_ENQUEUE;
  e.id = 7;
  e.data = p;
  service_step(0, &e, 1, budget);
  mesa_buffer_release(p);
}
static void crash_child(const char *directory, int boundary) {
  ready_count = 0;
  enqueued_count = 0;
  pending[0] = pending[1] = 0;
  open_services(directory, 1);
  enqueue_message(&one);
  if (boundary == 0)
    kill(getpid(), SIGKILL); /* enqueue proposal, before persist */
  service_step(0, NULL, 0, &one);
  if (boundary == 1)
    kill(getpid(), SIGKILL); /* enqueue persisted, before confirm */
  for (uint64_t tick = 0; tick < 4000; tick++) {
    for (int i = 0; i < 2; i++)
      service_step(i, NULL, 0, &one);
    if (npackets)
      receive_one(1, &one);
    if (boundary == 2 && pending[1] && inbox_count(1, NULL) == 0)
      kill(getpid(), SIGKILL);
    if (boundary == 3 && inbox_count(1, NULL) == 1 && ready_count == 0)
      kill(getpid(), SIGKILL);
    if (tick % 10 == 0) {
      mesa_event e = {0};
      e.tag = MESA_ADVANCE_TO;
      e.value = tick;
      for (int i = 0; i < 2; i++)
        service_step(i, &e, 1, &one);
    }
  }
  _exit(90);
}
static void inbox_crashes(void) {
  for (int boundary = 0; boundary < 4; boundary++) {
    char directory[] = "/tmp/mesa-c-inbox-XXXXXX";
    assert(mkdtemp(directory));
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0)
      crash_child(directory, boundary);
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    clear_packets();
    open_services(directory, 0);
    if (boundary == 0)
      enqueue_message(&full);
    for (uint64_t tick = 0; tick < 4000; tick++) {
      for (int i = 0; i < 2; i++)
        service_step(i, NULL, 0, &full);
      if (npackets)
        receive_one(1, &full);
      if (tick % 10 == 0) {
        mesa_event e = {0};
        e.tag = MESA_ADVANCE_TO;
        e.value = tick;
        for (int i = 0; i < 2; i++)
          service_step(i, &e, 1, &full);
      }
      if (inbox_count(1, NULL) == 1 && enqueued_count > 0 && tick > 100)
        break;
    }
    mesa_flow_progress progress;
    OK(mesa_inbox_flow_progress(services[0], 7, &progress));
    assert(progress.next_sequence == 1 && progress.pending_messages == 0);
    const mesa_batch *outcomes = NULL;
    OK(mesa_inbox_outcomes(services[0], 0, 64, &outcomes));
    size_t outcome_processed, outcome_count, outcome_bytes;
    OK(mesa_batch_info(outcomes, &outcome_processed, &outcome_count,
                       &outcome_bytes));
    assert(outcome_count == 1);
    mesa_result settled = {0};
    OK(mesa_batch_get(outcomes, 0, &settled));
    assert(settled.tag == MESA_SETTLED && settled.outcome == -1 &&
           settled.message.sequence == 0);
    mesa_result_release(&settled);
    mesa_batch_release(outcomes);
    mesa_message_id id;
    assert(inbox_count(1, &id) == 1);
    OK(mesa_inbox_mark_consumed(services[1], &id, 1));
    OK(mesa_inbox_mark_consumed(services[1], &id, 1));
    assert(inbox_count(1, NULL) == 0);
    for (int i = 0; i < 2; i++)
      mesa_inbox_release(services[i]);
    clear_packets();
    open_services(directory, 0);
    assert(inbox_count(1, NULL) == 0);
    /* Opening another writer fences the existing service. */
    mesa_inbox_service *old = services[1];
    char path[512];
    snprintf(path, sizeof path, "%s/peer1.db", directory);
    const mesa_buffer *p = buf(path, strlen(path), strlen(path));
    mesa_options o = opt[1];
    o.kind = MESA_FLOW;
    OK(mesa_inbox_open(&o, &keys[0], 1, &flows[1], 1, p, &services[1]));
    mesa_buffer_release(p);
    const mesa_batch *b = NULL;
    assert(mesa_inbox_scan(old, 0, 64, &b) == MESA_IO && b == NULL);
    mesa_inbox_release(old);
    for (int i = 0; i < 2; i++)
      mesa_inbox_release(services[i]);
    for (int i = 0; i < 2; i++) {
      snprintf(path, sizeof path, "%s/peer%d.db", directory, i);
      assert(unlink(path) == 0);
    }
    assert(rmdir(directory) == 0);
    printf("C inbox SIGKILL boundary %d recovered\n", boundary);
  }
}
int main(void) {
  setup();
  buffers_and_core();
  explicit_transactions();
  transport_pair(0);
  transport_pair(1);
  inbox_crashes();
  puts("C embedding ownership, faults, batching, transports and crash recovery "
       "passed");
  return 0;
}
