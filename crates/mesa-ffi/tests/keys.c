#define _POSIX_C_SOURCE 200809L
#include "mesa_keys.h"
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#define OK(x)                                                                  \
  do {                                                                         \
    int rc_ = (x);                                                             \
    if (rc_) {                                                                 \
      fprintf(stderr, "%s:%d %s => %d\n", __FILE__, __LINE__, #x, rc_);        \
      abort();                                                                 \
    }                                                                          \
  } while (0)
static const mesa_budget budget = {16385, 64 * 1024 * 1024, 64};
static mesa_pki_ticket provider;
static mesa_keys_options options;
static uint8_t public_key[32];
static uint32_t life = 1, rift = 0;
static size_t width(const mesa_buffer *b) {
  const uint8_t *d;
  size_t n, w;
  OK(mesa_buffer_dat(b, &d, &n, &w));
  return w;
}
static const mesa_buffer *bytes(const uint8_t *p, size_t n, size_t w) {
  const mesa_buffer *b = NULL;
  OK(mesa_buffer_new(p, n, w, &b));
  return b;
}
static mesa_pki_record pstep(mesa_pki *p, mesa_pki_event e, uint32_t wanted) {
  const mesa_pki_batch *b = NULL;
  OK(mesa_pki_step(p, &e, 1, &budget, &b));
  size_t done, n;
  OK(mesa_pki_batch_info(b, &done, &n));
  assert(done == 1);
  mesa_pki_record found = {0};
  for (size_t i = 0; i < n; i++) {
    mesa_pki_record r = {0};
    OK(mesa_pki_batch_get(b, i, &r));
    assert(r.tag != MESA_PKI_ERROR);
    if (r.tag == wanted)
      found = r;
    else
      mesa_pki_record_release(&r);
  }
  mesa_pki_batch_release(b);
  if (wanted)
    assert(found.tag == wanted);
  return found;
}
static mesa_pki_event pevent(uint32_t tag) {
  mesa_pki_event e = {0};
  e.tag = tag;
  memcpy(e.domain, "gw-btc", 7);
  e.peer[0] = 1;
  e.ticket = provider;
  return e;
}
static mesa_pki *authority(void) {
  mesa_pki_options o = {0};
  o.version = 1;
  o.incarnation[0] = 1;
  o.max_domains = 2;
  o.max_peers = 8;
  o.max_history = 4;
  o.max_evidence_bytes = 1024;
  o.max_checkpoint_bytes = 1024 * 1024;
  o.max_pending = 4;
  o.max_pending_bytes = 4096;
  o.max_packet = 1472;
  o.request_timeout = 20;
  o.retry_after = 5;
  o.attempts = 2;
  o.work_per_tick = 2;
  o.max_subscriptions = 4;
  o.dispatches = 4;
  o.dispatch_interval = 10;
  mesa_pki *p = NULL;
  OK(mesa_pki_create(MESA_PKI_RAW, &o, NULL, &p));
  mesa_pki_event e = pevent(MESA_PKI_REGISTER);
  e.value = 1;
  mesa_pki_record q = pstep(p, e, MESA_PKI_PERSIST);
  e = pevent(MESA_PKI_COMMIT);
  e.token = q.token;
  pstep(p, e, 0);
  mesa_pki_record_release(&q);
  uint8_t d[64] = {0};
  memcpy(d, "gw-btc", 7);
  OK(mesa_pki_provider(p, d, &provider));
  e = pevent(MESA_PKI_STATUS);
  e.flags = 3;
  pstep(p, e, 0);
  e = pevent(MESA_PKI_AUTHORIZED_POINT);
  e.life = life;
  e.rift = rift;
  memcpy(e.public_key, public_key, 32);
  uint8_t v = 1;
  e.evidence = bytes(&v, 1, 4);
  q = pstep(p, e, MESA_PKI_PERSIST);
  mesa_buffer_release(e.evidence);
  e = pevent(MESA_PKI_COMMIT);
  e.token = q.token;
  pstep(p, e, 0);
  mesa_pki_record_release(&q);
  return p;
}
static mesa_key_event event(uint32_t tag) {
  mesa_key_event e = {0};
  e.tag = tag;
  e.reference.backend[0] = 1;
  e.reference.object[0] = 1;
  e.reference.version = life;
  return e;
}
static mesa_result step(mesa_keys *k, mesa_pki *p, mesa_engine *engine,
                        mesa_key_event e, uint32_t wanted, int failure) {
  const mesa_batch *b = NULL;
  OK(mesa_keys_submit(k, p, engine, &e, 1, &budget, &b));
  size_t done, n, byte_count;
  OK(mesa_batch_info(b, &done, &n, &byte_count));
  assert(done == 1);
  mesa_result found = {0};
  for (size_t i = 0; i < n; i++) {
    mesa_result r = {0};
    OK(mesa_batch_get(b, i, &r));
    if (r.tag == MESA_EVENT_RESULT)
      assert((r.status != 0) == failure);
    if (r.tag == wanted) {
      mesa_result_release(&found);
      found = r;
    } else
      mesa_result_release(&r);
  }
  mesa_batch_release(b);
  if (wanted)
    assert(found.tag == wanted);
  return found;
}
static void stage(mesa_keys *k, mesa_pki *p, const mesa_buffer *seed) {
  mesa_key_event e = event(MESA_KEYS_IMPORT_SEED);
  e.peer[0] = 1;
  e.life = life;
  e.rift = rift;
  memcpy(e.public_key, public_key, 32);
  uint8_t v = 1;
  e.data = bytes(&v, 1, 4);
  e.seed = seed;
  step(k, p, NULL, e, 0, 0);
  mesa_buffer_release(e.data);
}
static mesa_engine *engine(uint8_t incarnation[16]) {
  mesa_options o;
  OK(mesa_options_default(&o));
  o.local.id[0] = 1;
  memcpy(o.local.domain, "gw-btc", 7);
  o.local.key = 1;
  o.incarnation[0] = 9;
  memcpy(incarnation, o.incarnation, 16);
  memset(o.seed, 1, 32);
  mesa_key key = {0};
  key.handle = 2;
  memcpy(key.public_key, public_key, 32);
  mesa_engine *h = NULL;
  OK(mesa_engine_create(&o, &key, 1, NULL, 0, NULL, &h));
  mesa_event e[2] = {0};
  e[0].tag = MESA_INSTALL_PEER;
  e[0].peer.id[0] = 2;
  memcpy(e[0].peer.domain, "gw-btc", 7);
  e[0].peer.life = 1;
  e[0].peer.key = 2;
  e[0].peer.allowed = 1;
  e[1].tag = MESA_SET_ATTACHMENT;
  e[1].peer.id[0] = 2;
  e[1].flag = 1;
  e[1].value = 1;
  const mesa_batch *b = NULL;
  OK(mesa_engine_submit(h, incarnation, e, 2, &budget, &b));
  size_t done, n, byte_count;
  OK(mesa_batch_info(b, &done, &n, &byte_count));
  assert(done == 2);
  mesa_batch_release(b);
  return h;
}
static const mesa_packet *packet(mesa_engine *h, const uint8_t inc[16]) {
  mesa_event e = {0};
  e.tag = MESA_READ;
  e.id = 1;
  e.peer.id[0] = 2;
  uint8_t v = 7;
  e.data = bytes(&v, 1, 4);
  const mesa_batch *b = NULL;
  OK(mesa_engine_submit(h, inc, &e, 1, &budget, &b));
  mesa_buffer_release(e.data);
  size_t done, n, byte_count;
  OK(mesa_batch_info(b, &done, &n, &byte_count));
  const mesa_packet *out = NULL;
  for (size_t i = 0; i < n; i++) {
    mesa_result r = {0};
    OK(mesa_batch_get(b, i, &r));
    assert(!r.status);
    if (r.tag == MESA_SEND)
      OK(mesa_batch_packet(b, i, &out));
    mesa_result_release(&r);
  }
  mesa_batch_release(b);
  assert(out);
  return out;
}
static mesa_udp_endpoint *udp(void) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  assert(fd >= 0);
  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(0x7f000001u);
  assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
  socklen_t len = sizeof(addr);
  assert(getsockname(fd, (struct sockaddr *)&addr, &len) == 0);
  mesa_udp_options o = {1, 2, 1472};
  mesa_udp_endpoint *u = NULL;
  OK(mesa_udp_endpoint_new(fd, &o, &u));
  close(fd);
  mesa_udp_command c = {0};
  c.tag = MESA_UDP_SET_ROUTE;
  c.peer[0] = 2;
  c.generation = 1;
  c.flag = 1;
  c.address.address[0] = 127;
  c.address.address[3] = 1;
  c.address.port = ntohs(addr.sin_port);
  const mesa_batch *b = NULL;
  OK(mesa_udp_endpoint_submit(u, &c, 1, &budget, &b));
  mesa_batch_release(b);
  return u;
}
static void exercise(void) {
  mesa_pki *p = authority();
  mesa_keys *k = NULL;
  OK(mesa_keys_new(&options, NULL, 0, &k));
  uint8_t raw[32];
  memset(raw, 1, 32);
  const mesa_buffer *seed = bytes(raw, 32, 32);
  stage(k, p, seed);
  mesa_buffer_release(seed);
  mesa_key_event es[3] = {event(MESA_KEYS_ADVANCE), event(999),
                          event(MESA_KEYS_ADVANCE)};
  es[0].value = 1;
  es[2].value = 2;
  const mesa_batch *b = NULL;
  OK(mesa_keys_submit(k, p, NULL, es, 3, &budget, &b));
  size_t done, n, byte_count;
  OK(mesa_batch_info(b, &done, &n, &byte_count));
  assert(done == 2);
  mesa_batch_release(b);
  mesa_key_event e = event(MESA_KEYS_PREPARE);
  mesa_budget tiny = {0, 0, 1};
  assert(mesa_keys_submit(k, p, NULL, &e, 1, &tiny, &b) == MESA_CAPACITY && !b);
  mesa_result q = step(k, p, NULL, e, MESA_KEYS_PERSIST, 0);
  const mesa_buffer *keep = mesa_buffer_retain(q.data);
  e = event(MESA_KEYS_COMMIT);
  e.token = q.token;
  step(k, p, NULL, e, 0, 0);
  mesa_result_release(&q);
  uint8_t inc[16];
  mesa_engine *h = engine(inc);
  step(k, p, h, event(MESA_KEYS_SYNC_CORE), 0, 0);
  const mesa_packet *old = packet(h, inc);
  mesa_packet_retain(old);
  mesa_packet_release(old);
  mesa_udp_endpoint *u = udp();
  OK(mesa_udp_endpoint_send_packet(u, old));
  e = event(MESA_KEYS_ROOT);
  uint8_t v = 1;
  e.data = bytes(&v, 1, 4);
  e.value = 32;
  memset(e.root, 6, 32);
  mesa_result req = step(k, p, NULL, e, MESA_KEYS_REQUEST, 0);
  mesa_buffer_release(e.data);
  const mesa_buffer *transcript = mesa_buffer_retain(req.data);
  e = event(MESA_KEYS_EXECUTE);
  e.id = req.id;
  e.generation = req.value;
  memcpy(e.incarnation, req.token.incarnation, 16);
  mesa_result result = step(k, p, NULL, e, MESA_KEYS_COMPLETED, 0);
  assert(width(result.data) == 64);
  mesa_result_release(&result);
  mesa_result_release(&req);
  q = step(k, p, NULL, event(MESA_KEYS_PREPARE), MESA_KEYS_PERSIST, 0);
  assert(mesa_udp_endpoint_send_packet(u, old) == MESA_STALE);
  const mesa_packet *packets[] = {old, old};
  mesa_budget one = {1, 0, 64};
  OK(mesa_udp_endpoint_send_packets(u, packets, 2, &one, &b));
  OK(mesa_batch_info(b, &done, &n, &byte_count));
  assert(done == 1 && n == 1);
  mesa_result r = {0};
  OK(mesa_batch_get(b, 0, &r));
  assert(r.status == MESA_STALE);
  mesa_result_release(&r);
  mesa_batch_release(b);
  mesa_result_release(&q);
  mesa_keys_free(k);
  assert(width(keep) > 0 && width(transcript) > 0);
  mesa_buffer_release(keep);
  mesa_buffer_release(transcript);
  mesa_packet_release(old);
  mesa_udp_endpoint_release(u);
  mesa_engine_release(h);
  mesa_pki_release(p);
}
static void save(int fd, const mesa_buffer *b) {
  size_t n = width(b);
  uint8_t *v = malloc(n);
  assert(v);
  OK(mesa_buffer_copy(b, 0, v, n));
  assert(ftruncate(fd, 0) == 0 && lseek(fd, 0, SEEK_SET) == 0);
  size_t done = 0;
  while (done < n) {
    ssize_t z = write(fd, v + done, n - done);
    assert(z > 0);
    done += (size_t)z;
  }
  assert(fsync(fd) == 0);
  free(v);
}
static const mesa_buffer *load(int fd) {
  off_t n = lseek(fd, 0, SEEK_END);
  assert(n >= 0);
  if (!n)
    return NULL;
  assert(lseek(fd, 0, SEEK_SET) == 0);
  uint8_t *v = malloc((size_t)n);
  assert(v);
  size_t done = 0;
  while (done < (size_t)n) {
    ssize_t z = read(fd, v + done, (size_t)n - done);
    assert(z > 0);
    done += (size_t)z;
  }
  const mesa_buffer *b = bytes(v, (size_t)n, (size_t)n);
  free(v);
  return b;
}
static void crash_case(int at) {
  char keypath[] = "/tmp/mesa-keys-material-XXXXXX",
       path[] = "/tmp/mesa-keys-manifest-XXXXXX";
  int keyfd = mkstemp(keypath), fd = mkstemp(path);
  assert(keyfd >= 0 && fd >= 0);
  pid_t pid = fork();
  assert(pid >= 0);
  if (!pid) {
    mesa_pki *p = authority();
    mesa_keys *k = NULL;
    OK(mesa_keys_new(&options, NULL, 0, &k));
    uint8_t raw[32];
    memset(raw, 1, 32);
    const mesa_buffer *seed = bytes(raw, 32, 32);
    if (at == 0)
      goto kill;
    save(keyfd, seed);
    stage(k, p, seed);
    if (at == 1)
      goto kill;
    mesa_result q =
        step(k, p, NULL, event(MESA_KEYS_PREPARE), MESA_KEYS_PERSIST, 0);
    if (at == 2)
      goto kill;
    save(fd, q.data);
    if (at == 3)
      goto kill;
    mesa_key_event e = event(MESA_KEYS_COMMIT);
    e.token = q.token;
    step(k, p, NULL, e, 0, 0);
    if (at == 4)
      goto kill;
    uint8_t inc[16];
    mesa_engine *h = engine(inc);
    step(k, p, h, event(MESA_KEYS_SYNC_CORE), 0, 0);
    if (at == 5)
      goto kill;
    const mesa_packet *out = packet(h, inc);
    mesa_udp_endpoint *u = udp();
    OK(mesa_udp_endpoint_send_packet(u, out));
  kill:
    raise(SIGKILL);
    _exit(99);
  }
  int status;
  assert(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
         WTERMSIG(status) == SIGKILL);
  const mesa_buffer *saved = load(fd), *seed = load(keyfd);
  close(fd);
  close(keyfd);
  unlink(path);
  unlink(keypath);
  mesa_keys_options o = options;
  o.incarnation[0] = 11;
  mesa_keys *k = NULL;
  OK(mesa_keys_new(&o, saved, at >= 3 ? 1 : 0, &k));
  mesa_pki *p = authority();
  mesa_key_event e = event(MESA_KEYS_ROOT);
  uint8_t v = 1;
  e.data = bytes(&v, 1, 1);
  e.value = 32;
  step(k, p, NULL, e, MESA_EVENT_RESULT, 1);
  mesa_buffer_release(e.data);
  if (seed) {
    stage(k, p, seed);
    mesa_result q =
        step(k, p, NULL, event(MESA_KEYS_PREPARE), MESA_KEYS_PERSIST, 0);
    e = event(MESA_KEYS_COMMIT);
    e.token = q.token;
    step(k, p, NULL, e, 0, 0);
    mesa_result_release(&q);
  }
  if (saved) {
    mesa_keys *bad = NULL;
    assert(mesa_keys_new(&o, saved, 2, &bad) == MESA_STALE && !bad);
    o.host_epoch[0]++;
    assert(mesa_keys_new(&o, saved, 0, &bad) == MESA_STALE && !bad);
  }
  mesa_buffer_release(seed);
  mesa_buffer_release(saved);
  mesa_keys_free(k);
  mesa_pki_release(p);
}

static void identity(uint32_t new_life, uint32_t new_rift) {
  life = new_life;
  rift = new_rift;
  uint8_t seed[32];
  memset(seed, (int)life, 32);
  OK(mesa_key_from_seed(seed, public_key));
}
static void rotation_crash_case(int at) {
  char path[] = "/tmp/mesa-rotate-manifest-XXXXXX",
       keypath[] = "/tmp/mesa-rotate-key-XXXXXX";
  int fd = mkstemp(path), keyfd = mkstemp(keypath);
  assert(fd >= 0 && keyfd >= 0);
  pid_t pid = fork();
  assert(pid >= 0);
  if (!pid) {
    identity(1, 0);
    mesa_pki *p = authority();
    mesa_keys *k = NULL;
    OK(mesa_keys_new(&options, NULL, 0, &k));
    uint8_t raw[32];
    memset(raw, 1, 32);
    const mesa_buffer *seed = bytes(raw, 32, 32);
    save(keyfd, seed);
    stage(k, p, seed);
    mesa_buffer_release(seed);
    mesa_result q =
        step(k, p, NULL, event(MESA_KEYS_PREPARE), MESA_KEYS_PERSIST, 0);
    save(fd, q.data);
    mesa_key_event e = event(MESA_KEYS_COMMIT);
    e.token = q.token;
    step(k, p, NULL, e, 0, 0);
    mesa_result_release(&q);
    uint8_t inc[16];
    mesa_engine *h = engine(inc);
    step(k, p, h, event(MESA_KEYS_SYNC_CORE), 0, 0);
    const mesa_packet *old = packet(h, inc);
    mesa_udp_endpoint *u = udp();
    mesa_pki_release(p);
    identity(2, 1);
    p = authority();
    step(k, p, h, event(MESA_KEYS_RECONCILE), 0, 0);
    assert(mesa_udp_endpoint_send_packet(u, old) == MESA_STALE);
    if (at == 0)
      goto kill;
    memset(raw, 2, 32);
    seed = bytes(raw, 32, 32);
    save(keyfd, seed);
    stage(k, p, seed);
    if (at == 1)
      goto kill;
    q = step(k, p, h, event(MESA_KEYS_PREPARE), MESA_KEYS_PERSIST, 0);
    if (at == 2)
      goto kill;
    save(fd, q.data);
    if (at == 3)
      goto kill;
    e = event(MESA_KEYS_COMMIT);
    e.token = q.token;
    step(k, p, h, e, 0, 0);
    if (at == 4)
      goto kill;
    step(k, p, h, event(MESA_KEYS_SYNC_CORE), 0, 0);
    assert(mesa_udp_endpoint_send_packet(u, old) == MESA_STALE);
    if (at == 5)
      goto kill;
    const mesa_packet *fresh = packet(h, inc);
    OK(mesa_udp_endpoint_send_packet(u, fresh));
  kill:
    raise(SIGKILL);
    _exit(99);
  }
  int status;
  assert(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
         WTERMSIG(status) == SIGKILL);
  const mesa_buffer *saved = load(fd), *seed = load(keyfd);
  assert(saved && seed);
  close(fd);
  close(keyfd);
  unlink(path);
  unlink(keypath);
  identity(2, 1);
  mesa_pki *p = authority();
  mesa_keys_options o = options;
  o.incarnation[0] = 11;
  mesa_keys *k = NULL;
  OK(mesa_keys_new(&o, saved, at >= 3 ? 2 : 1, &k));
  uint8_t inc[16];
  mesa_engine *h = engine(inc);
  step(k, p, h, event(MESA_KEYS_SYNC_CORE), 0, 0);
  const mesa_buffer *view = NULL;
  OK(mesa_engine_snapshot(h, &view));
  size_t n = width(view);
  char *v = calloc(n + 1, 1);
  assert(v);
  OK(mesa_buffer_copy(view, 0, (uint8_t *)v, n));
  assert(strstr(v, "\"quiescent\":true"));
  free(v);
  mesa_buffer_release(view);
  if (at == 0) {
    identity(1, 0);
    stage(k, p, seed);
    step(k, p, h, event(MESA_KEYS_PREPARE), MESA_EVENT_RESULT, 1);
    identity(2, 1);
    uint8_t raw[32];
    memset(raw, 2, 32);
    mesa_buffer_release(seed);
    seed = bytes(raw, 32, 32);
  }
  stage(k, p, seed);
  mesa_result q = step(k, p, h, event(MESA_KEYS_PREPARE), MESA_KEYS_PERSIST, 0);
  mesa_key_event e = event(MESA_KEYS_COMMIT);
  e.token = q.token;
  step(k, p, h, e, 0, 0);
  step(k, p, h, event(MESA_KEYS_SYNC_CORE), 0, 0);
  mesa_udp_endpoint *u = udp();
  const mesa_packet *fresh = packet(h, inc);
  OK(mesa_udp_endpoint_send_packet(u, fresh));
  mesa_packet_release(fresh);
  mesa_udp_endpoint_release(u);
  mesa_result_release(&q);
  mesa_buffer_release(saved);
  mesa_buffer_release(seed);
  mesa_keys_free(k);
  mesa_engine_release(h);
  mesa_pki_release(p);
  identity(1, 0);
}
static void flow_bridge(void) {
  mesa_pki *p = authority();
  mesa_pki_event pe = pevent(MESA_PKI_AUTHORIZED_POINT);
  pe.peer[0] = 2;
  pe.life = 1;
  memcpy(pe.public_key, public_key, 32);
  uint8_t v = 1;
  pe.evidence = bytes(&v, 1, 4);
  mesa_pki_record pp = pstep(p, pe, MESA_PKI_PERSIST);
  mesa_buffer_release(pe.evidence);
  pe = pevent(MESA_PKI_COMMIT);
  pe.token = pp.token;
  pstep(p, pe, 0);
  mesa_pki_record_release(&pp);
  mesa_keys *k = NULL;
  OK(mesa_keys_new(&options, NULL, 0, &k));
  uint8_t raw[32];
  memset(raw, 1, 32);
  const mesa_buffer *seed = bytes(raw, 32, 32);
  stage(k, p, seed);
  mesa_buffer_release(seed);
  mesa_options o;
  OK(mesa_options_default(&o));
  o.kind = MESA_FLOW;
  o.local.id[0] = 1;
  memcpy(o.local.domain, "gw-btc", 7);
  o.local.key = 1;
  o.incarnation[0] = 9;
  memset(o.seed, 1, 32);
  mesa_key key = {0};
  key.handle = 2;
  memcpy(key.public_key, public_key, 32);
  mesa_flow_config f = {0};
  f.flow = 7;
  f.peer.id[0] = 2;
  memcpy(f.peer.domain, "gw-btc", 7);
  f.peer.life = 1;
  f.peer.key = 2;
  f.peer.allowed = 1;
  f.attachment = 1;
  f.attached = 1;
  mesa_engine *h = NULL;
  OK(mesa_engine_create(&o, &key, 1, &f, 1, NULL, &h));
  step(k, p, h, event(MESA_KEYS_PLAN_FLOW), MESA_EVENT_RESULT, 1);
  step(k, p, h, event(MESA_KEYS_QUIESCE_FLOW), 0, 0);
  mesa_result q =
      step(k, p, h, event(MESA_KEYS_PLAN_FLOW), MESA_KEYS_PERSIST, 0);
  mesa_key_event e = event(MESA_KEYS_COMMIT);
  e.token = q.token;
  step(k, p, h, e, 0, 0);
  e = event(MESA_KEYS_SYNC_FLOW);
  e.incarnation[0] = 11;
  step(k, p, h, e, 0, 0);
  mesa_event tick = {0};
  tick.tag = MESA_ADVANCE_TO;
  const mesa_batch *b = NULL;
  assert(mesa_engine_submit(h, o.incarnation, &tick, 1, &budget, &b) ==
             MESA_STALE &&
         !b);
  o.incarnation[0] = 11;
  OK(mesa_engine_submit(h, o.incarnation, &tick, 1, &budget, &b));
  mesa_batch_release(b);
  mesa_result_release(&q);
  mesa_keys_free(k);
  mesa_engine_release(h);
  mesa_pki_release(p);
}
#ifdef MESA_TEST_SUITE_C
/* Public fixture from vectors/crypto/suite-c.json, never a live identity. */
static void ring_codec(void) {
  static const uint8_t ring[] = {
      67,  1,   0,   0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,
      0,   0,   0,   0,   0,   206, 204, 21,  7,   220, 29, 221, 114, 149,
      149, 28,  41,  8,   136, 240, 149, 173, 185, 4,   77, 27,  115, 214,
      150, 230, 223, 6,   93,  104, 59,  212, 252, 128, 17, 240, 157, 221,
      181, 136, 209, 141, 145, 68,  211, 56,  36,  26};
  static const uint8_t name[] = {162, 237, 169, 159, 169, 239, 45,  83,
                                 183, 1,   87,  222, 236, 209, 105, 17};
  mesa_keys_options o = options;
  memcpy(o.peer, name, 16);
  mesa_keys *k = NULL;
  OK(mesa_keys_new(&o, NULL, 0, &k));
  mesa_pki *p = authority();
  const mesa_buffer *description = NULL;
  OK(mesa_keys_view(k, 0, &description));
  mesa_buffer_release(description);
  OK(mesa_keys_view(k, 1, &description));
  mesa_buffer_release(description);
  mesa_key_event e = event(MESA_KEYS_IMPORT_RING);
  memcpy(e.peer, name, 16);
  e.life = 1;
  e.data = bytes(ring, sizeof(ring), sizeof(ring));
  step(k, p, NULL, e, 0, 0);
  e.peer[0] ^= 1;
  step(k, p, NULL, e, MESA_EVENT_RESULT, 1);
  mesa_buffer_release(e.data);
  mesa_keys_free(k);
  mesa_pki_release(p);
}
#endif
int main(void) {
  options.version = 1;
  options.peer[0] = 1;
  memcpy(options.domain, "gw-btc", 7);
  options.incarnation[0] = 10;
  options.host_epoch[0] = 99;
  options.history = 4;
  options.operations = 4;
  options.timeout = 20;
  options.checkpoint_bytes = 1024 * 1024;
  options.max_keys = 8;
  options.max_objects = 8;
  uint8_t seed[32];
  memset(seed, 1, 32);
  OK(mesa_key_from_seed(seed, public_key));
#ifdef MESA_TEST_SUITE_C
  ring_codec();
#endif
  exercise();
  flow_bridge();
  for (int i = 0; i <= 6; i++) {
    crash_case(i);
    rotation_crash_case(i);
  }
  puts("C key activation: ownership, batching, fenced UDP, 14 SIGKILL "
       "bootstrap/rotation boundaries passed");
  return 0;
}
