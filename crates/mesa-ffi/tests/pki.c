#define _POSIX_C_SOURCE 200809L
#include "mesa_pki.h"
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#define OK(x) do { int rc_=(x); if(rc_){fprintf(stderr,"%s:%d: %s => %d\n",__FILE__,__LINE__,#x,rc_);abort();} } while(0)
static size_t width(const mesa_buffer *b){const uint8_t *dat;size_t len,wid;OK(mesa_buffer_dat(b,&dat,&len,&wid));return wid;}
static const mesa_budget budget={16385,64*1024*1024,64};
static mesa_pki_options options;
static mesa_pki_ticket provider;
static mesa_pki_record run(mesa_pki *h,mesa_pki_event e,uint32_t wanted){
  const mesa_pki_batch *batch=NULL;OK(mesa_pki_step(h,&e,1,&budget,&batch));
  size_t processed,count;OK(mesa_pki_batch_info(batch,&processed,&count));assert(processed==1);
  mesa_pki_record found={0};
  for(size_t i=0;i<count;i++){mesa_pki_record r={0};OK(mesa_pki_batch_get(batch,i,&r));
    assert(r.tag!=MESA_PKI_ERROR || wanted==MESA_PKI_ERROR);
    if(r.tag==wanted){mesa_pki_record_release(&found);found=r;}else mesa_pki_record_release(&r);
  }
  mesa_pki_batch_release(batch);if(wanted)assert(found.tag==wanted);return found;
}
static mesa_pki_event event(uint32_t tag){mesa_pki_event e={0};e.tag=tag;memcpy(e.domain,"gw-btc",7);e.peer[0]=2;e.peer[15]=128;e.ticket=provider;return e;}
static void commit(mesa_pki *h,mesa_pki_record *p){mesa_pki_event e=event(MESA_PKI_COMMIT);e.token=p->token;run(h,e,0);}
static mesa_pki *setup(uint32_t kind,uint8_t incarnation){
  options.incarnation[0]=incarnation;memset(&provider,0,sizeof(provider));provider.incarnation[0]=incarnation;provider.generation=1;
  mesa_pki *h=NULL;OK(mesa_pki_create(kind,&options,NULL,&h));
  mesa_pki_event e=event(MESA_PKI_REGISTER);e.value=1;mesa_pki_record p=run(h,e,MESA_PKI_PERSIST);commit(h,&p);mesa_pki_record_release(&p);
  e=event(MESA_PKI_STATUS);e.flags=3;run(h,e,0);return h;
}
static const mesa_buffer *evidence(void){const uint8_t bytes[]={1,2};const mesa_buffer *b=NULL;OK(mesa_buffer_new(bytes,2,4,&b));return b;}
static mesa_pki_event candidate(uint32_t tag){mesa_pki_event e=event(tag);e.life=1;e.evidence=evidence();uint8_t seed[32];memset(seed,2,32);OK(mesa_key_from_seed(seed,e.public_key));return e;}
static mesa_pki_record propose(mesa_pki *h,uint32_t kind){
  mesa_pki_event e=candidate(kind==MESA_PKI_RAW?MESA_PKI_AUTHORIZED_POINT:MESA_PKI_PROFILE_CANDIDATE);
  mesa_pki_record r=run(h,e,kind==MESA_PKI_RAW?MESA_PKI_PERSIST:MESA_PKI_VERIFY);mesa_buffer_release(e.evidence);
  if(kind==MESA_PKI_RAW)return r;
  /* Retaining evidence survives record, batch and admission-handle lifetimes. */
  const mesa_buffer *keep=mesa_buffer_retain(r.data);mesa_pki_ticket t=r.ticket;mesa_pki_record_release(&r);
  uint8_t bytes[4]={0};OK(mesa_buffer_copy(keep,0,bytes,4));assert(bytes[0]==1&&bytes[1]==2&&bytes[2]==0&&bytes[3]==0);mesa_buffer_release(keep);
  e=event(MESA_PKI_COMPLETE);e.ticket=t;e.value=0;return run(h,e,MESA_PKI_PERSIST);
}
static char *snapshot(mesa_pki *h){const mesa_buffer *b=NULL;OK(mesa_pki_snapshot(h,&b));size_t n=width(b);char *s=calloc(n+1,1);assert(s);OK(mesa_buffer_copy(b,0,(uint8_t*)s,n));mesa_buffer_release(b);return s;}
static void allowed(mesa_pki *h,int expected){char *s=snapshot(h);assert(strstr(s,expected?"\"ordinary\":true":"\"ordinary\":false"));free(s);}
static void exercise(uint32_t kind){
  mesa_pki *h=setup(kind,(uint8_t)kind);
  const mesa_buffer *description=NULL;OK(mesa_pki_describe(h,&description));
  mesa_pki_event batch_events[3]={event(MESA_PKI_STATUS),event(999),event(MESA_PKI_STATUS)};
  batch_events[0].flags=3;batch_events[2].flags=3;
  const mesa_pki_batch *prefix=NULL;OK(mesa_pki_step(h,batch_events,3,&budget,&prefix));
  size_t consumed,nrecords;OK(mesa_pki_batch_info(prefix,&consumed,&nrecords));assert(consumed==2);
  mesa_pki_record failure={0};OK(mesa_pki_batch_get(prefix,nrecords-1,&failure));
  assert(failure.tag==MESA_PKI_ERROR&&failure.event_index==1);mesa_pki_record_release(&failure);mesa_pki_batch_release(prefix);
  mesa_pki_record p=propose(h,kind);allowed(h,0);
  /* Too-small budget must not confirm a proposal or mutate the handle. */
  mesa_pki_event e=event(MESA_PKI_COMMIT);e.token=p.token;const mesa_budget tiny={0,0,1};const mesa_pki_batch *batch=NULL;
  assert(mesa_pki_step(h,&e,1,&tiny,&batch)==MESA_CAPACITY);assert(!batch);allowed(h,0);
  commit(h,&p);allowed(h,1);
  mesa_options eo;OK(mesa_options_default(&eo));eo.local.id[0]=1;memcpy(eo.local.domain,"gw-btc",7);eo.local.key=1;eo.incarnation[0]=9;memset(eo.seed,1,32);
  mesa_engine *engine=NULL;OK(mesa_engine_create(&eo,NULL,0,NULL,0,NULL,&engine));const mesa_batch *out=NULL;uint8_t peer[16]={2};peer[15]=128;
  OK(mesa_pki_sync_core(h,engine,peer,&budget,&out));mesa_batch_release(out);
  const mesa_buffer *view=NULL;OK(mesa_engine_snapshot(engine,&view));size_t n=width(view);char *s=calloc(n+1,1);assert(s);OK(mesa_buffer_copy(view,0,(uint8_t*)s,n));assert(strstr(s,"\"allowed\":true"));free(s);mesa_buffer_release(view);
  e=event(MESA_PKI_WITHDRAW);e.expected=p.token.revision;mesa_pki_record w=run(h,e,MESA_PKI_PERSIST);allowed(h,0);
  OK(mesa_pki_sync_core(h,engine,peer,&budget,&out));mesa_batch_release(out);
  e=event(MESA_PKI_COMMIT);e.token=p.token;mesa_pki_record error=run(h,e,MESA_PKI_ERROR);assert(error.status==MESA_STALE);mesa_pki_record_release(&error);
  commit(h,&w);const mesa_buffer *checkpoint=mesa_buffer_retain(w.data);
  mesa_pki_record_release(&p);mesa_pki_record_release(&w);mesa_pki_release(h);mesa_engine_release(engine);
  assert(width(description)>0);mesa_buffer_release(description);
  options.incarnation[0]=99;OK(mesa_pki_create(kind,&options,checkpoint,&h));allowed(h,0);mesa_buffer_release(checkpoint);mesa_pki_release(h);
}
static void lookup(void){
  mesa_pki *h=setup(MESA_PKI_JAEL,55);mesa_pki_event e=event(MESA_PKI_RESOLVE_PEER);
  mesa_pki_record query=run(h,e,MESA_PKI_LOOKUP);e=candidate(MESA_PKI_RESOLVED);e.ticket=query.ticket;
  mesa_pki_record p=run(h,e,MESA_PKI_PERSIST);mesa_buffer_release(e.evidence);commit(h,&p);allowed(h,1);
  mesa_pki_record_release(&query);mesa_pki_record_release(&p);mesa_pki_release(h);
}
static void save(int fd,const mesa_buffer *b){size_t n=width(b);uint8_t *p=malloc(n);assert(p);OK(mesa_buffer_copy(b,0,p,n));
  assert(lseek(fd,0,SEEK_SET)==0);assert(ftruncate(fd,0)==0);size_t done=0;while(done<n){ssize_t k=write(fd,p+done,n-done);assert(k>0);done+=(size_t)k;}assert(fsync(fd)==0);free(p);
}
static void crash_case(int stage){
  char path[]="/tmp/mesa-pki-crash-XXXXXX";int fd=mkstemp(path);assert(fd>=0);
  pid_t pid=fork();assert(pid>=0);
  if(!pid){mesa_pki *h=setup(MESA_PKI_JAEL,10);mesa_pki_record p=propose(h,MESA_PKI_JAEL);
    if(stage==0){/* no committed peer: persist the registration from a separate fresh handle */
      mesa_pki *fresh=NULL;OK(mesa_pki_create(MESA_PKI_JAEL,&options,NULL,&fresh));mesa_pki_event e=event(MESA_PKI_REGISTER);e.value=1;mesa_pki_record r=run(fresh,e,MESA_PKI_PERSIST);save(fd,r.data);
    }else{save(fd,p.data);if(stage>=2)commit(h,&p);if(stage>=3){mesa_pki_event e=event(MESA_PKI_WITHDRAW);e.expected=p.token.revision;mesa_pki_record w=run(h,e,MESA_PKI_PERSIST);if(stage>=4)save(fd,w.data);}}
    raise(SIGKILL);_exit(90);
  }
  int status;assert(waitpid(pid,&status,0)==pid);assert(WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);
  off_t n=lseek(fd,0,SEEK_END);assert(n>0);assert(lseek(fd,0,SEEK_SET)==0);uint8_t *bytes=malloc((size_t)n);assert(bytes);
  size_t done=0;while(done<(size_t)n){ssize_t k=read(fd,bytes+done,(size_t)n-done);assert(k>0);done+=(size_t)k;}close(fd);unlink(path);
  const mesa_buffer *checkpoint=NULL;OK(mesa_buffer_new(bytes,(size_t)n,(size_t)n,&checkpoint));free(bytes);
  options.incarnation[0]=11;mesa_pki *h=NULL;OK(mesa_pki_create(MESA_PKI_JAEL,&options,checkpoint,&h));mesa_buffer_release(checkpoint);
  memset(&provider,0,sizeof(provider));provider.incarnation[0]=11;provider.generation=1;mesa_pki_event e=event(MESA_PKI_STATUS);e.flags=3;run(h,e,0);
  char *s=snapshot(h);assert(!strstr(s,"\"ordinary\":true"));free(s);mesa_pki_release(h);
}
int main(void){OK(mesa_pki_options_default(&options));exercise(MESA_PKI_RAW);exercise(MESA_PKI_JAEL);lookup();
  for(int stage=0;stage<5;stage++)crash_case(stage);
  puts("PKI C ownership, batching, bridge and five SIGKILL recovery boundaries passed");return 0;
}
