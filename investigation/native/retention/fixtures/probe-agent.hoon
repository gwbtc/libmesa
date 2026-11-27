/+  default-agent
|%
+$  probe-state  [count=@ud results=(list noun) seen=(list noun)]
--
=|  state=probe-state
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def  ~(. (default-agent this %.n) bowl)
++  on-init  [~ this]
++  on-save  !>(state)
++  on-load
  |=  old=vase
  [~ this(state !<(probe-state old))]
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card:agent:gall _this)
  ?:  &((team:title [our src]:bowl) ?=([%send @ *] q.vase))
    =/  [who=@p payload=*]  +.q.vase
    :_  this
    [%pass /probe %agent [who %crash-probe] %poke %noun !>(payload)]~
  ?:  &((team:title [our src]:bowl) ?=([%watch @] q.vase))
    =/  who=@p  +.q.vase
    :_  this
    [%pass /watch %agent [who %crash-probe] %watch /results]~
  ?:  &((team:title [our src]:bowl) ?=([%leave @] q.vase))
    =/  who=@p  +.q.vase
    :_  this
    [%pass /watch %agent [who %crash-probe] %leave ~]~
  ?:  ?=([%reject *] q.vase)
    ~|  [%probe-rejected +.q.vase]
    !!
  [~ this(count.state +(count.state), seen.state [[src.bowl q.vase] seen.state])]
++  on-watch
  |=  =path
  ^-  (quip card:agent:gall _this)
  :_  this(count.state +(count.state), seen.state [[%watch path] seen.state])
  [%give %fact ~[path] %noun !>([%probe-boon 200])]~
++  on-leave  on-leave:def
++  on-peek
  |=  =path
  ^-  (unit (unit cage))
  ``noun+!>(state)
++  on-agent
  |=  [=wire =sign:agent:gall]
  ^-  (quip card:agent:gall _this)
  [~ this(results.state [[wire sign] results.state])]
++  on-arvo  on-arvo:def
++  on-fail  on-fail:def
--
