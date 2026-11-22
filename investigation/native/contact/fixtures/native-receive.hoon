/+  default-agent
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def  ~(. (default-agent this %.n) bowl)
++  on-init  on-init:def
++  on-save  on-save:def
++  on-load  on-load:def
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card:agent:gall _this)
  ?:  &((team:title [our src]:bowl) ?=([%send @ *] q.vase))
    =/  [who=@p payload=*]  +.q.vase
    ~&  [%native-submit who payload]
    :_  this
    [%pass /delivery %agent [who %native-receive] %poke %noun !>(payload)]~
  ~&  [%native-delivery our.bowl src.bowl mark q.vase]
  [~ this]
++  on-watch  on-watch:def
++  on-leave  on-leave:def
++  on-peek  on-peek:def
++  on-agent
  |=  [=wire =sign:agent:gall]
  ^-  (quip card:agent:gall _this)
  ~&  [%native-result wire sign]
  [~ this]
++  on-arvo  on-arvo:def
++  on-fail  on-fail:def
--
