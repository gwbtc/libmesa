::  Isolated experimental v2 endpoint, carried over Lick to a loopback UDP bridge.
/+  default-agent, *mesa-v2
|%
+$  card  card:agent:gall
+$  peer-state
  $:  bound=octs
      built=tree
      signature=@
      reading=(unit reader)
      active=?
      configured=?
      epoch=@da
      deadline=@da
  ==
--
=|  peer-state
=*  state  -
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def  ~(. (default-agent this %|) bowl)
    spit
      |=  [mark=@tas data=*]
      ^-  card
      [%pass /mesa %arvo %l %spit /mesa-v2 mark data]
    send
      |=  pak=packet
      (spit %datagram (encode pak))
    request
      ^-  card
      (send [2 1 ?~(reading & |) ?~(reading 0 next.u.reading) 0 1 0 0^0])
    timer
      ^-  card
      [%pass /timer/[(scot %da epoch)] %arvo %b %wait (add now.bowl (div ~s1 4))]
    receive
      |=  bytes=octs
      ^-  (quip card peer-state)
      ?>  configured
      =/  pak  (decode bytes)
      ?:  =(2 tip.pak)
        ?>  =(2 pub.pak)
        ?:  proof.pak
          =/  proof=octs  [(mul 32 (lent proof.built)) (can 3 (turn proof.built |=([h=@] [32 h])))]
          [~[(send [1 2 & 0 p.bound 0 signature proof])] state]
        ?>  (lth index.pak (leaves p.bound))
        =/  off  (mul 1.024 index.pak)
        =/  len  (min 1.024 (sub p.bound off))
        =/  pair  (~(get by pairs.built) index.pak)
        =/  aut  ?~(pair 0 (can 3 ~[[32 -.u.pair] [32 +.u.pair]]))
        [~[(send [1 2 | index.pak p.bound ?~(pair 1 3) aut [len (cut 3 [off len] q.bound)]])] state]
      ?.  active  [~ state]
      ?>  =(1 pub.pak)
      ?:  proof.pak
        ?^  reading  [~ state]
        ?>  =(0 kind.pak)
        =/  r  (open total.pak frag.pak auth.pak)
        [~[(send [2 1 | 0 0 1 0 0^0])] state(reading `r)]
      ?~  reading  [~ state]
      ?.  =(index.pak next.u.reading)  [~ state]
      =/  r  (ingest u.reading pak)
      ?.  =(next.r (leaves total.r))
        [~[(send [2 1 | next.r 0 1 0 0^0])] state(reading `r)]
      [~[(spit %done [total.r bytes.r])] state(active |, reading ~)]
++  on-init
  ^-  (quip card _this)
  :_  this(active |, configured |, reading ~)
  ~[[%pass /mesa %arvo %l %spin /mesa-v2]]
++  on-save  !>(state)
++  on-load
  |=  old=vase
  on-init
++  on-poke  on-poke:def
++  on-watch  on-watch:def
++  on-leave  on-leave:def
++  on-peek  on-peek:def
++  on-agent  on-agent:def
++  on-fail  on-fail:def
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  ?:  ?=([%behn %wake *] sign-arvo)
    ?.  ?&(active =(wire /timer/[(scot %da epoch)]))  [~ this]
    ?:  (gte now.bowl deadline)
      [~[(spit %timeout ~)] this(active |, reading ~)]
    [~[timer request] this]
  ?.  ?=([%lick %soak *] sign-arvo)  [~ this]
  ?:  =(%start mark.sign-arvo)
    =/  len  ;;(@ud noun.sign-arvo)
    ?>  (lte len 65.536)
    =.  bound  (payload 2 len)
    =.  built  (build bound)
    =.  signature  (sign 2 len root.built)
    =.  reading  ~
    =.  active  &
    =.  configured  &
    =.  epoch  now.bowl
    =.  deadline  (add now.bowl ~s20)
    [~[(spit %ready len) request timer] this]
  ?:  =(%cancel mark.sign-arvo)
    [~[(spit %cancelled ~)] this(active |, reading ~)]
  ?:  =(%status mark.sign-arvo)
    [~[(spit %status [active ?~(reading 0 (met 3 bytes.u.reading))])] this]
  ?.  =(%datagram mark.sign-arvo)  [~ this]
  ::  Parsing/authentication failure rolls back the whole event computation.
  =/  result  (mole |.((receive ;;(octs noun.sign-arvo))))
  ?~  result  [~[(spit %rejected ~)] this]
  [-.u.result this(state +.u.result)]
--
