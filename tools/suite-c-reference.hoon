::  Public deterministic test seeds only. Compile after pinned Lull and Zuse.
=/  peer  (luck:ed:crypto 3)
=/  dat  (can 0 ~[(mat %gw-btc) (mat 9) (mat (jam [0 0]))])
=/  xtr  (jam [1 2 3])
=/  msg  (jam [%libmesa-suite-c 1 %rotation])
=/  seeds=(list @)  ~[1 2 0 4 0xffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff]
%+  turn  seeds
|=  seed=@
::  Seed 18 gives a name key with a high zero byte, testing atom hashing.
=/  genesis  pub:(luck:ed:crypto ?:(=(4 seed) 18 1))
=/  ring
  =<  p
  %-  fax:plot
  :-  0
  :*  [s+~ 3 [1 'C'] ~]
      [s+~ 3 [32 seed] ~]
      [s+~ 3 [32 genesis] ~]
      (mat dat)
      [(met 0 xtr)^xtr ~]
  ==
=/  key  (nol:nu:cric:crypto ring)
=/  public  (com:nu:cric:crypto pub:ex:key)
?>  =(ring sec:ex:key)
?>  =(fig:ex:key fig:ex:public)
:~  seed
    genesis
    cry:ded:ex:key
    dat
    xtr
    sec:ex:key
    pub:ex:key
    nam:ex:key
    fig:ex:key
    msg
    (sigh:as:key msg)
    (sign-octs-raw:ed:crypto [(add 1 (met 3 msg)) msg] sgn:ex:key)
    pub.peer
    (slar:ed:crypto pub.peer sek:sgn:ex:key)
    (slar:ed:crypto cry:ded:ex:key sek.peer)
==
