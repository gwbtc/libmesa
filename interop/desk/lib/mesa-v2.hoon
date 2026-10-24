::  Experimental v2 fixture endpoint. Public seeds; loopback use only.
::  Exact bytes stay in octs, including terminal zeros. No Ames v1 fallback.
|%
+$  packet
  [tip=@ud pub=@ud proof=? index=@ud total=@ud kind=@ud auth=@ frag=octs]
+$  tree  [root=@ proof=(list @) pairs=(map @ [@ @])]
+$  reader
  [total=@ next=@ hashes=(map @ [end=@ hash=@]) bytes=@]
++  join
  |=  parts=(list octs)
  ^-  octs
  [(roll parts |=([a=octs b=@] (add p.a b))) (can 3 parts)]
++  field
  |=  [off=@ width=@ bytes=octs]
  ?>  (lte (add off width) p.bytes)
  (cut 3 [off width] q.bytes)
++  checksum
  |=  bytes=octs
  =/  seed  0xcafe.babe
  =|  tries=@
  |-
  ?:  =(8 tries)  0x7fff
  =/  hash  (muk seed p.bytes q.bytes)
  =/  folded  (mix (rsh [0 31] hash) (end [0 31] hash))
  ?:  =(0 folded)  $(seed +(seed), tries +(tries))
  (end [0 20] folded)
++  name
  |=  [pub=@ proof=? index=@]
  ?>  ?&(?|(=(1 pub) =(2 pub)) (lth index 64) ?|(!proof =(0 index)))
  (join ~[[1 ?:(proof 32 0)] [1 6] [6 'gw-btc'] [16 pub] [1 0] [1 13] [1 index] [2 13] [13 'example/value']])
++  encode
  |=  pak=packet
  ^-  octs
  =/  nam  (name pub.pak proof.pak index.pak)
  =/  body=octs
    ?:  =(2 tip.pak)  nam
    ?>  =(1 tip.pak)
    ?>  (lte total.pak 65.536)
    ?>  (lte p.frag.pak 1.024)
    =/  tw  ?:(=(0 (rsh [3 1] total.pak)) 1 ?:(=(0 (rsh [3 2] total.pak)) 2 4))
    =/  fw  ?:(=(0 p.frag.pak) 0 ?:(=(0 (rsh [3 1] p.frag.pak)) 1 2))
    =/  aut=octs
      ?+  kind.pak  !!
        %0  [66 (can 3 ~[[2 64] [64 auth.pak]])]
        %1  [0 0]
        %3  [64 auth.pak]
      ==
    =/  meta  (add (dec (met 0 tw)) (add (mul 4 kind.pak) (mul 64 fw)))
    (join ~[nam [1 meta] [tw total.pak] aut [fw p.frag.pak] frag.pak])
  =/  head  (add 32 (add (mul 128 tip.pak) (mul 4.096 (checksum body))))
  (join ~[[4 head] [4 0x67e0.0200] body])
++  decode
  |=  bytes=octs
  ^-  packet
  ?>  ?&((lte 50 p.bytes) (lte p.bytes 1.472) (lte (met 3 q.bytes) p.bytes))
  =/  head  (field 0 4 bytes)
  =/  tip  (cut 0 [7 2] head)
  ?>  ?|(=(1 tip) =(2 tip))
  ?>  =(0x67e0.0200 (field 4 4 bytes))
  ?>  =((add 32 (mul 128 tip)) (end [0 12] head))
  =/  body=octs  [(sub p.bytes 8) (rsh [3 8] q.bytes)]
  ?>  =((checksum body) (rsh [0 12] head))
  =/  meta  (field 0 1 body)
  =/  proof  =(32 meta)
  =/  pub  (field 8 16 body)
  =/  index  (field 26 1 body)
  ?>  =((field 0 42 body) q:(name pub proof index))
  ?:  =(2 tip)
    ?>  =(42 p.body)
    [tip pub proof index 0 1 0 0^0]
  =/  dat  (field 42 1 body)
  =/  tw  (bex (end [0 2] dat))
  =/  kind  (cut 0 [2 2] dat)
  =/  fw  (rsh [0 6] dat)
  ?>  ?&((lte tw 4) (lte fw 2) !=(2 kind))
  =/  total  (field 43 tw body)
  ?>  (lte total 65.536)
  =/  off  (add 43 tw)
  =/  aw  ?:(=(0 kind) 66 ?:(=(3 kind) 64 0))
  =/  auth
    ?:  =(0 kind)
      ?>  =(64 (field off 2 body))
      (field (add off 2) 64 body)
    (field off aw body)
  =.  off  (add off aw)
  =/  len  (field off fw body)
  ?>  (lte len 1.024)
  =.  off  (add off fw)
  ?>  =(p.body (add off len))
  =/  pak=packet  [tip pub proof index total kind auth [len (field off len body)]]
  ?>  =(bytes (encode pak))
  pak
++  context
  |=  [pub=@ total=@ root=@]
  (join ~[[24 'libmesa/v2/public-lss/1'] [1 6] [6 'gw-btc'] [16 pub] [4 0] [4 1] [1 13] [2 13] [13 'example/value'] [8 total] [32 root]])
++  seed
  |=  pub=@
  (rep 3 (reap 32 pub))
++  sign
  |=  [pub=@ total=@ root=@]
  (sign-octs:ed:crypto (context pub total root) (seed pub))
++  verify
  |=  [pub=@ total=@ root=@ sig=@]
  (veri-octs:ed:crypto sig (context pub total root) pub:(luck:ed:crypto (seed pub)))
++  payload
  |=  [pub=@ len=@]
  ^-  octs
  ?>  (lte len 65.536)
  :-  len
  =|  i=@
  =|  acc=(list @)
  |-
  ?:  =(i len)  (rep 3 (flop acc))
  $(i +(i), acc [?:((gte (mod i 29) 24) 0 (mod (add i pub) 251)) acc])
++  parent
  |=  [l=@ r=@]
  (output-cv:blake3:blake:crypto (parent-output:blake3:blake:crypto l r))
++  leaf
  |=  [i=@ bytes=octs]
  ?:  =(0 p.bytes)  (blake3:blake:crypto 32 0^0)
  (output-cv:blake3:blake:crypto (chunk-output:blake3:blake:crypto i bytes))
++  leaves
  |=  total=@
  (max 1 (div (add total 1.023) 1.024))
++  build
  |=  bytes=octs
  ^-  tree
  ?>  (lte p.bytes 65.536)
  =/  start  0
  =/  count  (leaves p.bytes)
  |-  ^-  tree
  ?:  =(1 count)
    =/  off  (mul start 1.024)
    =/  len  (min 1.024 (sub p.bytes off))
    =/  hash  (leaf start [len (cut 3 [off len] q.bytes)])
    [hash ?:(=(0 start) ~[hash] ~) ~]
  =/  width  (bex (dec (met 0 (dec count))))
  =/  left  $(count width)
  =/  right  $(start (add start width), count (sub count width))
  =/  pairs  (~(uni by pairs.left) pairs.right)
  ?:  =(0 start)
    [(parent root.left root.right) (weld proof.left ~[root.right]) pairs]
  [(parent root.left root.right) ~ (~(put by pairs) (sub start width) [root.left root.right])]
++  open
  |=  [total=@ proof=octs sig=@]
  ^-  reader
  ?>  (lte total 65.536)
  =/  count  (leaves total)
  =/  depth  (met 0 (dec count))
  ?>  =(p.proof (mul 32 +(depth)))
  =/  root  (field 0 32 proof)
  =/  hashes  (~(put by *(map @ [end=@ hash=@])) 0 [1 root])
  =/  i  0
  =^  root  hashes
    |-
    ?:  =(i depth)  [root hashes]
    =/  start  (bex i)
    =/  hash  (field (mul 32 +(i)) 32 proof)
    $(i +(i), root (parent root hash), hashes (~(put by hashes) start [(min count (mul 2 start)) hash]))
  ?>  (verify 1 total root sig)
  [total 0 hashes 0]
++  ingest
  |=  [r=reader pak=packet]
  ^-  reader
  ?>  ?&(!proof.pak =(1 pub.pak) =(next.r index.pak) =(total.r total.pak))
  =/  len  (min 1.024 (sub total.r (mul next.r 1.024)))
  ?>  (lte p.frag.pak len)
  =/  want  (~(got by hashes.r) next.r)
  ?>  ?&(=(end.want +(next.r)) =(hash.want (leaf next.r [len q.frag.pak])))
  =/  width
    ?:  =(0 next.r)  0
    =|  n=@
    |-(?:(=(1 (cut 0 [n 1] next.r)) (bex n) $(n +(n))))
  =/  count  (leaves total.r)
  =/  pair  ?&(!=(0 next.r) (lth (add next.r (mul 2 width)) count))
  ?>  =(kind.pak ?:(pair 3 1))
  =/  hashes
    ?.  pair  hashes.r
    =/  start  (add next.r width)
    =/  want  (~(got by hashes.r) start)
    =/  l  (end [3 32] auth.pak)
    =/  rr  (rsh [3 32] auth.pak)
    ?>  ?&(=(end.want (min count (add start (mul 2 width)))) =(hash.want (parent l rr)))
    =/  h  (~(put by hashes.r) start [(add start width) l])
    (~(put by h) (add start width) [end.want rr])
  [total.r +(next.r) (~(del by hashes) next.r) (mix bytes.r (lsh [3 (mul next.r 1.024)] q.frag.pak))]
--
