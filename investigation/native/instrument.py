from pathlib import Path
import re
import argparse
p=argparse.ArgumentParser()
p.add_argument('--urbit-source',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
out=a.output
out.mkdir(parents=True,exist_ok=True)
src=(a.urbit_source/'tests/sys/vane/ames.hoon').read_text()
helper='''++  trace-moves
  |=  [who=ship moves=(list move:ames)]
  ^-  (list move:ames)
  =/  todo  moves
  |-
  ?~  todo  moves
  =/  item  i.todo
  ?:  (is-move-send item)
    =/  blob  +:(move-to-packet item)
    ~&  [%native-packet who %send (met 3 blob) `@ux`blob]
    $(todo t.todo)
  ?:  (is-move-push item)
    =/  blob  +:(move-to-push item)
    ~&  [%native-packet who %push (met 3 blob) `@ux`blob]
    $(todo t.todo)
  $(todo t.todo)
::
'''
src=src.replace('++  call\n',helper+'++  call\n',1)
for kind,args in [('call','duct ~ task'),('take','wire duct ~ sign')]:
 old=f'  ({kind}:vane-core {args})'
 new=f'  =/  result  ({kind}:vane-core {args})\n  [(trace-moves our.vane -.result) +.result]'
 assert src.count(old)==1
 src=src.replace(old,new)
src=re.sub(r'^(\+\+  (test-[\w-]+)[^\n]*)\n',lambda m:m[1]+'\n  ~&  [%native-case %'+m[2]+']\n',src,flags=re.M)
extra='''++  test-native-crypto-capture  ^-  tang
  ~&  [%native-case %native-crypto]
  =/  key  `@uxI`(derive-symmetric-key:ames pub.saf.ames-state.cd sek.saf.ames-state.cc)
  =/  path  /g/x/0/native-probe//value/noun
  =/  sealed  (seal-path:crypt:ames key path)
  =/  value  (jam [%octs 5 0x1234])
  =/  cipher  (encrypt:crypt:ames key sealed value)
  =/  root  (root:lss:ames (met 3 cipher)^cipher)
  =/  tag  (mac:crypt:ames key path root)
  ~&  [%native-crypto `@ux`key path `@ux`sealed `@ux`value `@ux`cipher `@ux`root `@ux`tag]
  ;:  weld
    (expect-eq !>(path) !>((open-path:crypt:ames key sealed)))
    (expect-eq !>(value) !>((decrypt:crypt:ames key sealed cipher)))
  ==
++  test-native-proof-capture  ^-  tang
  ~&  [%native-case %native-proof-capture]
  =/  one  cc-proof-push
  =/  two  cc-life2-proof-push
  =/  pok  cc-life2-proof-poke
  ~&  [%native-packet cc-comet %proof-life1 (met 3 +.one) `@ux`+.one]
  ~&  [%native-packet cc-comet %proof-life2 (met 3 +.two) `@ux`+.two]
  ~&  [%native-packet cc-comet %proof-poke (met 3 +.pok) `@ux`+.pok]
  ~
++  test-native-udp-peek-capture  ^-  tang
  ~&  [%native-case %native-udp-peek]
  =/  pak=pact:pact:ames
    [0 %peek [[~zod 0] [13 ~] /publ/1/g/x/0/native-probe//value/noun]]
  =/  blob  (pact-to-blob pak)
  ~&  [%native-packet ~zod %udp-peek (met 3 blob) `@ux`blob]
  ~
'''
pos=src.rfind('\n--')
src=src[:pos]+'\n'+extra+src[pos:]
(out/'native-capture.hoon').write_text(src)
