/+  default-agent
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def  ~(. (default-agent this %|) bowl)
++  on-init
  :_  this
  :~  [%pass /publish %grow /value noun+[%native-probe 5 0x1234]]
      [%pass /publish %grow /multi noun+[%octs 4.100 (bex 32.768)]]
  ==
++  on-save  on-save:def
++  on-load
  |=  vase
  on-init
++  on-poke  on-poke:def
++  on-watch  on-watch:def
++  on-leave  on-leave:def
++  on-peek
  |=  =path
  ^-  (unit (unit cage))
  ``noun+!>([%native-probe 5 0x1234])
++  on-agent  on-agent:def
++  on-arvo  on-arvo:def
++  on-fail  on-fail:def
--
