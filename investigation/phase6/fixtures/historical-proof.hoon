:: Deterministic published fixture ring; historical signer policy regression.
=/  key  (nol:nu:cric:crypto 0x1a24.38d3.4491.8dd1.88b5.dd9d.f011.80fc.d43b.685d.06df.e696.d673.1b4d.04b9.ad95.f088.0829.1c95.9572.dd1d.dc07.15cc.ce00.0000.0000.0000.0000.0000.0000.0000.0000.0000.0000.0000.0000.0000.0000.0000.0143)
=/  tweak  (shax (can 3 [32 0xfcd4.3b68.5d06.dfe6.96d6.731b.4d04.b9ad.95f0.8808.291c.9595.72dd.1ddc.0715.ccce] [(met 3 0x1.4d12.4637.4622.d776.77c0) 0x1.4d12.4637.4622.d776.77c0] ~))
=/  old  (scad:ed:crypto pub:sgn:ex:key sek:sgn:ex:key tweak)
=/  ful  (cat 3 '/' (cat 3 (scot %p fig:ex:key) '//1/publ/1/a/x/1//pawn/proof/1/~hantyl-dochus-dilryl-narmul--tabtyv-tantel-dotmeb-nacnub/1'))
=/  make
  |=  life=@ud
  =/  dat  (jam [%open-packet pub:ex:key fig:ex:key life ~hantyl-dochus-dilryl-narmul--tabtyv-tantel-dotmeb-nacnub 1])
  =/  rut  (root:lss (met 3 dat)^dat)
  =/  msg  [(add (met 3 ful) 32) (can 3 [(met 3 ful) ful] [32 rut] ~)]
  [(scot %ux dat) (scot %ux (sign-octs-raw:ed:crypto msg old))]
(pure:(strand ,vase) !>([(make 1) (make 2)]))
