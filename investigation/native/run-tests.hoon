=/  m  (strand ,vase)
;<  our=@p  bind:m  get-our
;<  now=@da  bind:m  get-time
;<  =beak  bind:m  get-beak
=/  paths=(list path)
  :~  (en-beam [[our %base da+now] /tests/sys/vane/ames])
      (en-beam [[our %base da+now] /tests/sys/vane/jael])
      (en-beam [[our %base da+now] /tests/sys/vane/mesa])
  ==
;<  tid=@ta  bind:m  (start-thread-with-args beak %test !>(`paths))
(pure:m !>(tid))