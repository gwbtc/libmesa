=/  m  (strand ,vase)
;<  our=@p  bind:m  get-our
;<  now=@da  bind:m  get-time
;<  =beak  bind:m  get-beak
;<  tid=@ta  bind:m
  (start-thread-with-args beak %test !>(`~[(en-beam [[our %base da+now] /tests/native-capture])]))
(pure:m !>(tid))
