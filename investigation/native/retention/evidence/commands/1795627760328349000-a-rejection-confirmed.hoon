=/  m  (strand ,vase)
;<  our=@p  bind:m  get-our
;<  now=@da  bind:m  get-time
=/  st  .^([count=@ud results=(list noun) seen=(list noun)] %gx (en-beam [[our %crash-probe da+now] /state/noun]))
(pure:m !>([(lent results.st) ?~(results.st %.n ?=([* %poke-ack ^] i.results.st))]))