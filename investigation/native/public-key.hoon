=/  m  (strand ,vase)
;<  our=@p  bind:m  get-our
;<  now=@da  bind:m  get-time
=/  deed  .^([@ud =pass (unit @)] %j /(scot %p our)/deed/(scot %da now)/(scot %p our)/1)
=/  cic  (com:nu:cric:crypto pass.deed)
=/  keys=public-keys:ames  ded:ex:cic
(pure:m !>(`@ux`sgn.keys))
