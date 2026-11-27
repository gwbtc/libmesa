:: Deterministic disposable fixture identities only. Keep the returned rings
:: under ignored target/ with mode 0600; never use these identities for funds.
=/  a  (pit:nu:cric:crypto 512 (shaz 'libmesa-contact-a') %c q:(mat %mesa-test))
=/  d  (pit:nu:cric:crypto 512 (shaz 'libmesa-phase6-d') %c q:(mat %mesa-test))
(pure:(strand ,vase) !>([[sec:ex:a pub:ex:a fig:ex:a] [sec:ex:d pub:ex:d fig:ex:d]]))
