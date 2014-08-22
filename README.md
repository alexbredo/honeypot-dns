honeypot-dns
============

DNS Honeypot

Features:
 * Diffusor-Mode: Make all requests going to a worldwide random host
 * Konzentrator-Mode: Make all requests going to a specific honeypot
 * Reverse Requests (with generated FQDNs)

Dependencies:
 * Twisted
 * My site-packages(3) --> common-modules

Usage:
```bash
python dns-server.py
```

TODO:
 * implement cache (same answers in multiple requests)
 * do not answer all requests (reality)
 * remove hacky coding
 
Contribution welcome.

All rights reserved.
(c) 2014 by Alexander Bredo