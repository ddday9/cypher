# Compatibility and behaviour checks with real binaries

Go tests cover one version at a time. These scripts run real `cypher`
binaries of different versions against each other on localhost, which is
how every protocol change is checked before a release ("old clients with
the new server, new clients with old servers"). Linux only; they need
`curl`, `python3`, `openssl`, `bc`.

```bash
./build-old.sh v0.1.0 v0.2.3 v0.4.3      # → .work/bin/cypher-<tag> and cypher-new
B=.work/bin
./compat.sh $B/cypher-new $B/cypher-v0.1.0   # server, client: TCP 3 MB + UDP
./compat.sh $B/cypher-v0.2.3 $B/cypher-new
./idlecompat.sh $B/cypher-new $B/cypher-v0.1.0   # 75 s idle stream + idle tunnel (keepalive)
./freezetest.sh $B/cypher-new $B/cypher-new 16000 ',"antiFreeze":"on","antiFreezeRate":1000'
./relaytest.sh $B/cypher-new $B/cypher-new $B/cypher-new e2e   # exit, relay, client; a | e2e | hide
```

* `compat.sh SERVER CLIENT [extra outbound json]` — the third argument is
  appended to the client's cypher outbound, e.g. `',"singleConnection":true'`.
* `idlecompat.sh` — older versions close a session after 60 s without
  data; this checks that keepalives still satisfy them (takes ~2.5 min).
* `freezetest.sh SERVER CLIENT LIMIT [extra]` — puts `freezer.py` between
  them: it silently stops forwarding a connection after LIMIT bytes, like
  the TSPU's ~16 KB freeze.
* `relaytest.sh EXIT RELAY CLIENT MODE` — a relay with the default relay
  rules and the real runetfreedom lists (downloaded once, ~100 MB); shows
  which route each test domain took.

Logs of each run stay in the temporary directory the script prints.
