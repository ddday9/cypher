#!/usr/bin/env bash
# idlecompat.sh SERVER_BIN CLIENT_BIN [extra json]
# An idle TCP stream through the tunnel must survive 75 s of silence (older
# versions time out sessions after 60 s without data), and a new request
# after that must work.
set -u
D=$(cd "$(dirname "$0")" && pwd)
. "$D/lib.sh"
SRV=$1 CLI=$2 EXTRA=${3:-}
W=$(mktemp -d)
PORT=$((30000 + RANDOM % 5000)) SOCKS=$((35000 + RANDOM % 5000))
KEY=$($SRV genkey)
cat > $W/server.json <<JSON
{"log":{"level":"debug"},"server":{"listen":"127.0.0.1:$PORT","certFile":"$CERT","keyFile":"$CERTKEY","users":[{"name":"u","key":"$KEY"}],"allowPrivate":true}}
JSON
cat > $W/client.json <<JSON
{"log":{"level":"debug"},"inbounds":[{"type":"socks","listen":"127.0.0.1:$SOCKS"}],
 "outbounds":[{"tag":"proxy","type":"cypher","server":"localhost:$PORT","key":"$KEY","ca":"$CERT"$EXTRA}]}
JSON
$SRV run -c $W/server.json > $W/server.log 2>&1 & SP=$!
sleep 0.5
$CLI run -c $W/client.json > $W/client.log 2>&1 & CP=$!
sleep 0.8
python3 - "$SOCKS" <<'PY'
import socket, struct, sys, threading, time
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(8)
def serve():
    while True:
        c, _ = srv.accept()
        def h(c=c):
            while True:
                d = c.recv(100)
                if not d: return
                c.sendall(d)
        threading.Thread(target=h, daemon=True).start()
threading.Thread(target=serve, daemon=True).start()
def conn():
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
    s.sendall(b"\x05\x01\x00"); s.recv(2)
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", srv.getsockname()[1]))
    r = s.recv(10); assert r[1] == 0, r
    return s
s = conn(); s.sendall(b"a"); assert s.recv(1) == b"a"
time.sleep(75)
try:
    s.sendall(b"b"); ok = s.recv(1) == b"b"
except Exception as e:
    ok = False
print("  idle stream after 75 s:", "ok" if ok else "FAIL")
s.close()
time.sleep(75)  # idle tunnel without streams
t = conn(); t.sendall(b"c"); ok2 = t.recv(1) == b"c"
print("  request after 75 s idle tunnel:", "ok" if ok2 else "FAIL")
sys.exit(0 if ok and ok2 else 1)
PY
r=$?
echo "  client connects: $(grep -c 'connected to server\|connected in' $W/client.log), server sessions: $(grep -c 'client connected' $W/server.log)"
kill $CP $SP 2>/dev/null; wait 2>/dev/null
[[ $r -eq 0 ]] && echo "  PASS" || { echo "  FAIL — logs in $W"; }
