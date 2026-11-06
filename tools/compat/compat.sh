#!/usr/bin/env bash
# compat.sh SERVER_BIN CLIENT_BIN [extra client outbound json]
# Runs a server and a client of the given versions and pushes TCP (a 3 MB
# download) and UDP through the tunnel. Prints PASS/FAIL.
set -u
D=$(cd "$(dirname "$0")" && pwd)
. "$D/lib.sh"
SRV=$1 CLI=$2 EXTRA=${3:-}
W=$(mktemp -d)
PORT=$((30000 + RANDOM % 5000)) SOCKS=$((35000 + RANDOM % 5000)) HTTPP=$((40000 + RANDOM % 5000))
KEY=$($SRV genkey)
cat > $W/server.json <<JSON
{"log":{"level":"debug"},"server":{"listen":"127.0.0.1:$PORT","certFile":"$CERT","keyFile":"$CERTKEY","users":[{"name":"u","key":"$KEY"}],"allowPrivate":true}}
JSON
cat > $W/client.json <<JSON
{"log":{"level":"debug"},"inbounds":[{"type":"socks","listen":"127.0.0.1:$SOCKS"}],
 "outbounds":[{"tag":"proxy","type":"cypher","server":"localhost:$PORT","key":"$KEY","ca":"$CERT"$EXTRA}]}
JSON
head -c 3000000 /dev/urandom > $W/blob
(cd $W && exec python3 -m http.server $HTTPP --bind 127.0.0.1 >/dev/null 2>&1) & HP=$!
$SRV run -c $W/server.json > $W/server.log 2>&1 & SP=$!
sleep 0.5
$CLI run -c $W/client.json > $W/client.log 2>&1 & CP=$!
sleep 0.8
C="env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy -u NO_PROXY -u no_proxy curl -s -m 20"
ok=1
got=$($C --socks5-hostname 127.0.0.1:$SOCKS http://127.0.0.1:$HTTPP/blob | sha256sum | cut -c1-16)
want=$(sha256sum $W/blob | cut -c1-16)
[[ "$got" == "$want" ]] && echo "  tcp 3MB: ok" || { echo "  tcp 3MB: FAIL"; ok=0; }
python3 - "$SOCKS" <<'PY' && echo "  udp: ok" || { echo "  udp: FAIL"; false; }
import socket, struct, sys, threading
echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); echo.bind(("127.0.0.1", 0))
def serve():
    while True:
        d, a = echo.recvfrom(65535); echo.sendto(b"echo:" + d, a)
threading.Thread(target=serve, daemon=True).start()
ctl = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
ctl.sendall(b"\x05\x01\x00"); ctl.recv(2)
ctl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"); rep = ctl.recv(10)
relay = (socket.inet_ntoa(rep[4:8]), struct.unpack(">H", rep[8:10])[0])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(5)
port = echo.getsockname()[1]
u.sendto(b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", port) + b"hi", relay)
d, _ = u.recvfrom(4096)
sys.exit(0 if d.endswith(b"echo:hi") else 1)
PY
[[ $? -ne 0 ]] && ok=0
echo "  server sees: $(grep -o "client connected.*" $W/server.log | grep -o "protocol=[0-9]" | sort -u | tr "\n" " ")"
kill $CP $SP $HP 2>/dev/null; wait 2>/dev/null
if [[ $ok -eq 1 ]]; then echo "  PASS"; else echo "  FAIL — logs in $W"; tail -5 $W/client.log; tail -5 $W/server.log; fi
