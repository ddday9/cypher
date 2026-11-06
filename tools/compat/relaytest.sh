#!/usr/bin/env bash
# relaytest.sh EXIT_BIN RELAY_BIN CLIENT_BIN MODE   (MODE: a | e2e | hide)
# client → relay → exit with the default relay routing and real runetfreedom
# geo files. Checks TCP+UDP through the exit, and which route domains take.
set -u
D=$(cd "$(dirname "$0")" && pwd)
. "$D/lib.sh"
EXIT=$1 RELAY=$2 CLI=$3 MODE=$4
W=$(mktemp -d)
PE=$((30000 + RANDOM % 5000)) PR=$((30000 + RANDOM % 5000)) SOCKS=$((35000 + RANDOM % 5000)) HTTPP=$((40000 + RANDOM % 5000))
RK=$($EXIT genkey) AK=$($EXIT genkey) PK=$($EXIT genkey)
cat > $W/exit.json <<JSON
{"log":{"level":"debug"},"server":{"listen":"127.0.0.1:$PE","certFile":"$CERT","keyFile":"$CERTKEY","allowPrivate":true,
 "users":[{"name":"relay","key":"$RK"},{"name":"alice","key":"$AK"}]}}
JSON
EXITLINK=$($EXIT user link relay -c $W/exit.json -host localhost 2>/dev/null || echo "cypher://$RK@localhost:$PE")
ALICELINK=$($EXIT user link alice -c $W/exit.json -host localhost 2>/dev/null || echo "")
need_geo
cp "$GEO_DIR/geosite.dat" "$GEO_DIR/geoip.dat" $W/
cat > $W/relay.json <<JSON
{"log":{"level":"debug"},"server":{"listen":"127.0.0.1:$PR","certFile":"$CERT","keyFile":"$CERTKEY","allowPrivate":true,
 "users":[{"name":"phone","key":"$PK"}],
 "upstream":{"link":"$EXITLINK","ca":"$CERT"}},
 "routing":{"geositeURL":"none","geoipURL":"none","rules":[
  {"domain":["geosite:ru-blocked"],"outbound":"exit"},{"ip":["geoip:ru-blocked"],"outbound":"exit"},
  {"domain":["geosite:category-ru","geosite:ru-available-only-inside","domain:ru","domain:xn--p1ai","domain:su"],"outbound":"direct"},
  {"ip":["geoip:ru"],"outbound":"direct"}],"default":"exit"}}
JSON
case $MODE in
  a) LINK=$($RELAY user link phone -c $W/relay.json -host localhost) ;;
  e2e) LINK=$($RELAY user link phone -c $W/relay.json -host localhost -exit "$ALICELINK") ;;
  hide) LINK=$($RELAY user link phone -c $W/relay.json -host localhost -exit "$ALICELINK") ;;
esac
LINK=$(echo "$LINK" | sed 's/#.*//')
if [[ $MODE != a && $LINK != *ek=* ]]; then # exit too old to print epk: e2e with a made-up key
  LINK="$($RELAY user link phone -c $W/relay.json -host localhost | sed 's/#.*//')?ek=$AK&epk=$(python3 -c 'import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))')"
fi
[[ $MODE == hide ]] && LINK="$LINK&hd=1"
# client config from the link
python3 - "$LINK" "$SOCKS" "$CERT" > $W/client.json <<'PY'
import sys, json, urllib.parse as u
l = u.urlparse(sys.argv[1]); q = dict(u.parse_qsl(l.query))
o = {"tag":"proxy","type":"cypher","server":l.netloc.split("@")[1],"key":l.netloc.split("@")[0],"ca":sys.argv[3]}
if "ek" in q: o["exitKey"], o["exitPublicKey"] = q["ek"], q["epk"]
if q.get("hd") == "1": o["hideDestinations"] = True
print(json.dumps({"log":{"level":"debug"},"inbounds":[{"type":"socks","listen":"127.0.0.1:"+sys.argv[2]}],"outbounds":[o]}))
PY
head -c 2000000 /dev/urandom > $W/blob
(cd $W && exec python3 -m http.server $HTTPP --bind 127.0.0.1 >/dev/null 2>&1) & HP=$!
$EXIT run -c $W/exit.json > $W/exit.log 2>&1 & EP=$!
sleep 0.5
$RELAY run -c $W/relay.json > $W/relay.log 2>&1 & RP=$!
sleep 1.5
$CLI run -c $W/client.json > $W/client.log 2>&1 & CP=$!
sleep 1
C="env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy -u NO_PROXY -u no_proxy curl -s -m 20"
ok=1
got=$($C --socks5-hostname 127.0.0.1:$SOCKS http://127.0.0.1:$HTTPP/blob | sha256sum | cut -c1-16)
[[ "$got" == "$(sha256sum $W/blob | cut -c1-16)" ]] && echo "  tcp 2MB: ok" || { echo "  tcp 2MB: FAIL"; ok=0; }
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
u.sendto(b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", echo.getsockname()[1]) + b"hi", relay)
d, _ = u.recvfrom(4096)
sys.exit(0 if d.endswith(b"echo:hi") else 1)
PY
[[ $? -ne 0 ]] && ok=0
# Route checks by domain (no internet needed: only the route decision is logged).
for h in yandex.ru gosuslugi.ru rutracker.org www.instagram.com example.com; do
  $C --socks5-hostname 127.0.0.1:$SOCKS -o /dev/null http://$h/ ; done
sleep 0.5
for h in yandex.ru gosuslugi.ru rutracker.org www.instagram.com example.com; do
  r=$(grep -o "dest=$h:80 route=[a-z]*" $W/relay.log | head -1 | sed 's/.*route=//')
  x=$(grep -c "dest=$h:80" $W/exit.log)
  echo "  $h: relay route=${r:-none(e2e/hidden)} exit-sees=$x"
done
echo "  exit users: $(grep -o 'user=[a-z]*' $W/exit.log | sort | uniq -c | tr '\n' ' ')"
echo "  e2e streams at exit: $(grep -c 'e2e stream user' $W/exit.log)"
kill $CP $RP $EP $HP 2>/dev/null; wait 2>/dev/null
[[ $ok -eq 1 ]] && echo "  PASS" || { echo "  FAIL — logs in $W"; tail -5 $W/client.log; tail -5 $W/relay.log; tail -5 $W/exit.log; }
