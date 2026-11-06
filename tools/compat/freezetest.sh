#!/usr/bin/env bash
# freezetest.sh SERVER_BIN CLIENT_BIN LIMIT [extra outbound json]
# Server ← freezer (freeze after LIMIT bytes down) ← client. Downloads files of
# several sizes through the tunnel and reports which arrive intact and how long.
set -u
D=$(cd "$(dirname "$0")" && pwd)
. "$D/lib.sh"
SRV=$1 CLI=$2 LIMIT=$3 EXTRA=${4:-}
W=$(mktemp -d)
PORT=$((30000 + RANDOM % 5000)) FP=$((45000 + RANDOM % 4000)) SOCKS=$((35000 + RANDOM % 5000)) HTTPP=$((40000 + RANDOM % 5000))
KEY=$($SRV genkey)
cat > $W/server.json <<JSON
{"log":{"level":"debug"},"server":{"listen":"127.0.0.1:$PORT","certFile":"$CERT","keyFile":"$CERTKEY","users":[{"name":"u","key":"$KEY"}],"allowPrivate":true}}
JSON
cat > $W/client.json <<JSON
{"log":{"level":"debug"},"inbounds":[{"type":"socks","listen":"127.0.0.1:$SOCKS"}],
 "outbounds":[{"tag":"proxy","type":"cypher","server":"127.0.0.1:$FP","serverName":"localhost","key":"$KEY","ca":"$CERT"$EXTRA}]}
JSON
for size in 4000 50000 1000000; do head -c $size /dev/urandom > $W/f$size; done
(cd $W && exec python3 -m http.server $HTTPP --bind 127.0.0.1 >/dev/null 2>&1) & HP=$!
$SRV run -c $W/server.json > $W/server.log 2>&1 & SP=$!
python3 "$D/freezer.py" $FP 127.0.0.1:$PORT $LIMIT > $W/freezer.log 2>&1 & FZ=$!
sleep 0.5
$CLI run -c $W/client.json > $W/client.log 2>&1 & CP=$!
sleep 0.8
C="env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy -u NO_PROXY -u no_proxy curl -s -m 60"
for size in 4000 4000 50000 1000000 4000; do
  start=$(date +%s.%N)
  got=$($C --socks5-hostname 127.0.0.1:$SOCKS http://127.0.0.1:$HTTPP/f$size | sha256sum | cut -c1-12)
  t=$(echo "$(date +%s.%N) - $start" | bc)
  [[ "$got" == "$(sha256sum $W/f$size | cut -c1-12)" ]] && r=ok || r=FAIL
  printf "  %8d B: %-4s %5.1fs\n" $size $r $t
done
echo "  freezer: $(grep -c frozen $W/freezer.log) frozen connections; client: $(grep -c 'tunnel frozen' $W/client.log) freezes detected, $(grep -c 'connected to server' $W/client.log) tunnels, resumed=$(grep -c 'resumed=true' $W/client.log)"
grep -m3 -E "segmented|anti-freeze" $W/client.log | cut -c30-200
kill $CP $SP $HP $FZ 2>/dev/null; wait 2>/dev/null
echo "  logs: $W"
