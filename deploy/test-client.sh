#!/usr/bin/env bash
# Checks a cypher server from a Linux client host.
#
#   ./test-client.sh --server example.com:443 --key KEY [--ca cert.pem] [--binary ./cypher]
#
# It runs a temporary client, then checks that:
#   1. the server looks like an ordinary website to a browser (no key);
#   2. traffic through the tunnel works and exits from the server's IP;
#   3. UDP (DNS) works through the tunnel.
set -euo pipefail

SERVER="" KEY="" CA="" BINARY=""
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --ca) CA="$(realpath "$2")"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ -n "$SERVER" && -n "$KEY" ]] || { echo "usage: $0 --server HOST:PORT --key KEY [--ca FILE]" >&2; exit 2; }

if [[ -z "$BINARY" ]]; then
  for c in "$HERE/cypher-linux-amd64" "$HERE/../bin/cypher-linux-amd64" "$(command -v cypher || true)"; do
    [[ -n "$c" && -x "$c" ]] && { BINARY="$c"; break; }
  done
fi
[[ -n "$BINARY" ]] || { echo "cypher binary not found; pass --binary" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'kill $PID 2>/dev/null || true; rm -rf "$WORK"' EXIT
SOCKS=127.0.0.1:$((20000 + RANDOM % 20000))
HOST="${SERVER%:*}"

cat > "$WORK/client.json" <<EOF
{
  "log": { "level": "debug" },
  "inbounds": [ { "tag": "socks", "type": "socks", "listen": "$SOCKS" } ],
  "outbounds": [
    { "tag": "proxy", "type": "cypher", "server": "$SERVER", "key": "$KEY"${CA:+, \"ca\": \"$CA\"} }
  ]
}
EOF
"$BINARY" run -c "$WORK/client.json" > "$WORK/client.log" 2>&1 &
PID=$!
sleep 1

pass=0 fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }
# Ignore proxy variables from the environment: we test the direct path and
# our own SOCKS port only. (curl's --noproxy would also disable --socks5.)
CURL=(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy
      -u NO_PROXY -u no_proxy curl -sS --max-time 15)

echo "1. Server as seen by a browser (no key)"
CA_ARGS=(); [[ -n "$CA" ]] && CA_ARGS=(--cacert "$CA")
if out=$("${CURL[@]}" "${CA_ARGS[@]}" -o /dev/null -w '%{http_code} %{http_version}' "https://$SERVER/" 2>&1); then
  ok "https://$SERVER/ answered: HTTP $out"
else
  bad "website not reachable: $out"
fi

echo "2. TCP through the tunnel"
if trace=$("${CURL[@]}" --socks5-hostname "$SOCKS" https://cloudflare.com/cdn-cgi/trace 2>&1); then
  exit_ip=$(sed -n 's/^ip=//p' <<<"$trace")
  ok "request succeeded, exit IP $exit_ip"
  server_ips=$(getent ahosts "$HOST" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')
  if [[ -n "$server_ips" && " $server_ips " == *" $exit_ip "* ]]; then
    ok "exit IP belongs to the server ($HOST)"
  else
    echo "  NOTE  exit IP $exit_ip; server resolves to: ${server_ips:-?} (may differ if the server has several IPs)"
  fi
else
  bad "tunnel request failed: $trace"
fi

echo "3. UDP through the tunnel (DNS query to 1.1.1.1)"
if command -v python3 >/dev/null; then
  if python3 - "$SOCKS" <<'PY'
import socket, struct, sys
host, port = sys.argv[1].rsplit(":", 1)
ctl = socket.create_connection((host, int(port)), timeout=10)
ctl.sendall(b"\x05\x01\x00"); ctl.recv(2)
ctl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
rep = ctl.recv(10)
assert rep[1] == 0, f"associate failed: {rep!r}"
relay = (socket.inet_ntoa(rep[4:8]), struct.unpack(">H", rep[8:10])[0])
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07example\x03com\x00" + b"\x00\x01\x00\x01"
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(10)
u.sendto(b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack(">H", 53) + q, relay)
data, _ = u.recvfrom(4096)
assert data[10:12] == b"\x12\x34", "bad DNS reply"
PY
  then ok "DNS reply received over UDP"; else bad "UDP did not work"; fi
else
  echo "  SKIP  python3 not installed"
fi

echo
echo "passed: $pass, failed: $fail"
if [[ $fail -gt 0 ]]; then
  echo "--- client log ---"; tail -n 30 "$WORK/client.log"
  exit 1
fi
