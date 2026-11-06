# Shared setup for the compatibility scripts (sourced, not run).
# Everything generated lives in tools/compat/.work (ignored by git).
WORK="$D/.work"
mkdir -p "$WORK"
CERT="$WORK/cert.pem" CERTKEY="$WORK/key.pem"
if [ ! -s "$CERT" ]; then
  # A self-signed certificate for localhost; clients get it as "ca".
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout "$CERTKEY" -out "$CERT" >/dev/null 2>&1
fi
GEO_DIR="$WORK/geo"
need_geo() { # relaytest.sh: the real runetfreedom lists
  mkdir -p "$GEO_DIR"
  for f in geosite.dat geoip.dat; do
    [ -s "$GEO_DIR/$f" ] || curl -sSLf -o "$GEO_DIR/$f" \
      "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/$f"
  done
}
