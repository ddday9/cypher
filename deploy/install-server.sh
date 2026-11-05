#!/usr/bin/env bash
# Installs or updates a cypher server on Debian/Ubuntu/RHEL-like systems.
#
#   sudo ./install-server.sh --domain example.com --email you@example.com
#   sudo ./install-server.sh --self-signed            # testing, no domain
#
# Options:
#   --domain NAME     domain pointing at this server; cypher gets and renews the
#                     Let's Encrypt certificate itself (ports 80 and 443 open)
#   --email ADDR      email for Let's Encrypt (optional)
#   --self-signed     use a self-signed certificate (testing only)
#   --binary PATH     cypher binary to install (default: ./cypher-linux-<arch>
#                     next to this script, or ../bin/ in the repository)
#   --port N          listen port (default 443)
#   --site DIR        static website shown to non-clients (default: a placeholder)
#   --add-user NAME   add a user (with a new key) to an existing config
#   --no-nginx        do not install nginx; cypher serves port 80 itself
#   --upstream LINK   relay mode: a cypher:// link of a user on the exit server;
#                     Russian sites leave from here, the rest via the exit
#
# Users later: cypher user add|list|revoke NAME -c /etc/cypher/server.json
# (applied by the running server within seconds, no restart).
set -euo pipefail

DOMAIN="" EMAIL="" SELF_SIGNED=0 BINARY="" PORT=443 SITE_SRC="" ADD_USER="" NO_NGINX=0 UPSTREAM=""
ETC=/etc/cypher
WWW=/var/www/cypher
UNIT=/etc/systemd/system/cypher.service
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --self-signed) SELF_SIGNED=1; shift ;;
    --binary) BINARY="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --site) SITE_SRC="$2"; shift 2 ;;
    --add-user) ADD_USER="$2"; shift 2 ;;
    --no-nginx) NO_NGINX=1; shift ;;
    --upstream) UPSTREAM="$2"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root (sudo)"

# --- binary ---------------------------------------------------------------
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
if [[ -z "$BINARY" ]]; then
  for c in "$HERE/cypher-linux-$ARCH" "$HERE/../bin/cypher-linux-$ARCH" "$HERE/cypher"; do
    [[ -f "$c" ]] && { BINARY="$c"; break; }
  done
fi
if [[ -n "$BINARY" ]]; then
  log "installing $BINARY to /usr/local/bin/cypher"
  install -m 755 "$BINARY" /usr/local/bin/cypher
elif [[ ! -x /usr/local/bin/cypher ]]; then
  die "cypher binary not found; build it with 'make linux' and pass --binary"
fi
/usr/local/bin/cypher version

# --- add a user to an existing install --------------------------------------
if [[ -n "$ADD_USER" ]]; then
  [[ -f $ETC/server.json ]] || die "$ETC/server.json not found; install first"
  /usr/local/bin/cypher user add "$ADD_USER" -c $ETC/server.json
  exit 0
fi

[[ -n "$DOMAIN" || $SELF_SIGNED -eq 1 ]] || die "pass --domain NAME or --self-signed"

# --- system user and directories --------------------------------------------
id cypher >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin cypher
install -d -m 750 -o root -g cypher $ETC
install -d -m 755 $WWW

if [[ -n "$SITE_SRC" ]]; then
  log "copying website from $SITE_SRC"
  cp -a "$SITE_SRC"/. $WWW/
elif [[ ! -e $WWW/index.html ]]; then
  cat > $WWW/index.html <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Notes</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{max-width:40em;margin:3em auto;padding:0 1em;font:16px/1.6 Georgia,serif;color:#222}</style>
</head>
<body>
<h1>Notes</h1>
<p>A small personal page. Nothing much here yet.</p>
</body>
</html>
HTML
fi

# --- nginx: port 80 and the cover website -------------------------------------
# cypher on :443 passes everyone without a key to nginx on 127.0.0.1:8080, and
# nginx on :80 redirects to https and forwards Let's Encrypt checks to cypher.
USE_NGINX=0
if [[ $SELF_SIGNED -eq 0 && $NO_NGINX -eq 0 ]]; then
  if ! command -v nginx >/dev/null; then
    log "installing nginx"
    if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq nginx
    elif command -v dnf >/dev/null; then dnf install -y -q nginx
    fi
  fi
  if command -v nginx >/dev/null; then
    USE_NGINX=1
    rm -f /etc/nginx/sites-enabled/default   # it would take port 80
    cat > /etc/nginx/conf.d/cypher.conf <<'NGINXCONF'
server {
    listen 80 default_server;
    server_name _;
    server_tokens off;
    location /.well-known/acme-challenge/ {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
    }
    location / { return 301 https://$host$request_uri; }
}
server {
    listen 127.0.0.1:8080;
    server_name _;
    server_tokens off;
    root /var/www/cypher;
    index index.html;
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;
    location / { try_files $uri $uri/ =404; }
}
NGINXCONF
    nginx -t && systemctl enable --now nginx >/dev/null && systemctl reload nginx
    if command -v ufw >/dev/null && ufw status | grep -q active; then ufw allow 80/tcp >/dev/null; fi
  else
    log "nginx is not available; cypher serves port 80 and the website itself"
  fi
fi

# --- certificate -------------------------------------------------------------
# With a domain, cypher gets the Let's Encrypt certificate itself and renews it
# automatically (no certbot, no restart). --self-signed is for testing.
if [[ $SELF_SIGNED -eq 1 && ! -f $ETC/cert.pem ]]; then
  NAME="${DOMAIN:-$(hostname -I | awk '{print $1}')}"
  if [[ "$NAME" =~ ^[0-9.]+$ || "$NAME" == *:* ]]; then SAN="IP:$NAME"; else SAN="DNS:$NAME"; fi
  log "creating a self-signed certificate for $NAME"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
    -keyout $ETC/key.pem -out $ETC/cert.pem -subj "/CN=$NAME" -addext "subjectAltName=$SAN" 2>/dev/null
  chown root:cypher $ETC/cert.pem $ETC/key.pem
  chmod 640 $ETC/cert.pem $ETC/key.pem
fi
install -d -m 770 -o root -g cypher $ETC/acme
# Files the server writes itself: geo lists, the end-to-end key.
VAR=/var/lib/cypher
install -d -m 770 -o root -g cypher $VAR

# --- config --------------------------------------------------------------------
NEW_KEY=""
if [[ ! -f $ETC/server.json ]]; then
  NEW_KEY="$(/usr/local/bin/cypher genkey)"
  if [[ $SELF_SIGNED -eq 1 ]]; then
    TLS='"certFile": "'$ETC'/cert.pem", "keyFile": "'$ETC'/key.pem",'
    FALLBACK='{ "dir": "'$WWW'" }'
  elif [[ $USE_NGINX -eq 1 ]]; then
    TLS='"acme": { "domain": "'$DOMAIN'", "email": "'$EMAIL'", "cacheDir": "'$ETC'/acme", "httpListen": "127.0.0.1:8081" },'
    FALLBACK='{ "proxy": "http://127.0.0.1:8080" }'
  else
    TLS='"acme": { "domain": "'$DOMAIN'", "email": "'$EMAIL'", "cacheDir": "'$ETC'/acme", "httpListen": ":80" },'
    FALLBACK='{ "dir": "'$WWW'" }'
  fi
  UPSTREAM_JSON="" ROUTING_JSON=""
  if [[ -n $UPSTREAM ]]; then
    UPSTREAM_JSON='"upstream": { "link": "'$UPSTREAM'" },'
    RU='"domain:ru", "domain:xn--p1ai", "domain:su"'
    ROUTING_JSON=',
  "routing": {
    "geosite": "'$VAR'/geosite.dat", "geoip": "'$VAR'/geoip.dat",
    "geositeURL": "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
    "geoipURL": "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
    "rules": [
      { "domain": ["geosite:ru-blocked"], "outbound": "exit" },
      { "ip": ["geoip:ru-blocked"], "outbound": "exit" },
      { "domain": ["geosite:category-ru", "geosite:ru-available-only-inside", '$RU'], "outbound": "direct" },
      { "ip": ["geoip:ru"], "outbound": "direct" }
    ],
    "default": "exit"
  }'
  fi
  cat > $ETC/server.json <<SERVERJSON
{
  "log": { "level": "info" },
  "server": {
    "listen": ":$PORT",
    $TLS
    $UPSTREAM_JSON
    "users": [ { "name": "user1", "key": "$NEW_KEY" } ],
    "fallback": $FALLBACK,
    "allowPrivate": false,
    "e2eKeyFile": "$VAR/e2e.key"
  }$ROUTING_JSON
}
SERVERJSON
  chown root:cypher $ETC/server.json
  chmod 660 $ETC/server.json
else
  log "keeping existing $ETC/server.json"
fi
/usr/local/bin/cypher check -c $ETC/server.json
# Creates the end-to-end key (readable by the service) for configs that
# predate it.
/usr/local/bin/cypher user list -c $ETC/server.json >/dev/null

# --- service ---------------------------------------------------------------------
if [[ -f "$HERE/cypher.service" ]]; then
  install -m 644 "$HERE/cypher.service" $UNIT
else
  die "cypher.service not found next to this script"
fi
sed -i "s#-c /etc/cypher/server.json#-c $ETC/server.json#" $UNIT
systemctl daemon-reload
systemctl enable --now cypher >/dev/null
systemctl restart cypher
if command -v ufw >/dev/null && ufw status | grep -q active; then ufw allow "$PORT"/tcp >/dev/null; fi
sleep 1
systemctl is-active --quiet cypher || { journalctl -u cypher -n 30 --no-pager; die "service failed to start"; }

# --- summary -------------------------------------------------------------------
HOST="${DOMAIN:-$(hostname -I | awk '{print $1}')}"
log "cypher is running on port $PORT"
if [[ -n "$NEW_KEY" ]]; then
  echo
  echo "Client outbound:"
  cat <<EOF
    {
      "tag": "proxy",
      "type": "cypher",
      "server": "$HOST:$PORT",
      "key": "$NEW_KEY",
      "fingerprint": "firefox"$( [[ $SELF_SIGNED -eq 1 ]] && printf ',\n      "ca": "cert.pem"' )
    }
EOF
  [[ $SELF_SIGNED -eq 1 ]] && echo "Self-signed: copy $ETC/cert.pem to the client as cert.pem."
  if [[ $SELF_SIGNED -eq 0 ]]; then
    echo
    echo "Link for the desktop client (nevio → Servers → paste):"
    /usr/local/bin/cypher user link user1 -c $ETC/server.json
    echo
    echo "The certificate is requested now; watch for 'certificate ready': journalctl -u cypher -f"
  fi
fi
echo
echo "Check it: open https://$HOST:$PORT/ in a browser — you should see the website."
