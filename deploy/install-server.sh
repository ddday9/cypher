#!/usr/bin/env bash
# Installs or updates a cypher server on Debian/Ubuntu/RHEL-like systems.
#
#   sudo ./install-server.sh --domain example.com --email you@example.com
#   sudo ./install-server.sh --self-signed            # testing, no domain
#
# Options:
#   --domain NAME     domain pointing at this server (gets a Let's Encrypt cert)
#   --email ADDR      email for Let's Encrypt (optional)
#   --self-signed     use a self-signed certificate (testing only)
#   --binary PATH     cypher binary to install (default: ./cypher-linux-<arch>
#                     next to this script, or ../bin/ in the repository)
#   --port N          listen port (default 443)
#   --site DIR        static website shown to non-clients (default: a placeholder)
#   --add-user NAME   add a user (with a new key) to an existing config
set -euo pipefail

DOMAIN="" EMAIL="" SELF_SIGNED=0 BINARY="" PORT=443 SITE_SRC="" ADD_USER=""
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
  command -v python3 >/dev/null || die "python3 is required for --add-user"
  KEY="$(/usr/local/bin/cypher genkey)"
  python3 - "$ETC/server.json" "$ADD_USER" "$KEY" <<'PY'
import json, sys
path, name, key = sys.argv[1:]
cfg = json.load(open(path))
users = cfg["server"].setdefault("users", [])
if any(u.get("name") == name for u in users):
    sys.exit(f"user {name} already exists")
users.append({"name": name, "key": key})
json.dump(cfg, open(path, "w"), indent=2)
PY
  systemctl restart cypher
  log "user $ADD_USER added; key: $KEY"
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

# --- certificate -------------------------------------------------------------
if [[ $SELF_SIGNED -eq 1 ]]; then
  if [[ ! -f $ETC/cert.pem ]]; then
    NAME="${DOMAIN:-$(hostname -I | awk '{print $1}')}"
    if [[ "$NAME" =~ ^[0-9.]+$ || "$NAME" == *:* ]]; then SAN="IP:$NAME"; else SAN="DNS:$NAME"; fi
    log "creating a self-signed certificate for $NAME"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
      -keyout $ETC/key.pem -out $ETC/cert.pem -subj "/CN=$NAME" -addext "subjectAltName=$SAN" 2>/dev/null
  fi
else
  if ! command -v certbot >/dev/null; then
    log "installing certbot"
    if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq certbot
    elif command -v dnf >/dev/null; then dnf install -y -q certbot
    else die "install certbot manually"; fi
  fi
  # Copy renewed certificates where the cypher user can read them. The server
  # notices the new files by itself; no restart is needed.
  install -d /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/cypher.sh <<EOF
#!/bin/sh
[ "\$RENEWED_LINEAGE" = "/etc/letsencrypt/live/$DOMAIN" ] || exit 0
install -m 640 -o root -g cypher "\$RENEWED_LINEAGE/fullchain.pem" $ETC/cert.pem
install -m 640 -o root -g cypher "\$RENEWED_LINEAGE/privkey.pem" $ETC/key.pem
EOF
  chmod 755 /etc/letsencrypt/renewal-hooks/deploy/cypher.sh
  if [[ ! -d /etc/letsencrypt/live/$DOMAIN ]]; then
    systemctl stop cypher 2>/dev/null || true
    log "requesting a certificate for $DOMAIN (port 80 must be reachable)"
    if command -v ufw >/dev/null && ufw status | grep -q active; then ufw allow 80/tcp >/dev/null; fi
    certbot certonly --standalone --non-interactive --agree-tos \
      ${EMAIL:+--email "$EMAIL"} ${EMAIL:---register-unsafely-without-email} -d "$DOMAIN"
  fi
  RENEWED_LINEAGE=/etc/letsencrypt/live/$DOMAIN /etc/letsencrypt/renewal-hooks/deploy/cypher.sh
fi
chown root:cypher $ETC/cert.pem $ETC/key.pem
chmod 640 $ETC/cert.pem $ETC/key.pem

# --- config --------------------------------------------------------------------
NEW_KEY=""
if [[ ! -f $ETC/server.json ]]; then
  NEW_KEY="$(/usr/local/bin/cypher genkey)"
  cat > $ETC/server.json <<EOF
{
  "log": { "level": "info" },
  "server": {
    "listen": ":$PORT",
    "certFile": "$ETC/cert.pem",
    "keyFile": "$ETC/key.pem",
    "users": [ { "name": "user1", "key": "$NEW_KEY" } ],
    "fallback": { "dir": "$WWW" },
    "allowPrivate": false
  }
}
EOF
  chown root:cypher $ETC/server.json
  chmod 640 $ETC/server.json
else
  log "keeping existing $ETC/server.json"
fi
/usr/local/bin/cypher check -c $ETC/server.json

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
      "fingerprint": "chrome"$( [[ $SELF_SIGNED -eq 1 ]] && printf ',\n      "ca": "cert.pem"' )
    }
EOF
  [[ $SELF_SIGNED -eq 1 ]] && echo "Self-signed: copy $ETC/cert.pem to the client as cert.pem."
fi
echo
echo "Check it: open https://$HOST:$PORT/ in a browser — you should see the website."
