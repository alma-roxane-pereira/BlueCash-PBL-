#!/usr/bin/env bash
#
# Start the BlueCash mint for development on whatever network the laptop is on now.
#
# The laptop's address changes every time it joins a different Wi-Fi network or phone
# hotspot, and the phones hold that address in their own settings. This finds the current
# IPv4 address, prints the exact URL to type into the app, and serves on 0.0.0.0.
#
# It refuses to start without BLUECASH_DATABASE_URL. The mint's identity and denomination
# keys live in the database, and clients pin the mint's public key on first contact, so
# starting against the wrong file silently creates a *different mint* and orphans every
# wallet that has already registered.
#
#   BLUECASH_DATABASE_URL="sqlite:///C:/path/to/ble-mint.db" ./dev-server.sh
#   ./dev-server.sh --show-only          # print the address and URL, start nothing
#
set -euo pipefail

PORT="${PORT:-8000}"
SHOW_ONLY=0
[ "${1:-}" = "--show-only" ] && SHOW_ONLY=1

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- the database must be chosen deliberately -------------------------------------------
if [ -z "${BLUECASH_DATABASE_URL:-}" ]; then
    cat >&2 <<'EOF'

  BLUECASH_DATABASE_URL is not set.

  Refusing to start. Without it the server would create a fresh database, which means a
  new mint identity -- every wallet that already registered pins the old key and would
  refuse this one.

  Set it to the database you mean to serve, for example:
    export BLUECASH_DATABASE_URL="sqlite:///C:/full/path/to/ble-mint.db"

EOF
    exit 1
fi

db_path=""
is_new=0
case "$BLUECASH_DATABASE_URL" in
    sqlite:///*)
        db_path="${BLUECASH_DATABASE_URL#sqlite:///}"
        [ -f "$db_path" ] || is_new=1
        ;;
esac

# --- find the address the phones should use ---------------------------------------------
# Windows (Git Bash) has no `ip` or `hostname -I`, so ipconfig is the portable source here.
addresses="$(
    { ipconfig 2>/dev/null || true; } \
        | tr -d '\r' \
        | grep -iE "IPv4 Address" \
        | sed 's/.*: //' \
        | grep -vE '^(127\.|169\.254\.)' || true
)"

if [ -z "$addresses" ]; then
    # Fall back to the usual Unix sources, so the script also works off Windows.
    addresses="$(
        { hostname -I 2>/dev/null || true; } | tr ' ' '\n' \
            | grep -E '^[0-9]+\.' | grep -vE '^(127\.|169\.254\.)' || true
    )"
fi

if [ -z "$addresses" ]; then
    echo >&2 ""
    echo >&2 "  No usable IPv4 address found."
    echo >&2 "  Join a Wi-Fi network or a phone hotspot first, then run this again."
    echo >&2 ""
    exit 1
fi

chosen="$(echo "$addresses" | head -1)"
base_url="http://${chosen}:${PORT}"

python="$here/../.venv/Scripts/python.exe"
[ -x "$python" ] || python="$here/../.venv/bin/python"

printf '\n  BlueCash mint -- development server\n\n'
printf '  %-16s %s\n' "laptop IPv4" "$chosen"
printf '  %-16s %s\n' "listening on" "0.0.0.0:${PORT}  (all interfaces)"
printf '  %-16s %s\n' "database" "$BLUECASH_DATABASE_URL"
[ "$is_new" = "1" ] && printf '  %-16s %s\n' "" "this file does not exist yet -- a NEW mint will be created"

# Which mint is in that database? Read-only, before anything starts.
if [ "$is_new" = "0" ] && [ -n "$db_path" ] && [ -x "$python" ]; then
    fingerprint="$("$python" - "$db_path" <<'PY' 2>/dev/null || true
import hashlib, sqlite3, sys
try:
    c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1].replace("?", "%3f"), uri=True)
    row = c.execute("select public_key_hex from mint_identity where id = 1").fetchone()
    print(hashlib.sha256(row[0].encode()).hexdigest()[:16] if row else "none yet")
except Exception as e:
    print("unreadable (%s)" % type(e).__name__)
PY
)"
    [ -n "$fingerprint" ] && printf '  %-16s %s\n' "mint fingerprint" "$fingerprint"
fi

others="$(echo "$addresses" | tail -n +2)"
if [ -n "$others" ]; then
    printf '\n  Other addresses on this machine (try one of these if the phones cannot reach the first):\n'
    echo "$others" | sed 's/^/    /'
fi

printf '\n  Enter this in the app, under Settings -> Backend:\n'
printf '      %s\n\n' "$base_url"
printf '  Check it from a phone with:\n'
printf '      adb -s <serial> shell curl -s -m 8 %s/health\n\n' "$base_url"

[ "$SHOW_ONLY" = "1" ] && exit 0

if [ ! -x "$python" ]; then
    echo >&2 "  Interpreter not found at $python"
    echo >&2 "  Create the virtual environment first, or run uvicorn yourself."
    exit 1
fi

cd "$here"
exec "$python" -m uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
