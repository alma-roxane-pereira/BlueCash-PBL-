#!/bin/sh
# Bring the schema up to date, then serve.
#
# Migrations run here rather than at image build time, because the database is
# a runtime dependency: the image is built once and may be deployed against
# different databases. `upgrade head` is idempotent, so a restart that changes
# nothing costs one query.
#
# If the migration fails the container must not start. A mint serving against a
# half-migrated schema would accept registrations it cannot settle later.
set -e

if [ -z "$BLUECASH_DATABASE_URL" ]; then
    echo "BLUECASH_DATABASE_URL is not set." >&2
    echo "Refusing to start: the mint's signing identity lives in the database," >&2
    echo "and defaulting to a local file would silently create a different mint." >&2
    exit 1
fi

echo "Applying migrations..."
python -m alembic upgrade head

echo "Starting the mint on 0.0.0.0:${PORT}"
exec python -m uvicorn app.main:app --host 0.0.0.0 --port "${PORT}" --proxy-headers --forwarded-allow-ips='*'
