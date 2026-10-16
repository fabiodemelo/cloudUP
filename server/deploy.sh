#!/usr/bin/env bash
# Deploy the CloudUp sync API to demelos.com.
#
#   server/deploy.sh            first run creates the database, DB user and env
#                               file; every run applies schema.sql (idempotent),
#                               lints the PHP on the server and swaps the new
#                               code into place.
#
# Needs the `demelos` ssh alias with passwordless sudo for the ssh user.
# Never prints secrets: they are generated on the server and stay there.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SSH=(ssh -o RemoteCommand=none -o BatchMode=yes -o LogLevel=ERROR demelos)

HOME_DIR=/home/demelos.com
DEST=$HOME_DIR/public_html/tools/cloudup/api/v1
ENV_FILE=$HOME_DIR/cloudup-api.env
LOG_FILE=$HOME_DIR/cloudup-api.log
STAGE=$HOME_DIR/.cloudup-api-stage
PHP=/usr/local/lsws/lsphp83/bin/php
WEB_USER=demel3276

echo "==> database, DB user, env file and log file (first run only)"
"${SSH[@]}" "bash -s" <<REMOTE
set -euo pipefail
if sudo -n test -f '$ENV_FILE'; then
  echo "    env file exists; leaving database credentials alone"
else
  DB_PASS=\$(openssl rand -hex 24)
  SERVER_SECRET=\$(openssl rand -hex 32)
  TEST_SECRET=\$(openssl rand -hex 32)
  sudo -n mysql <<SQL
CREATE DATABASE IF NOT EXISTS cloudup CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'cloudup'@'localhost' IDENTIFIED BY '\$DB_PASS';
ALTER USER 'cloudup'@'localhost' IDENTIFIED BY '\$DB_PASS';
GRANT SELECT, INSERT, UPDATE, DELETE ON cloudup.* TO 'cloudup'@'localhost';
FLUSH PRIVILEGES;
SQL
  printf '%s\n' \
    '# CloudUp sync API (server/README.md). Owner $WEB_USER, mode 0600.' \
    'DB_HOST=localhost' \
    'DB_NAME=cloudup' \
    'DB_USER=cloudup' \
    "DB_PASS=\$DB_PASS" \
    '# HMAC key for fake prelogin salts, code hashes and rate-limit buckets.' \
    '# Changing it invalidates live codes and changes fake salts.' \
    "SERVER_SECRET=\$SERVER_SECRET" \
    '# Header secret for server/tests/api_test.py (cloudup-test+*@demelos.com only).' \
    '# Leave empty to switch test mode off.' \
    "TEST_SECRET=\$TEST_SECRET" \
    'LOG_FILE=$LOG_FILE' \
    | sudo -n -u $WEB_USER sh -c 'umask 077; cat > "\$1"' sh '$ENV_FILE'
  echo "    created database cloudup, user cloudup@localhost and $ENV_FILE"
fi
sudo -n -u $WEB_USER sh -c 'umask 077; touch "\$1"; chmod 600 "\$1" "\$2"' sh '$LOG_FILE' '$ENV_FILE'
REMOTE

echo "==> schema"
"${SSH[@]}" "sudo -n mysql cloudup" < "$HERE/schema.sql"

echo "==> upload and lint"
"${SSH[@]}" "sudo -n -u $WEB_USER rm -rf '$STAGE' && sudo -n -u $WEB_USER mkdir -p '$STAGE'"
COPYFILE_DISABLE=1 tar -C "$HERE/api" --no-xattrs --exclude '.DS_Store' --exclude '._*' -czf - . \
  | "${SSH[@]}" "sudo -n -u $WEB_USER tar -C '$STAGE' -xzf - --no-same-owner --no-same-permissions"
"${SSH[@]}" "bash -s" <<REMOTE
set -euo pipefail
cd '$STAGE'
for f in \$(sudo -n -u $WEB_USER find . -name '*.php'); do
  sudo -n -u $WEB_USER $PHP -l "\$f" >/dev/null
done
sudo -n -u $WEB_USER find . -type d -exec chmod 755 {} +
sudo -n -u $WEB_USER find . -type f -exec chmod 644 {} +
REMOTE

echo "==> swap into $DEST"
"${SSH[@]}" "bash -s" <<REMOTE
set -euo pipefail
sudo -n -u $WEB_USER mkdir -p '$(dirname "$DEST")'
sudo -n -u $WEB_USER chmod 755 '$(dirname "$DEST")'
sudo -n -u $WEB_USER rm -rf '$STAGE.old'
if sudo -n test -d '$DEST'; then sudo -n -u $WEB_USER mv '$DEST' '$STAGE.old'; fi
sudo -n -u $WEB_USER mv '$STAGE' '$DEST'
sudo -n -u $WEB_USER rm -rf '$STAGE.old'
REMOTE

echo "==> smoke test"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -A 'CloudUp-Deploy/1' --data '{"email":"cloudup-test+deploy@demelos.com"}' \
  https://www.demelos.com/tools/cloudup/api/v1/prelogin)
echo "    POST prelogin -> HTTP $code"
[ "$code" = 200 ]
