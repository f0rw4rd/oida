#!/usr/bin/env bash
# Regenerate tests/fixtures/pcap/pgsql/oida_pgsql_md5.pcap
#
# Captures a real psql -> postgres:13 md5 auth handshake. Capture is done with a
# tcpdump sidecar that shares the postgres container's network namespace, so it
# works without host root / wireshark-group membership (only the docker group).
#
# Known credential (for the cracking assertion):  oida / S3cretPg1
# Crack:  hashcat -m 11100 '$postgres$oida*<salt>*<hash>' wordlist  ->  S3cretPg1
set -euo pipefail

OUT="${1:-$(git rev-parse --show-toplevel)/tests/fixtures/pcap/pgsql/oida_pgsql_md5.pcap}"
NET=oida-cap-pg PG=oida-pg CAP=oida-pg-cap
PASS=S3cretPg1 USER=oida
TMP="$(mktemp -d)"

cleanup() { docker rm -f "$CAP" "$PG" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT
cleanup

docker network create "$NET" >/dev/null
# PG13: default password_encryption=md5, so md5 pg_hba -> md5 auth on the wire.
docker run -d --name "$PG" --network "$NET" \
  -e POSTGRES_USER="$USER" -e POSTGRES_PASSWORD="$PASS" \
  -e POSTGRES_HOST_AUTH_METHOD=md5 postgres:13 >/dev/null
for _ in $(seq 1 30); do docker exec "$PG" pg_isready -U "$USER" >/dev/null 2>&1 && break; sleep 1; done

docker run -d --name "$CAP" --net="container:$PG" -v "$TMP:/cap" \
  alpine sh -c "apk add -q tcpdump && tcpdump -i any -U -w /cap/out.pcap 'tcp port 5432'" >/dev/null
sleep 4
docker run --rm --network "$NET" -e PGPASSWORD="$PASS" \
  postgres:13 psql "host=$PG user=$USER dbname=postgres" -c "select 1" >/dev/null
sleep 2
docker rm -f "$CAP" >/dev/null; sleep 1

mkdir -p "$(dirname "$OUT")"
cp "$TMP/out.pcap" "$OUT"
echo "[+] wrote $OUT"
tshark -r "$OUT" -Y "pgsql.authtype==5 || pgsql.password" -T fields -e pgsql.salt -e pgsql.password 2>/dev/null
