#!/usr/bin/env bash
# Regenerate tests/fixtures/pcap/mysql/oida_mysql_native.pcap
#
# Captures a real mysql -> mysql:5.7 mysql_native_password handshake (CRAM-SHA1).
# Known credential (for the cracking assertion):  oida / S3cretMy1
# Crack:  hashcat -m 11200 '$mysqlna$<salt>*<hash>' wordlist  ->  S3cretMy1
set -euo pipefail

OUT="${1:-$(git rev-parse --show-toplevel)/tests/fixtures/pcap/mysql/oida_mysql_native.pcap}"
NET=oida-cap-my MY=oida-my CAP=oida-my-cap
ROOTPW=rootpw123 USER=oida PASS=S3cretMy1
TMP="$(mktemp -d)"

cleanup() { docker rm -f "$CAP" "$MY" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT
cleanup

docker network create "$NET" >/dev/null
# 5.7 default authentication plugin is mysql_native_password.
docker run -d --name "$MY" --network "$NET" \
  -e MYSQL_ROOT_PASSWORD="$ROOTPW" -e MYSQL_USER="$USER" -e MYSQL_PASSWORD="$PASS" \
  -e MYSQL_DATABASE=test mysql:5.7 >/dev/null
echo "[*] waiting for mysql..."
for _ in $(seq 1 60); do
  docker exec "$MY" mysqladmin ping -uroot -p"$ROOTPW" >/dev/null 2>&1 && break
  sleep 1
done

docker run -d --name "$CAP" --net="container:$MY" -v "$TMP:/cap" \
  alpine sh -c "apk add -q tcpdump && tcpdump -i any -U -w /cap/out.pcap 'tcp port 3306'" >/dev/null
sleep 4
# --ssl-mode=DISABLED keeps the handshake in cleartext so the CRAM is captured.
docker run --rm --network "$NET" mysql:5.7 \
  mysql -h "$MY" -u "$USER" -p"$PASS" --ssl-mode=DISABLED -e "select 1" >/dev/null 2>&1 || true
sleep 2
docker rm -f "$CAP" >/dev/null; sleep 1

mkdir -p "$(dirname "$OUT")"
cp "$TMP/out.pcap" "$OUT"
echo "[+] wrote $OUT"
tshark -r "$OUT" -Y "mysql.salt || mysql.passwd" -T fields -e mysql.salt -e mysql.salt2 -e mysql.passwd 2>/dev/null | head
