#!/usr/bin/env bash
# Regenerate tests/fixtures/pcap/http/oida_http_digest.pcap
#
# Captures a real curl --digest -> apache httpd:2.4 (mod_auth_digest) exchange.
# Known credential:  oida / S3cretHt1   (realm "testrealm")
# Crack:  john --format=hdaa  ->  S3cretHt1
set -euo pipefail

OUT="${1:-$(git rev-parse --show-toplevel)/tests/fixtures/pcap/http/oida_http_digest.pcap}"
NET=oida-cap-http WEB=oida-httpd CAP=oida-httpd-cap
USER=oida PASS=S3cretHt1 REALM=testrealm
TMP="$(mktemp -d)"

cleanup() { docker rm -f "$CAP" "$WEB" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$TMP" 2>/dev/null || true; }
trap cleanup EXIT
cleanup
mkdir -p "$TMP"   # the startup cleanup above removes $TMP; we write to it next

# htdigest file format: user:realm:md5(user:realm:password)
HA1=$(printf '%s:%s:%s' "$USER" "$REALM" "$PASS" | md5sum | cut -d' ' -f1)
printf '%s:%s:%s\n' "$USER" "$REALM" "$HA1" > "$TMP/digest.passwd"
cat > "$TMP/digest.conf" <<EOF
LoadModule auth_digest_module modules/mod_auth_digest.so
<Location "/">
  AuthType Digest
  AuthName "$REALM"
  AuthDigestProvider file
  AuthUserFile conf/digest.passwd
  Require valid-user
</Location>
EOF

docker network create "$NET" >/dev/null
docker run -d --name "$WEB" --network "$NET" -v "$TMP:/work" httpd:2.4 sh -c '
  cp /work/digest.passwd conf/digest.passwd &&
  cat /work/digest.conf >> conf/httpd.conf &&
  httpd-foreground' >/dev/null
for _ in $(seq 1 30); do
  docker run --rm --network "$NET" curlimages/curl -s -o /dev/null "http://$WEB/" && break
  sleep 1
done

docker run -d --name "$CAP" --net="container:$WEB" -v "$TMP:/cap" \
  alpine sh -c "apk add -q tcpdump && tcpdump -i any -U -w /cap/out.pcap 'tcp port 80'" >/dev/null
sleep 4
docker run --rm --network "$NET" curlimages/curl -s --digest -u "$USER:$PASS" "http://$WEB/" >/dev/null
sleep 2
docker rm -f "$CAP" >/dev/null; sleep 1

mkdir -p "$(dirname "$OUT")"
cp "$TMP/out.pcap" "$OUT"
echo "[+] wrote $OUT"
tshark -r "$OUT" -Y "http.authorization" -T fields -e http.request.method -e http.authorization 2>/dev/null | head
