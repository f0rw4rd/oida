#!/usr/bin/env bash
# Regenerate tests/fixtures/pcap/smb/oida_ntlmv2_smb.pcap
#
# Captures a COMPLETE NetNTLMv2 handshake: impacket smbserver (which ALSO prints
# the NetNTLMv2 hash it receives -> independent oracle) + smbclient auth.
# Known credential:  oida / S3cretNt1   (domain WORKGROUP)
# Crack:  hashcat -m 5600 '<netntlmv2 line>' wordlist  ->  S3cretNt1
#
# Prints both impacket's oracle hash and the captured pcap path.
set -euo pipefail

OUT="${1:-$(git rev-parse --show-toplevel)/tests/fixtures/pcap/smb/oida_ntlmv2_smb.pcap}"
NET=oida-cap-smb SRV=oida-smb CAP=oida-smb-cap
USER=oida PASS=S3cretNt1
TMP="$(mktemp -d)"; chmod 777 "$TMP"

cleanup() { docker rm -f "$CAP" "$SRV" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$TMP" 2>/dev/null || true; }
trap cleanup EXIT
cleanup
mkdir -p "$TMP"; chmod 777 "$TMP"

docker network create "$NET" >/dev/null

# impacket smbserver: prints the NetNTLMv2 hash of any client that authenticates.
docker run -d --name "$SRV" --network "$NET" -v "$TMP:/log" python:3.11-slim bash -c '
  pip install -q impacket 2>/dev/null
  mkdir -p /share
  smbserver.py share /share -smb2support 2>&1 | tee /log/impacket.log' >/dev/null
echo "[*] waiting for smbserver..."
for _ in $(seq 1 40); do
  docker logs "$SRV" 2>&1 | grep -q "Config file parsed" && break
  docker inspect -f '{{.State.Running}}' "$SRV" 2>/dev/null | grep -q false && { echo "smbserver died:"; docker logs "$SRV" 2>&1 | tail; exit 1; }
  sleep 1
done
sleep 2

docker run -d --name "$CAP" --net="container:$SRV" -v "$TMP:/cap" \
  alpine sh -c "apk add -q tcpdump && tcpdump -i any -U -w /cap/out.pcap 'tcp port 445'" >/dev/null
sleep 4

# smbclient (debian) authenticates with NTLMv2 (no kerberos realm -> NTLM).
docker run --rm --network "$NET" debian:12-slim bash -c "
  apt-get update -q >/dev/null 2>&1 && apt-get install -y -q smbclient >/dev/null 2>&1
  smbclient //$SRV/share -U '$USER%$PASS' -m SMB3 -c 'ls' 2>&1 | tail -3 || true"
sleep 2
docker rm -f "$CAP" >/dev/null; sleep 1

mkdir -p "$(dirname "$OUT")"
cp "$TMP/out.pcap" "$OUT"
echo "[+] wrote $OUT"
echo "[*] impacket ORACLE NetNTLMv2 hash:"
grep -aiE "::|NTLMv2" "$TMP/impacket.log" 2>/dev/null | grep -i "$USER" | head -3 || echo "(none logged)"
