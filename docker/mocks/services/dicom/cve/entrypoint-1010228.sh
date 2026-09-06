#!/bin/sh
# Foreground launcher for the DCMTK storescp Storage SCP so the ASan
# heap-buffer-overflow trace reaches `docker logs`. storescp listens on
# $DICOM_PORT (default 11112) and accepts all transfer syntaxes incl. RLE
# Lossless (+xa). It cannot itself decode RLE on store (DCMTK refuses to combine
# --accept-all with a forced uncompressed write TS), so on each reception it
# fires its --exec-on-reception hook:  dcmdrle <received-file> /dev/null
# dcmdrle registers the RLE codec and decodes the pixel data -> reaches
# DcmRLECodecDecoder::decode() -> DcmRLEDecoder::decompress() -> ASan abort on
# the malformed RLE offset table. The child's ASan trace is written to storescp's
# inherited stderr, so it shows up in `docker logs`.
set -e
PORT="${DICOM_PORT:-11112}"
echo "==========================================="
echo "  REAL DCMTK storescp Store SCP (ASan/UBSan)"
echo "  CVE-2019-1010228 RLE decoder heap overflow"
echo "  Port: ${PORT}  Accept: +xa (incl. RLE Lossless)"
echo "  Reception hook: dcmdrle (RLE decode) -> server-side crash"
echo "  Store: /app/storage"
echo "==========================================="
mkdir -p /app/storage
# -v verbose; +xa accept all supported TS (so the RLE presentation context is
# accepted and the RLE object is stored bit-preserving by default); -od output
# dir; -xcr run dcmdrle on the just-received file (#f) -> server-side RLE decode.
# storescp is single-process by default; it stays up, the dcmdrle child aborts
# under ASan and its trace is forwarded to the container log.
# #p = output directory, #f = filename -> #p/#f is the absolute path of the
# just-received RLE object that dcmdrle then decodes.
exec /app/storescp -v +xa -od /app/storage \
    -xcr "/app/dcmdrle -ll trace #p/#f /app/storage/decoded.dcm" \
    "${PORT}"
