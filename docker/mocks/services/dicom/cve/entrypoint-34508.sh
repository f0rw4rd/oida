#!/bin/sh
# Foreground launcher for the DCMTK DIMSE Store SCP (dcmrecv) so the ASan/abort
# trace reaches `docker logs`. Listens on $DICOM_PORT (default 11112), accepts
# any AE title, writes received objects to /app/storage.
set -e
PORT="${DICOM_PORT:-11112}"
echo "==========================================="
echo "  REAL DCMTK dcmrecv Store SCP (ASan/UBSan)"
echo "  Port: ${PORT}  AE: ANY-SCP  Store: /app/storage"
echo "==========================================="
mkdir -p /app/storage
# -v verbose, --output-directory storage, accept any calling/called AE.
# Run in foreground; ASan abort on the malformed DIMSE message kills this PID 1.
exec /app/dcmrecv "${PORT}" \
    --output-directory /app/storage \
    --aetitle ANY-SCP \
    --verbose
