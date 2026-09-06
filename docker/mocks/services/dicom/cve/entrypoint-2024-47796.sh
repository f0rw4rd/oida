#!/bin/sh
# Foreground launcher for the DCMTK storescp Storage SCP so the ASan OOB trace
# reaches `docker logs`. storescp listens on $DICOM_PORT (default 11112) and
# accepts all supported transfer syntaxes (+xa). On each reception it fires its
# --exec-on-reception hook:  dcmp2pgm <received-file> <out.pgm>
# dcmp2pgm loads the image into a DEFAULT presentation state (DVInterface) and
# renders the monochrome pixel data to a grayscale PGM frame WITHOUT a VOI
# window, driving DVPresentationState::getPixelData() -> DiMonoImage::getData ->
# DiMonoOutputPixelTemplate::nowindow() (dimoopxt.h:748). The presentation-state
# geometry sets the render Count from Rows*Columns, NOT the (short) input pixel
# buffer, so it over-reads -> ASan abort. The child's ASan trace is written to
# storescp's inherited stderr, so it shows up in `docker logs`.
#
# NOTE: the simpler dcm2pnm tool clamps the processed pixel count to the actually
# stored count and does NOT crash; dcmp2pgm is the canonical Talos crash path.
set -e
PORT="${DICOM_PORT:-11112}"
echo "==========================================="
echo "  REAL DCMTK storescp Store SCP (ASan/UBSan)"
echo "  CVE-2024-47796 nowindow OOB (TALOS-2024-2122)"
echo "  Port: ${PORT}  Accept: +xa"
echo "  Reception hook: dcmp2pgm (pstate no-window render) -> server crash"
echo "  Store: /app/storage"
echo "==========================================="
mkdir -p /app/storage
# -v verbose; +xa accept all supported TS; -od output dir; -xcr run dcmp2pgm on
# the just-received file (#p/#f) -> server-side no-window presentation render.
# storescp is single-process by default; it stays up, the dcmp2pgm child aborts
# under ASan and its trace is forwarded to the container log.
# #p = output directory, #f = filename -> #p/#f is the absolute path of the
# just-received DICOM object that dcmp2pgm then renders.
exec /app/storescp -v +xa -od /app/storage \
    -xcr "/app/dcmp2pgm -ll trace #p/#f /app/storage/rendered.pgm" \
    "${PORT}"
