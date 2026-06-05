# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the standalone ``oida`` binary (Linux + Windows, x86_64).

Produces a single-file executable bundling the oida CLI plus every protocol
module. Protocols are imported dynamically by name in
``loader.ProtocolLoader._discover_frozen`` (filesystem scanning is impossible
inside a frozen bundle), so their submodules must be *force-collected* —
PyInstaller's static analysis cannot see dynamic ``importlib.import_module``
calls.

Build:
    pyinstaller oida.spec --clean --noconfirm
Smoke test:
    pytest tests/integration/test_binary_smoke.py -m binary -v
"""

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

datas = []
binaries = []
hiddenimports = []

# ── oida itself ──────────────────────────────────────────────────────────────
# Every submodule (so dynamically-imported protocols resolve from the PYZ) plus
# the source tree as on-disk data. include_py_files=True recreates
# ``oida/protocols/**`` under _MEIPASS so the existence check in
# ``ProtocolLoader(Path(__file__).parent / "protocols")`` passes when frozen.
hiddenimports += collect_submodules("oida")
datas += collect_data_files("oida", include_py_files=True)

# ── protocol dependency packages ─────────────────────────────────────────────
# Bundle whatever optional deps are installed in the build environment. The
# try/except means a build with only a subset of extras (e.g. the wheels that
# exist for Windows) still succeeds; a missing dep only makes that protocol's
# live scan unavailable — ``oida <proto> --help`` still works because deps are
# lazy-imported (see oida.utils.lazy_import).
_OPTIONAL_PKGS = [
    # pure-python / cross-platform
    "scapy",
    "asyncua",
    "pymodbus",
    "paho",
    "pysnmp",
    "bacpypes3",
    "BAC0",
    "hl7apy",
    "pydicom",
    "can",
    "aiocoap",
    "ocpp",
    "fhirclient",
    "xknx",
    "xknxproject",
    "asn1tools",
    "construct",
    "cryptography",
    "websockets",
    "aiohttp",
    "defusedxml",
    "yaml",
    "pyshark",
    "bitstring",
    "ecdsa",
    # native-extension deps (collect_all grabs their bundled .so/.pyd/.dll)
    "pyads",
    "snap7",
    "opendnp3",
    "pyiec61850",
    "profinet",
    "hartip",
]
for _pkg in _OPTIONAL_PKGS:
    try:
        _d, _b, _h = collect_all(_pkg)
        datas += _d
        binaries += _b
        hiddenimports += _h
    except Exception:
        # Not installed in this build env — skip; protocol degrades gracefully.
        pass

hiddenimports = sorted(set(hiddenimports))

a = Analysis(
    ["src/oida/__main__.py"],
    pathex=["src"],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # boofuzz (the fuzzer) and test tooling are not part of the shipped CLI.
    excludes=["boofuzz", "pytest", "_pytest", "IPython", "tkinter", "matplotlib"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="oida",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
