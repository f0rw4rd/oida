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

# ── protocol + fuzzer dependency packages ────────────────────────────────────
# Derived programmatically from oida's own package metadata — the SAME source of
# truth as oida.utils.lazy_import — so the bundle can never silently drift from
# pyproject's [project.optional-dependencies]. We read every requirement gated
# by an `extra ==` marker (each protocol extra + the `fuzz` extra), map each pip
# distribution name to the import package(s) it actually installs via
# importlib.metadata, and collect_all() those. A build with only a subset of
# extras installed (e.g. the wheels that exist on Windows) just skips the absent
# ones — those protocols still expose `--help` because deps are lazy-imported.
import re as _re
from importlib.metadata import packages_distributions, requires

# dist-name (lowercased) -> set of import package names it provides
_dist_to_imports: dict = {}
for _imp, _dists in packages_distributions().items():
    for _d in _dists:
        _dist_to_imports.setdefault(_d.lower().replace("-", "_"), set()).add(_imp)

# Runtime extras only — never bundle test/doc tooling.
_SKIP_EXTRAS = {"dev", "docs", "all"}
_extra_re = _re.compile(r'extra\s*==\s*["\']([^"\']+)["\']')

_wanted_dists: set = set()
for _line in requires("oida") or []:
    _m = _extra_re.search(_line)
    if not _m or _m.group(1) in _SKIP_EXTRAS:
        continue
    _pip = _line.split(";")[0].split("[")[0]
    for _op in (">", "<", "=", "!", "~", " ", "@"):
        _pip = _pip.split(_op)[0]
    _pip = _pip.strip().lower().replace("-", "_")
    if _pip:
        _wanted_dists.add(_pip)

# Resolve each wanted distribution to its import package(s). Fall back to the
# dist name itself if metadata can't map it (covers same-name pip/import pkgs).
_pkgs_to_collect: set = set()
for _dist in _wanted_dists:
    _pkgs_to_collect |= _dist_to_imports.get(_dist, {_dist})

_collected, _skipped = [], []
for _pkg in sorted(_pkgs_to_collect):
    try:
        _d, _b, _h = collect_all(_pkg)
        datas += _d
        binaries += _b
        hiddenimports += _h
        _collected.append(_pkg)
    except Exception as _exc:
        _skipped.append(f"{_pkg} ({type(_exc).__name__})")

# Surface coverage in the build log so a missing dep is visible, not silent.
print(f"[oida.spec] collected {len(_collected)} dep packages: {sorted(_collected)}")
if _skipped:
    print(f"[oida.spec] skipped (not installed in this build env): {sorted(_skipped)}")

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
    # Test tooling and GUI/plotting libs are not part of the shipped CLI.
    # (boofuzz IS shipped — it backs the `oida fuzz` subcommand.)
    excludes=["pytest", "_pytest", "IPython", "tkinter", "matplotlib"],
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
