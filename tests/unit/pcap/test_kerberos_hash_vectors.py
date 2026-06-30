"""Known-answer tests for Kerberos hashcat/John hash formats.

Each vector below is a real example hash copied verbatim from the authoritative
sources:
  - hashcat example_hashes wiki (modes 7500, 18200, 13100, 19600, 19700,
    19800, 19900): https://hashcat.net/wiki/doku.php?id=example_hashes
  - John the Ripper krb5_asrep_fmt_plug.c (AES AS-REP, which hashcat has no
    mode for).

A Kerberos enc-part is captured on the wire as ``edata + HMAC-checksum``. The
cracking formats need the checksum as its own field, and its size/position
depends on the cipher family:
  - RC4  (etype 23):    checksum = FIRST 16 bytes (32 hex), edata = rest
  - AES  (etype 17/18): checksum = LAST  12 bytes (24 hex), edata = rest

For each vector we reconstruct the raw wire enc-part (``hash_value``) from the
canonical line using that layout, build a KerberosHash, and assert that
``hashcat_format`` regenerates the exact canonical line. This is a round-trip
that pins the split rule, the separators ($ : * @) and the field order — the
exact things that were previously wrong (no checksum split, AES emitted with
the RC4 ``*spn*`` wrapper, etc.).
"""

from oida.pcap.kerberos import KerberosHash


def _mk(hash_type, etype, username, domain, hash_value, service_name=""):
    return KerberosHash(
        hash_type=hash_type,
        etype=etype,
        username=username,
        domain=domain,
        service_name=service_name,
        hash_value=hash_value,
    )


# --- TGS-REP (Kerberoasting) -------------------------------------------------

TGS_RC4_13100 = (
    "$krb5tgs$23$*user$realm$test/spn*$63386d22d359fe42230300d56852c9eb$"
    "891ad31d09ab89c6b3b8c5e5de6c06a7f49fd559d7a9a3c32576c8fedf705376cea582ab"
    "5938f7fc8bc741acf05c5990741b36ef4311fe3562a41b70a4ec6ecba849905f2385bb37"
    "99d92499909658c7287c49160276bca0006c350b0db4fd387adc27c01e9e9ad0c20ed53a"
    "7e6356dee2452e35eca2a6a1d1432796fc5c19d068978df74d3d0baf35c77de12456bf11"
    "44b6a750d11f55805f5a16ece2975246e2d026dce997fba34ac8757312e9e4e6272de35e"
    "20d52fb668c5ed"
)

TGS_AES128_19600 = (
    "$krb5tgs$17$user$realm$ae8434177efd09be5bc2eff8$"
    "90b4ce5b266821adc26c64f71958a475cf9348fce65096190be04f8430c4e0d554c86dd7"
    "ad29c275f9e8f15d2dab4565a3d6e21e449dc2f88e52ea0402c7170ba74f4af037c5d7f8"
    "db6d53018a564ab590fc23aa1134788bcc4a55f69ec13c0a083291a96b41bffb978f5a16"
    "0b7edc828382d11aacd89b5a1bfa710b0e591b190bff9062eace4d26187777db358e70ef"
    "d26df9c9312dbeef20b1ee0d823d4e71b8f1d00d91ea017459c27c32dc20e451ea6278be"
    "63cdd512ce656357c942b95438228e"
)

TGS_AES256_19700 = (
    "$krb5tgs$18$user$realm$8efd91bb01cc69dd07e46009$"
    "7352410d6aafd72c64972a66058b02aa1c28ac580ba41137d5a170467f06f17faf5dfb3f"
    "95ecf4fad74821fdc7e63a3195573f45f962f86942cb24255e544ad8d05178d560f683a3"
    "f59ce94e82c8e724a3af0160be549b472dd83e6b80733ad349973885e9082617294c6cbb"
    "ea92349671883eaf068d7f5dcfc0405d97fda27435082b82b24f3be27f06c19354bf3206"
    "6933312c770424eb6143674756243c1bde78ee3294792dcc49008a1b54f32ec5d5695f89"
    "9946d42a67ce2fb1c227cb1d2004c0"
)


def test_tgs_rep_rc4_13100():
    # RC4: line is ...*$<checksum32>$<edata>; wire cipher = checksum + edata.
    tail = TGS_RC4_13100.rsplit("*$", 1)[1]
    checksum, edata = tail.split("$", 1)
    h = _mk("TGS-REP", 23, "user", "realm", checksum + edata, service_name="test/spn")
    assert h.hashcat_format == TGS_RC4_13100


def test_tgs_rep_aes128_19600():
    # AES: line is ...$realm$<checksum24>$<edata>; wire cipher = edata + checksum.
    parts = TGS_AES128_19600.split("$")
    checksum, edata = parts[-2], parts[-1]
    assert len(checksum) == 24  # 12-byte AES truncated HMAC
    h = _mk("TGS-REP", 17, "user", "realm", edata + checksum)
    assert h.hashcat_format == TGS_AES128_19600
    # AES must NOT carry the RC4 *user$realm$spn* wrapper.
    assert "*" not in h.hashcat_format


def test_tgs_rep_aes256_19700():
    parts = TGS_AES256_19700.split("$")
    checksum, edata = parts[-2], parts[-1]
    h = _mk("TGS-REP", 18, "user", "realm", edata + checksum)
    assert h.hashcat_format == TGS_AES256_19700


# --- AS-REP (AS-REP roasting) ------------------------------------------------

ASREP_RC4_18200 = (
    "$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$"
    "007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720"
    "e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c"
    "5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f"
    "4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b"
    "8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c"
    "210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb815"
    "4e18e49cb27b64bf74cd7112a0ebae2102ac"
)

# John the Ripper krb5asrep AES vector (hashcat has no AES AS-REP mode):
# $krb5asrep$18$<salt=REALM+user>$<edata>$<checksum24>
ASREP_AES256_JTR = (
    "$krb5asrep$18$EXAMPLE.COMluser$"
    "42e34732112be6cec1532177a6c93af5ec3b2fc7da106c004d6d89ddcb4131092aecbead"
    "3e9f30d07b593f4c7adc6478ab50b80fee07db3531471f5f1986c8882c45fef784258f9d"
    "43195108b83a74f6dcae1beed179c356c0da4e2d69f122efc579fd207d2b2b241a6c2759"
    "97f2ec6fec95573a7518cb8b8528d932cc14186e4c5d46cef1eed4f2924ea316d80a62b0"
    "bcd98592a11eb69c04ef43b63aeae35e9f8bd8f842d0c9c33d768cd33c55914c2a1fb2f7"
    "c640b7270cf2274993c0ce4f413aac8e9d7a231c70dd0c6f8b9c16b47a90fae8d68982a6"
    "6aa58e2eb8dde93d3504e87b5d4e33827c2aa501ed63544c0578032f395205c63b030ccc"
    "c699aafb9132692c79a154d645fe83927b0eda$420973360c2e907b9053f1db"
)


def test_as_rep_rc4_18200():
    # RC4: line is ...:<checksum32>$<edata>; wire cipher = checksum + edata.
    after_colon = ASREP_RC4_18200.split(":", 1)[1]
    checksum, edata = after_colon.split("$", 1)
    h = _mk("AS-REP", 23, "user", "domain.com", checksum + edata)
    assert h.hashcat_format == ASREP_RC4_18200


def test_as_rep_aes256_jtr():
    # AES: line is $krb5asrep$18$<salt>$<edata>$<checksum24>; salt = REALM+user,
    # so username='luser', domain='EXAMPLE.COM'. wire cipher = edata + checksum.
    parts = ASREP_AES256_JTR.split("$")
    salt, edata, checksum = parts[3], parts[4], parts[5]
    assert salt == "EXAMPLE.COMluser"
    assert len(checksum) == 24
    h = _mk("AS-REP", 18, "luser", "EXAMPLE.COM", edata + checksum)
    assert h.hashcat_format == ASREP_AES256_JTR


# --- AS-REQ pre-auth ---------------------------------------------------------

# AES pre-auth (19800/19900) carries NO salt field, so these round-trip exactly.
ASREQ_AES128_19800 = (
    "$krb5pa$17$hashcat$HASHCATDOMAIN.COM$"
    "a17776abe5383236c58582f515843e029ecbff43706d177651b7b6cdb2713b17597ddb35"
    "b1c9c470c281589fd1d51cca125414d19e40e333"
)

ASREQ_AES256_19900 = (
    "$krb5pa$18$hashcat$HASHCATDOMAIN.COM$"
    "96c289009b05181bfd32062962740b1b1ce5f74eb12e0266cde74e81094661addab08c0c"
    "1a178882c91a0ed89ae4e0e68d2820b9cce69770"
)


def test_as_req_aes128_19800():
    cipher = ASREQ_AES128_19800.split("$")[-1]
    h = _mk("AS-REQ", 17, "hashcat", "HASHCATDOMAIN.COM", cipher)
    assert h.hashcat_format == ASREQ_AES128_19800


def test_as_req_aes256_19900():
    cipher = ASREQ_AES256_19900.split("$")[-1]
    h = _mk("AS-REQ", 18, "hashcat", "HASHCATDOMAIN.COM", cipher)
    assert h.hashcat_format == ASREQ_AES256_19900


def test_as_req_rc4_7500_has_salt_field():
    # hashcat 7500 layout: $krb5pa$23$user$realm$salt$cipher (5 $-fields after
    # the tag). The wiki uses a literal placeholder "salt"; OIDA derives the
    # MS PA-ENC-TIMESTAMP salt as REALM+user, so we assert the structure and the
    # derived salt rather than the placeholder.
    cipher = "deadbeef" * 8
    h = _mk("AS-REQ", 23, "user", "REALM.COM", cipher)
    assert h.hashcat_format == f"$krb5pa$23$user$REALM.COM$REALM.COMuser${cipher}"
    # Field count: tag + user + realm + salt + cipher.
    assert h.hashcat_format.count("$") == 6


# --- Negative / guard cases --------------------------------------------------


def test_unsupported_etype_yields_empty():
    assert _mk("AS-REP", 1, "u", "R", "deadbeef" * 8).hashcat_format == ""
    assert _mk("TGS-REP", 99, "u", "R", "deadbeef" * 8).hashcat_format == ""


def test_too_short_cipher_yields_empty():
    # Below the checksum size there is nothing to split -> no crackable line.
    assert _mk("AS-REP", 23, "u", "R", "aa").hashcat_format == ""
    assert _mk("TGS-REP", 18, "u", "R", "aa").hashcat_format == ""


def test_empty_cipher_yields_empty():
    assert _mk("AS-REP", 23, "u", "R", "").hashcat_format == ""
