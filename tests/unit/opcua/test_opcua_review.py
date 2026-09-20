"""Regression tests from the modbus/opcua/snap7 bug hunt (OPC UA scope).

Each test here corresponds to a bug that was reproduced against the real
asyncua 1.1.8 API before being fixed.
"""

import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock

from asyncua import ua

from oida.protocols.opcua.scanner import (
    OPCUAScanner,
    _canonical_security_mode,
    _canonical_security_policy,
)


# ---------------------------------------------------------------------------
# O1: silent OPC UA security downgrade
# ---------------------------------------------------------------------------


class TestSecurityStringNormalisation:
    """asyncua resolves the policy/mode by exact attribute lookup:

        getattr(security_policies, f"SecurityPolicy{parts[0]}")
        getattr(ua.MessageSecurityMode, parts[1])

    so it only accepts PascalCase. OIDA's own ``protocol_options`` schema
    documents lowercase ("basic256sha256", "sign"). Feeding the documented
    value straight through raised AttributeError inside asyncua, which was
    swallowed at debug level -- and the scan then ran UNENCRYPTED.
    """

    @pytest.mark.parametrize(
        "given,expected",
        [
            ("basic256sha256", "Basic256Sha256"),
            ("Basic256Sha256", "Basic256Sha256"),
            ("BASIC256SHA256", "Basic256Sha256"),
            ("basic128rsa15", "Basic128Rsa15"),
            ("basic256", "Basic256"),
            ("aes128sha256rsaoaep", "Aes128Sha256RsaOaep"),
            ("aes256sha256rsapss", "Aes256Sha256RsaPss"),
        ],
    )
    def test_policy_normalises_to_asyncua_spelling(self, given, expected):
        assert _canonical_security_policy(given) == expected

    @pytest.mark.parametrize(
        "given,expected",
        [
            ("sign", "Sign"),
            ("Sign", "Sign"),
            ("signandencrypt", "SignAndEncrypt"),
            ("SignAndEncrypt", "SignAndEncrypt"),
        ],
    )
    def test_mode_normalises_to_asyncua_spelling(self, given, expected):
        assert _canonical_security_mode(given) == expected

    def test_normalised_names_actually_resolve_in_asyncua(self):
        """Guards against a normalisation table that drifts from the library."""
        from asyncua.crypto import security_policies

        policy = _canonical_security_policy("basic256sha256")
        mode = _canonical_security_mode("signandencrypt")
        assert getattr(security_policies, f"SecurityPolicy{policy}") is not None
        assert getattr(ua.MessageSecurityMode, mode) is not None

    def test_unknown_policy_is_rejected(self):
        assert _canonical_security_policy("totally-bogus") is None
        assert _canonical_security_mode("totally-bogus") is None


class TestConfigureSecurity:
    def _scanner(self, **over):
        args = {
            "rhost": "192.0.2.1",
            "security-policy": "basic256sha256",
            "security-mode": "sign",
            "certificate-path": "/tmp/oida-test-cert.pem",
            "private-key-path": "/tmp/oida-test-key.pem",
        }
        args.update(over)
        return OPCUAScanner(args)

    def test_lowercase_config_reaches_asyncua_as_pascalcase(self):
        """RED before the fix: the string passed through verbatim as
        "basic256sha256,sign,..." which asyncua cannot resolve."""
        scanner = self._scanner()
        client = MagicMock()
        client.set_security_string = AsyncMock()

        asyncio.run(scanner._configure_security(client))

        client.set_security_string.assert_awaited_once()
        sent = client.set_security_string.await_args.args[0]
        policy, mode, cert, key = sent.split(",")
        assert policy == "Basic256Sha256"
        assert mode == "Sign"
        assert cert == "/tmp/oida-test-cert.pem"
        assert key == "/tmp/oida-test-key.pem"

    def test_unknown_policy_raises_instead_of_connecting_insecurely(self):
        scanner = self._scanner(**{"security-policy": "basic999"})
        client = MagicMock()
        client.set_security_string = AsyncMock()

        with pytest.raises(ValueError, match="Unknown OPC UA security policy"):
            asyncio.run(scanner._configure_security(client))
        client.set_security_string.assert_not_awaited()

    def test_unknown_mode_raises_instead_of_connecting_insecurely(self):
        scanner = self._scanner(**{"security-mode": "encryptmaybe"})
        client = MagicMock()
        client.set_security_string = AsyncMock()

        with pytest.raises(ValueError, match="Unknown OPC UA security mode"):
            asyncio.run(scanner._configure_security(client))
        client.set_security_string.assert_not_awaited()

    def test_security_failure_propagates_and_is_not_swallowed(self):
        """The old code caught everything and logged at debug, so the caller
        went on to connect in cleartext believing security was configured."""
        scanner = self._scanner()
        client = MagicMock()
        client.set_security_string = AsyncMock(side_effect=RuntimeError("handshake refused"))

        with pytest.raises(RuntimeError, match="handshake refused"):
            asyncio.run(scanner._configure_security(client))

    def test_missing_certificate_does_not_silently_claim_security(self):
        scanner = self._scanner(**{"certificate-path": "", "private-key-path": ""})
        client = MagicMock()
        client.set_security_string = AsyncMock()

        asyncio.run(scanner._configure_security(client))
        client.set_security_string.assert_not_awaited()


# ---------------------------------------------------------------------------
# O3: max_nodes == 0 truncated the browse to the root node
# ---------------------------------------------------------------------------


def _mock_node(node_id, children=()):
    node = MagicMock()
    node.nodeid.to_string.return_value = node_id
    browse_name = MagicMock()
    browse_name.NamespaceIndex = 0
    browse_name.Name = node_id
    node.read_browse_name = AsyncMock(return_value=browse_name)
    display_name = MagicMock()
    display_name.Text = node_id
    node.read_display_name = AsyncMock(return_value=display_name)
    node_class = MagicMock()
    node_class.name = "Object"
    node.read_node_class = AsyncMock(return_value=node_class)
    node.get_children = AsyncMock(return_value=list(children))
    return node


class TestExploreNodeMaxNodes:
    def _explore(self, max_nodes):
        from oida.utils.protocol_helpers import ProgressTracker

        scanner = OPCUAScanner({"rhost": "192.0.2.1"})
        scanner.nodes = []
        scanner.node_values = {}
        tree = _mock_node("root", [_mock_node("c1"), _mock_node("c2"), _mock_node("c3")])
        tracker = ProgressTracker(100, logger=scanner.logger)
        asyncio.run(scanner._explore_node(tree, max_nodes, 10, 0, tracker, False))
        return scanner.nodes

    def test_max_nodes_zero_means_unlimited_not_root_only(self):
        """The top-of-method guard is `max_nodes > 0 and ...`, i.e. 0 == unlimited.
        The child-recursion guard used a bare `len(self.nodes) < max_nodes`, which
        is False for 0, so children were never visited: RED before the fix with
        exactly 1 node discovered."""
        nodes = self._explore(0)
        assert len(nodes) == 4, f"expected root + 3 children, got {[n['node_id'] for n in nodes]}"

    def test_positive_max_nodes_still_explores(self):
        assert len(self._explore(10)) == 4

    def test_positive_max_nodes_still_caps(self):
        assert len(self._explore(2)) <= 2


# ---------------------------------------------------------------------------
# O2: fuzz int encoding overflowed on UInt32/Int64 and narrowed on restore
# ---------------------------------------------------------------------------


class _FuzzHost:
    """Minimal host exposing FuzzMixin against a single mocked Variable node."""

    def __init__(self, value, variant_type):
        from oida.protocols.opcua.mixins.fuzz import FuzzMixin

        self.__class__ = type("_Host", (FuzzMixin,), {})
        self.logger = MagicMock()
        self.written = []

        node = MagicMock()
        node.read_node_class = AsyncMock(return_value=ua.NodeClass.Variable)
        node.read_data_type_as_variant_type = AsyncMock(return_value=variant_type)
        self._current = value

        async def _read_value():
            return self._current

        async def _write_value(v):
            self.written.append(v)
            self._current = v

        node.read_value = AsyncMock(side_effect=_read_value)
        node.write_value = AsyncMock(side_effect=_write_value)

        self._client = MagicMock()
        self._client.get_node = MagicMock(return_value=node)


class TestFuzzIntegerWidths:
    """Before the fix the int branch hardcoded a 4-byte SIGNED encoding:

        return value.to_bytes(4, byteorder="little", signed=True)

    Any UInt32 >= 2**31 (counters, IDs, timestamps) or any Int64 raised
    OverflowError on the very first read_value(); _fuzz_node's outer
    `except Exception` swallowed it into "Error fuzzing node", so the node was
    silently never fuzzed. The decode path also sliced data[:4], narrowing an
    Int64 on restore (5000000000 -> 705032704).
    """

    def _run(self, value, variant_type, iterations=2):
        host = _FuzzHost(value, variant_type)
        result = asyncio.run(host._fuzz_node("ns=2;i=42", iterations))
        return host, result

    def test_uint32_above_signed_range_is_actually_fuzzed(self):
        host, result = self._run(3_000_000_000, ua.VariantType.UInt32)
        assert result is not None, (
            "node was silently skipped -- encode_value raised OverflowError and "
            "_fuzz_node swallowed it"
        )
        assert result["tests"] > 0

    def test_int64_is_actually_fuzzed(self):
        host, result = self._run(5_000_000_000, ua.VariantType.Int64)
        assert result is not None
        assert result["tests"] > 0

    def test_int64_original_is_restored_exactly_not_narrowed(self):
        host, result = self._run(5_000_000_000, ua.VariantType.Int64)
        assert result is not None
        assert result["restore_failures"] == 0
        assert host.written, "nothing was ever written"
        assert host.written[-1] == 5_000_000_000, (
            f"restore narrowed the Int64 to {host.written[-1]} (data[:4] slice truncated the value)"
        )

    def test_int32_still_works(self):
        host, result = self._run(1234, ua.VariantType.Int32)
        assert result is not None
        assert host.written[-1] == 1234

    def test_unknown_variant_type_falls_back_to_int32(self):
        host, result = self._run(1234, None)
        assert result is not None
        assert host.written[-1] == 1234
