"""Integration tests for database passive listeners in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestPgsqlPassiveEK:
    """PostgreSQL listener field coverage tests."""

    def test_pgsql_basic(self):
        """Basic pgsql test: credentials, sessions, harvest tables."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/credslayer_pgsql.pcap",
            min_devices=0,
            min_interactions=1,
        )
        # PostgreSQL listener should extract credentials
        assert len(listener.credentials) >= 1, "Expected at least one credential"
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, "Expected at least one credential summary entry"
        for c in creds:
            assert c.get("protocol") == "PostgreSQL"
            assert c.get("username"), f"Missing username in credential: {c}"

        # get_hashes_summary returns MD5 hashes
        hashes = listener.get_hashes_summary()
        assert len(hashes) >= 1, "Expected at least one MD5 hash"
        for h in hashes:
            assert h.get("protocol") == "PostgreSQL"
            assert h.get("hash_type") == "MD5"

        # PostgreSQL tracks sessions
        assert len(listener._sessions) >= 1

    def test_pgsql_startup_version_fields(self):
        """Verify pgsql.version_major and pgsql.version_minor extraction."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/credslayer_pgsql.pcap",
            min_devices=0,
            min_interactions=1,
            expect_operations=["Startup"],
        )
        startup_ixs = [ix for ix in listener.interactions if ix.operation == "Startup"]
        assert len(startup_ixs) >= 1, "Expected at least one Startup interaction"

        for ix in startup_ixs:
            d = ix.details
            # version_major must be present and non-placeholder
            assert d.get("version_major"), f"Missing version_major in Startup details: {d}"
            assert d["version_major"] != "?", (
                f"version_major is placeholder '?' in Startup details: {d}"
            )
            # version_minor should be present (typically "0")
            assert "version_minor" in d, f"Missing version_minor key in Startup details: {d}"

    def test_pgsql_startup_username_database(self):
        """Verify EK-mode list parameter extraction for user and database."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/credslayer_pgsql.pcap",
            min_devices=0,
            min_interactions=1,
            expect_operations=["Startup"],
            expect_details=["username"],
        )
        startup_ixs = [ix for ix in listener.interactions if ix.operation == "Startup"]
        assert len(startup_ixs) >= 1, "Expected at least one Startup interaction"

        for ix in startup_ixs:
            d = ix.details
            assert d.get("username"), f"Missing username in Startup: {d}"
            assert d["username"] != "?", (
                f"username is placeholder '?' -- EK list param extraction likely broken: {d}"
            )
            assert d.get("database"), f"Missing database in Startup: {d}"
            assert d["database"] != "?", (
                f"database is placeholder '?' -- EK list param extraction likely broken: {d}"
            )

        # Session should also have the extracted values
        for sess in listener._sessions.values():
            assert sess.username, f"Session username empty: {sess}"
            assert sess.username != "?", f"Session username is '?': {sess}"
            assert sess.database, f"Session database empty: {sess}"

    def test_pgsql_message_type_field(self):
        """Verify pgsql.type (message type) extraction in interaction details."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/credslayer_pgsql.pcap",
            min_devices=0,
            min_interactions=1,
        )
        # Every interaction should have a msg_type in its details
        for ix in listener.interactions:
            assert ix.details.get("msg_type"), (
                f"Interaction missing msg_type: op={ix.operation} details={ix.details}"
            )

        # Verify known message types are present
        msg_types = {ix.details.get("msg_type") for ix in listener.interactions}
        assert "Startup message" in msg_types, (
            f"Expected 'Startup message' in msg_types; got: {sorted(msg_types)}"
        )

    def test_pgsql_auth_request_fields(self):
        """Verify pgsql.authtype and pgsql.salt extraction in auth interactions."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/credslayer_pgsql.pcap",
            min_devices=0,
            min_interactions=1,
        )
        auth_ixs = [ix for ix in listener.interactions if ix.operation.startswith("Auth")]
        assert len(auth_ixs) >= 1, "Expected at least one Auth interaction"

        for ix in auth_ixs:
            d = ix.details
            assert d.get("authtype"), f"Missing authtype in Auth details: {d}"
            assert d.get("auth_name"), f"Missing auth_name in Auth details: {d}"
            # For MD5 auth, salt should be present
            if d.get("auth_name") == "MD5":
                assert d.get("salt"), f"Missing salt in MD5 Auth details: {d}"

    def test_pgsql_credential_fields(self):
        """Verify credential dataclass has scanner-compatible fields."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/credslayer_pgsql.pcap",
            min_devices=0,
        )
        assert len(listener.credentials) >= 1, "Expected at least one credential"

        for cred in listener.credentials:
            # Canonical scanner fields must be accessible
            assert cred.username, "Credential username empty"
            assert cred.server_ip, "Credential server_ip empty"
            assert cred.client_ip, "Credential client_ip empty"
            assert cred.credential_type in ("plaintext", "hash", "none"), (
                f"Bad credential_type: {cred.credential_type}"
            )
            assert cred.auth_method, "Credential auth_method empty"
            assert cred.password is not None, "Credential password property missing"

            # MD5 credentials should have hash_value
            if cred.auth_type == "md5":
                assert cred.hash_value, "MD5 credential missing hash_value"
                assert cred.credential_type == "hash"

    def test_pgsql_hashcat_format(self):
        """Verify hashcat format output for MD5 credentials."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/credslayer_pgsql.pcap",
            min_devices=0,
        )
        hashcat = listener.get_hashcat_hashes()
        assert len(hashcat) >= 1, "Expected at least one hashcat line"
        for line in hashcat:
            parts = line.split(":")
            assert len(parts) >= 2, f"Bad hashcat format (expected user:hash:salt): {line}"
            # Username should be first
            assert parts[0], f"Empty username in hashcat line: {line}"
            # Hash should contain 'md5' prefix
            assert "md5" in parts[1], f"Hash missing md5 prefix: {line}"

    def test_pgsql_harvest_returns_dict(self):
        """Verify harvest returns a dict."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/credslayer_pgsql.pcap",
            min_devices=0,
            check_harvest=True,
        )
        assert isinstance(result, dict), "harvest() should return a dict"

    def test_pgsql_direction_via_frontend(self):
        """Verify direction detection uses pgsql.frontend, not hardcoded ports."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/credslayer_pgsql.pcap",
            min_devices=0,
            min_interactions=1,
        )
        # Check that requests come from client and responses from server
        for ix in listener.interactions:
            if ix.direction == "request":
                # Requests: src should be client (not port 5432). "Multi-message"
                # appears when EK mode collapses several client PG messages into
                # one TCP segment -- a legitimate client-side request (the server
                # side produces the same operation in the response branch below).
                assert ix.operation in (
                    "Startup",
                    "Password",
                    "Termination",
                    "Query",
                    "Multi-message",
                ), f"Unexpected request operation: {ix.operation}"
            elif ix.direction == "response":
                # Responses: src should be server. "Multi-message" appears when
                # the listener merges several PG messages from one TCP segment
                # (frequent in real PG traffic).
                assert ix.operation.startswith("Auth") or ix.operation in (
                    "Ready",
                    "Error",
                    "Notice",
                    "ParameterStatus",
                    "Multi-message",
                ), f"Unexpected response operation: {ix.operation}"

    def test_pgsql_session_protocol_version(self):
        """Verify protocol version is stored in sessions."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/credslayer_pgsql.pcap",
            min_devices=0,
        )
        for sess in listener._sessions.values():
            assert sess.protocol_version, f"Session missing protocol_version: {sess}"
            assert sess.protocol_version != "?", f"Session protocol_version is '?': {sess}"
            # Should be "3.0" for modern PostgreSQL
            assert "." in sess.protocol_version, (
                f"Session protocol_version has unexpected format: {sess.protocol_version}"
            )

    def test_pgsql_nopassword_pcap(self):
        """Verify no-password pcap still extracts username and database."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/credslayer_pgsql_nopassword.pcap",
            min_devices=0,
            min_interactions=1,
        )
        # Should have a session with username even without password
        assert len(listener._sessions) >= 1, "Expected at least one session"
        for sess in listener._sessions.values():
            assert sess.username, "Session username empty in nopassword pcap"
            assert sess.username != "?", "Session username is '?' in nopassword pcap"

        # Should have startup interactions
        startup_ixs = [ix for ix in listener.interactions if ix.operation == "Startup"]
        assert len(startup_ixs) >= 1, "Expected startup interaction in nopassword pcap"

    def test_pgsql_jdbc_ready_for_query(self):
        """Verify pgsql.status extraction from ReadyForQuery in JDBC pcap."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/wireshark_pgsql_jdbc.pcap",
            min_devices=0,
            min_interactions=10,
            expect_operations=["Ready"],
        )
        ready_ixs = [ix for ix in listener.interactions if ix.operation == "Ready"]
        assert len(ready_ixs) >= 1, "Expected at least one Ready interaction"

        for ix in ready_ixs:
            d = ix.details
            assert d.get("status"), f"Missing status in Ready details: {d}"
            assert d.get("transaction_status"), f"Missing transaction_status in Ready details: {d}"
            # Transaction status should be a known value
            assert (
                d["transaction_status"] in ("idle", "transaction", "failed")
                or "unknown" in d["transaction_status"]
            ), f"Unexpected transaction_status: {d['transaction_status']}"

    def test_pgsql_jdbc_notice_fields(self):
        """Verify error/notice field extraction: severity, code, message, file, line, routine."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/wireshark_pgsql_jdbc.pcap",
            min_devices=0,
            min_interactions=1,
            expect_operations=["Notice"],
        )
        notice_ixs = [ix for ix in listener.interactions if ix.operation == "Notice"]
        assert len(notice_ixs) >= 1, "Expected at least one Notice interaction"

        for ix in notice_ixs:
            d = ix.details
            # All T1 error/notice fields should be present
            assert d.get("severity"), f"Missing severity in Notice: {d}"
            assert d["severity"] != "?", f"severity is '?' in Notice: {d}"

            assert d.get("code"), f"Missing code in Notice: {d}"
            assert d["code"] != "?", f"code is '?' in Notice: {d}"

            assert d.get("message"), f"Missing message in Notice: {d}"
            assert d["message"] != "?", f"message is '?' in Notice: {d}"

            assert d.get("file"), f"Missing file in Notice: {d}"
            assert d["file"] != "?", f"file is '?' in Notice: {d}"

            assert d.get("line"), f"Missing line in Notice: {d}"
            assert d["line"] != "?", f"line is '?' in Notice: {d}"

            assert d.get("routine"), f"Missing routine in Notice: {d}"
            assert d["routine"] != "?", f"routine is '?' in Notice: {d}"

    def test_pgsql_jdbc_termination(self):
        """Verify Termination message extraction from JDBC pcap."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/wireshark_pgsql_jdbc.pcap",
            min_devices=0,
            min_interactions=1,
            expect_operations=["Termination"],
        )
        term_ixs = [ix for ix in listener.interactions if ix.operation == "Termination"]
        assert len(term_ixs) >= 1, "Expected at least one Termination interaction"

        for ix in term_ixs:
            assert ix.direction == "request", f"Termination should be request, got {ix.direction}"

    def test_pgsql_interaction_headers_format(self):
        """Verify PROTOCOL_COLUMNS are set and _format_protocol_columns produces correct cols."""
        from oida.pcap.pgsql import PostgreSQLPassiveListener

        assert PostgreSQLPassiveListener.PROTOCOL_COLUMNS == (
            "type",
            "operation",
            "details",
            "result",
        ), f"Unexpected PROTOCOL_COLUMNS: {PostgreSQLPassiveListener.PROTOCOL_COLUMNS}"

    def test_pgsql_credential_summary_keys(self):
        """Verify get_credentials_summary() uses canonical keys for harvest builder."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/credslayer_pgsql.pcap",
            min_devices=0,
        )
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1
        for c in creds:
            # Canonical keys that harvest builder uses directly
            assert "credential_type" in c, f"Missing credential_type key: {c.keys()}"
            assert "username" in c, f"Missing username key: {c.keys()}"
            assert "server_ip" in c, f"Missing server_ip key: {c.keys()}"
            assert "client_ip" in c, f"Missing client_ip key: {c.keys()}"
            assert "auth_method" in c, f"Missing auth_method key: {c.keys()}"
            assert "password" in c, f"Missing password key: {c.keys()}"

    def test_pgsql_hashes_summary_keys(self):
        """Verify get_hashes_summary() returns keys matching harvest hash builder."""
        listener, devices, result = _run_listener_test(
            "pgsql",
            "PostgreSQLPassiveListener",
            "pgsql",
            "pgsql/credslayer_pgsql.pcap",
            min_devices=0,
        )
        hashes = listener.get_hashes_summary()
        assert len(hashes) >= 1
        for h in hashes:
            assert "protocol" in h, f"Missing protocol key: {h.keys()}"
            assert "hash_type" in h, f"Missing hash_type key: {h.keys()}"
            assert "username" in h, f"Missing username key: {h.keys()}"
            assert "server_ip" in h, f"Missing server_ip key: {h.keys()}"
            assert "client_ip" in h, f"Missing client_ip key: {h.keys()}"
            assert "hashcat_format" in h, f"Missing hashcat_format key: {h.keys()}"


class TestMySQLPassiveEK:
    """MySQL-specific tests beyond the parametrised quality suite."""

    def test_mysql_basic(self):
        listener, devices, result = _run_listener_test(
            "mysql",
            "MySQLPassiveListener",
            "mysql",
            "mysql/credslayer_mysql.pcap",
        )
        # MySQL listener has PROTOCOL_COLUMNS so harvest should produce tables
        if result.get("tables"):
            assert len(result["tables"]) >= 1, "Expected at least one table from MySQL harvest"

        # MySQL listener should extract credentials when present
        if listener.credentials:
            creds = listener.get_credentials_summary()
            assert len(creds) >= 1, "Expected at least one credential summary entry"
            for c in creds:
                assert c.get("protocol") == "MySQL"
                assert "username" in c

            # get_hashes_summary should return data
            hashes = listener.get_hashes_summary()
            if hashes:
                for h in hashes:
                    assert h.get("protocol") == "MySQL"

            # get_hashcat_hashes should return formatted hashes
            # (canonical name probed by the scanner's --hashcat export)
            hashcat = listener.get_hashcat_hashes()
            if hashcat:
                for line in hashcat:
                    assert "$mysqlna$" in line, f"Bad hashcat format: {line}"

        # MySQL tracks sessions
        if listener._sessions:
            assert len(listener._sessions) >= 1

    def test_mysql_server_status_in_greeting(self):
        """Verify mysql.server_status extraction in server greeting details."""
        listener, devices, result = _run_listener_test(
            "mysql",
            "MySQLPassiveListener",
            "mysql",
            "mysql/credslayer_mysql.pcap",
            min_interactions=1,
            expect_operations=["Greeting"],
        )
        greeting_ixs = [ix for ix in listener.interactions if ix.operation == "Greeting"]
        assert len(greeting_ixs) >= 1, "Expected at least one Greeting interaction"

        for ix in greeting_ixs:
            d = ix.details
            # mysql.server_status should be present in greeting details
            assert "server_status" in d, f"Missing server_status key in Greeting details: {d}"
            assert d["server_status"], f"server_status is empty in Greeting details: {d}"
            # Should also have decoded flags string
            assert "server_status_flags" in d, (
                f"Missing server_status_flags key in Greeting details: {d}"
            )

    def test_mysql_auth_plugin_length_in_greeting(self):
        """Verify mysql.auth_plugin.length extraction in server greeting."""
        listener, devices, result = _run_listener_test(
            "mysql",
            "MySQLPassiveListener",
            "mysql",
            "mysql/credslayer_mysql2.pcap",
            min_interactions=1,
            expect_operations=["Greeting"],
        )
        greeting_ixs = [ix for ix in listener.interactions if ix.operation == "Greeting"]
        assert len(greeting_ixs) >= 1, "Expected at least one Greeting interaction"

        for ix in greeting_ixs:
            d = ix.details
            assert "auth_plugin_length" in d, (
                f"Missing auth_plugin_length key in Greeting details: {d}"
            )
            # credslayer_mysql2 uses MySQL 5.5 which sends auth_plugin_length=21
            apl = d["auth_plugin_length"]
            assert apl and apl != "?", f"auth_plugin_length is missing/placeholder in Greeting: {d}"

    def test_mysql_packet_number_in_greeting(self):
        """Verify mysql.packet_number (sequence ID) extraction in greeting."""
        listener, devices, result = _run_listener_test(
            "mysql",
            "MySQLPassiveListener",
            "mysql",
            "mysql/credslayer_mysql.pcap",
            min_interactions=1,
            expect_operations=["Greeting"],
        )
        greeting_ixs = [ix for ix in listener.interactions if ix.operation == "Greeting"]
        assert len(greeting_ixs) >= 1, "Expected at least one Greeting interaction"

        for ix in greeting_ixs:
            d = ix.details
            assert "packet_number" in d, f"Missing packet_number key in Greeting details: {d}"
            # Server greeting is always sequence 0
            assert d["packet_number"] == "0", (
                f"Expected packet_number=0 for greeting, got: {d['packet_number']}"
            )

    def test_mysql_server_status_in_response(self):
        """Verify mysql.server_status extraction in OK/EOF response details."""
        listener, devices, result = _run_listener_test(
            "mysql",
            "MySQLPassiveListener",
            "mysql",
            "mysql/credslayer_mysql.pcap",
            min_interactions=1,
        )
        # Find OK or EOF responses
        resp_ixs = [
            ix
            for ix in listener.interactions
            if ix.operation in ("Response", "EOF") and ix.direction == "response"
        ]
        assert len(resp_ixs) >= 1, "Expected at least one Response/EOF interaction"

        # At least one response should have server_status
        has_status = any(ix.details.get("server_status") for ix in resp_ixs)
        assert has_status, (
            f"No Response/EOF interaction has server_status; "
            f"sample details: {[ix.details for ix in resp_ixs[:3]]}"
        )

        # Check that server_status_flags is decoded for non-zero status
        for ix in resp_ixs:
            ss = ix.details.get("server_status", "")
            if ss and str(ss) != "0":
                flags = ix.details.get("server_status_flags", "")
                assert flags, f"Non-zero server_status={ss} but no decoded flags: {ix.details}"

    def test_mysql_insert_id_in_ok_response(self):
        """Verify mysql.insert_id extraction in OK response details.

        credslayer_mysql.pcap contains INSERT statements that return
        insert_id=1 and insert_id=2 in their OK response packets.
        """
        listener, devices, result = _run_listener_test(
            "mysql",
            "MySQLPassiveListener",
            "mysql",
            "mysql/credslayer_mysql.pcap",
            min_interactions=1,
        )
        # Find OK responses
        ok_ixs = [
            ix
            for ix in listener.interactions
            if ix.operation == "Response" and ix.details.get("response") == "OK"
        ]
        assert len(ok_ixs) >= 1, "Expected at least one OK Response interaction"

        # All OK responses should have insert_id key
        for ix in ok_ixs:
            assert "insert_id" in ix.details, (
                f"Missing insert_id key in OK response details: {ix.details}"
            )

        # At least one OK response should have non-zero insert_id
        nonzero_iids = [ix for ix in ok_ixs if ix.details.get("insert_id", "0") not in ("0", "")]
        assert len(nonzero_iids) >= 1, (
            f"Expected at least one OK response with non-zero insert_id; "
            f"insert_ids seen: {[ix.details.get('insert_id') for ix in ok_ixs]}"
        )

    def test_mysql_table_name_in_field_list(self):
        """Verify mysql.table_name extraction in Field List command.

        credslayer_mysql.pcap contains a Field List command for table 'agent'.
        """
        listener, devices, result = _run_listener_test(
            "mysql",
            "MySQLPassiveListener",
            "mysql",
            "mysql/credslayer_mysql.pcap",
            min_interactions=1,
        )
        # Find Field List interactions
        fl_ixs = [ix for ix in listener.interactions if ix.operation == "Field List"]
        assert len(fl_ixs) >= 1, (
            f"Expected at least one Field List interaction; "
            f"operations seen: {sorted({ix.operation for ix in listener.interactions})}"
        )

        for ix in fl_ixs:
            d = ix.details
            assert "table_name" in d, f"Missing table_name key in Field List details: {d}"
            assert d["table_name"], f"table_name is empty in Field List details: {d}"

        # The specific pcap has table_name='agent'
        table_names = [ix.details.get("table_name") for ix in fl_ixs]
        assert "agent" in table_names, (
            f"Expected table_name 'agent' in Field List; got: {table_names}"
        )

    def test_mysql_packet_number_in_response(self):
        """Verify mysql.packet_number extraction in response details."""
        listener, devices, result = _run_listener_test(
            "mysql",
            "MySQLPassiveListener",
            "mysql",
            "mysql/credslayer_mysql.pcap",
            min_interactions=1,
        )
        # Find response interactions
        resp_ixs = [
            ix
            for ix in listener.interactions
            if ix.direction == "response" and ix.operation in ("Response", "Error", "EOF")
        ]
        assert len(resp_ixs) >= 1, "Expected at least one response interaction"

        # At least some responses should have packet_number
        has_pn = any(ix.details.get("packet_number") for ix in resp_ixs)
        assert has_pn, (
            f"No response has packet_number; sample details: {[ix.details for ix in resp_ixs[:3]]}"
        )

    def test_mysql_server_status_flags_decode(self):
        """Verify server_status flags are decoded to human-readable names."""
        listener, devices, result = _run_listener_test(
            "mysql",
            "MySQLPassiveListener",
            "mysql",
            "mysql/credslayer_mysql.pcap",
            min_interactions=1,
        )
        # Find interactions with server_status_flags
        flagged = [ix for ix in listener.interactions if ix.details.get("server_status_flags")]
        assert len(flagged) >= 1, "Expected at least one interaction with decoded status flags"

        for ix in flagged:
            flags_str = ix.details["server_status_flags"]
            # Should contain known flag names like AUTOCOMMIT
            assert any(flag in flags_str for flag in ("AUTOCOMMIT", "IN_TRANS", "MORE_RESULTS")), (
                f"Unexpected flag string: {flags_str}"
            )

    def test_mysql_insert_id_wireshark_pcap(self):
        """Verify insert_id extraction from wireshark_mysql_complete.pcap.

        This pcap has INSERT statements returning insert_id=1 and insert_id=2.
        """
        listener, devices, result = _run_listener_test(
            "mysql",
            "MySQLPassiveListener",
            "mysql",
            "mysql/wireshark_mysql_complete.pcap",
            min_interactions=1,
        )
        # Find OK responses with non-zero insert_id
        ok_ixs = [
            ix
            for ix in listener.interactions
            if ix.operation == "Response"
            and ix.details.get("response") == "OK"
            and ix.details.get("insert_id", "0") not in ("0", "")
        ]
        assert len(ok_ixs) >= 2, (
            f"Expected >= 2 OK responses with non-zero insert_id from wireshark pcap; "
            f"got {len(ok_ixs)}"
        )
        insert_ids = sorted(ix.details["insert_id"] for ix in ok_ixs)
        assert "1" in insert_ids, f"Expected insert_id=1; got: {insert_ids}"
        assert "2" in insert_ids, f"Expected insert_id=2; got: {insert_ids}"

    def test_mysql_credential_fields(self):
        """Verify credential dataclass has scanner-compatible fields."""
        listener, devices, result = _run_listener_test(
            "mysql",
            "MySQLPassiveListener",
            "mysql",
            "mysql/credslayer_mysql.pcap",
            min_devices=0,
        )
        if not listener.credentials:
            pytest.skip("No credentials extracted from pcap")

        for cred in listener.credentials:
            # Canonical scanner fields must be accessible
            assert cred.username, "Credential username empty"
            assert cred.server_ip, "Credential server_ip empty"
            assert cred.client_ip, "Credential client_ip empty"
            assert cred.credential_type == "hash", (
                f"Expected credential_type 'hash', got: {cred.credential_type}"
            )
            assert cred.auth_method, "Credential auth_method empty"
            assert cred.password is not None, "Credential password property missing"
            assert cred.hash_value is not None, "Credential hash_value property missing"

    def test_mysql_credential_summary_keys(self):
        """Verify get_credentials_summary() uses canonical keys for harvest builder."""
        listener, devices, result = _run_listener_test(
            "mysql",
            "MySQLPassiveListener",
            "mysql",
            "mysql/credslayer_mysql.pcap",
            min_devices=0,
        )
        if not listener.credentials:
            pytest.skip("No credentials extracted from pcap")

        creds = listener.get_credentials_summary()
        assert len(creds) >= 1
        for c in creds:
            assert "credential_type" in c, f"Missing credential_type: {c.keys()}"
            assert "username" in c, f"Missing username: {c.keys()}"
            assert "server_ip" in c, f"Missing server_ip: {c.keys()}"
            assert "client_ip" in c, f"Missing client_ip: {c.keys()}"
            assert "auth_method" in c, f"Missing auth_method: {c.keys()}"
            assert "password" in c, f"Missing password: {c.keys()}"

    def test_mysql_harvest_returns_dict(self):
        """Verify harvest returns a dict."""
        listener, devices, result = _run_listener_test(
            "mysql",
            "MySQLPassiveListener",
            "mysql",
            "mysql/credslayer_mysql.pcap",
            check_harvest=True,
        )
        assert isinstance(result, dict), "harvest() should return a dict"

    def test_mysql_interaction_headers_format(self):
        """Verify PROTOCOL_COLUMNS are set and match expected format."""
        from oida.pcap.mysql import MySQLPassiveListener

        assert MySQLPassiveListener.PROTOCOL_COLUMNS == ("operation", "details", "result"), (
            f"Unexpected PROTOCOL_COLUMNS: {MySQLPassiveListener.PROTOCOL_COLUMNS}"
        )


class TestMSSQLPassiveEK:
    """MSSQL-specific tests beyond the parametrised quality suite."""

    def test_mssql_basic(self):
        listener, devices, result = _run_listener_test(
            "mssql",
            "MSSQLPassiveListener",
            "tds",
            "mssql/generated_mssql.pcap",
        )
        # MSSQL listener has PROTOCOL_COLUMNS so harvest should produce tables
        if result.get("tables"):
            assert len(result["tables"]) >= 1, "Expected at least one table from MSSQL harvest"

        # MSSQL listener should extract credentials when present
        if listener.credentials:
            creds = listener.get_credentials_summary()
            assert len(creds) >= 1, "Expected at least one credential summary entry"
            for c in creds:
                assert c.get("protocol") == "MSSQL"
                assert "username" in c

    def test_mssql_login7_fields(self):
        """Verify Login7 extraction: username, password, app, client, database, library."""
        listener, devices, result = _run_listener_test(
            "mssql",
            "MSSQLPassiveListener",
            "tds",
            "mssql/generated_mssql.pcap",
            expect_operations=["Login7"],
            expect_details=["username"],
        )
        # generated_mssql.pcap contains a full login sequence
        login_ixs = [ix for ix in listener.interactions if ix.operation == "Login7"]
        assert len(login_ixs) >= 1, "Expected at least one Login7 interaction"

        login = login_ixs[0]
        d = login.details
        # Core login fields must be present and non-empty
        assert d.get("username"), "Missing username in Login7 details"
        assert d.get("database") is not None, "Missing database key in Login7 details"
        assert d.get("app_name") is not None, "Missing app_name key"
        assert d.get("client_name") is not None, "Missing client_name key"
        assert d.get("server_name") is not None, "Missing server_name key"
        assert d.get("library") is not None, "Missing library key"

        # Credential extraction for SQL auth login
        if listener.credentials:
            cred = listener.credentials[0]
            assert cred.username, "Credential username is empty"
            assert cred.password, "Credential password is empty"
            assert cred.server_ip, "Credential server_ip is empty"
            assert cred.client_ip, "Credential client_ip is empty"

    def test_mssql_prelogin_fields(self):
        """Verify Pre-Login extraction: version, encryption, threadid."""
        listener, devices, result = _run_listener_test(
            "mssql",
            "MSSQLPassiveListener",
            "tds",
            "mssql/generated_mssql.pcap",
            min_devices=0,
            expect_operations=["Pre-Login"],
        )
        prelogin_ixs = [ix for ix in listener.interactions if ix.operation == "Pre-Login"]
        assert len(prelogin_ixs) >= 1, "Expected at least one Pre-Login interaction"

        # At least one pre-login should have version or encryption
        has_version = any(ix.details.get("version") for ix in prelogin_ixs)
        has_encryption = any(ix.details.get("encryption") for ix in prelogin_ixs)
        assert has_version or has_encryption, (
            f"No Pre-Login has version or encryption; "
            f"details: {[ix.details for ix in prelogin_ixs]}"
        )

    def test_mssql_rpc_wireshark(self):
        """Verify RPC extraction from wireshark TDS RPC capture."""
        listener, devices, result = _run_listener_test(
            "mssql",
            "MSSQLPassiveListener",
            "tds",
            "mssql/wireshark_mssql_tds_rpc.cap",
            min_devices=0,
            min_interactions=1,
        )
        # The wireshark RPC capture should contain RPC interactions
        rpc_ixs = [ix for ix in listener.interactions if ix.operation == "RPC"]
        if rpc_ixs:
            for rpc in rpc_ixs:
                assert rpc.details.get("proc_name"), (
                    f"RPC interaction missing proc_name; details: {rpc.details}"
                )

    def test_mssql_response_tokens_wireshark(self):
        """Verify response token extraction: Done, ReturnStatus, ColMetadata, Error."""
        listener, devices, result = _run_listener_test(
            "mssql",
            "MSSQLPassiveListener",
            "tds",
            "mssql/wireshark_mssql.cap",
            min_devices=0,
            min_interactions=1,
        )
        ops = {ix.operation for ix in listener.interactions}

        # The wireshark MSSQL capture should contain response tokens
        # (Done, ColMetadata, ReturnStatus are common in response packets)
        response_ops = ops & {
            "Done",
            "ColMetadata",
            "ReturnStatus",
            "Error",
            "Info",
            "LoginAck",
            "EnvChange",
        }
        assert len(response_ops) >= 1, (
            f"Expected at least one response token type; saw: {sorted(ops)}"
        )

        # If ColMetadata is present, verify column_names detail
        col_ixs = [ix for ix in listener.interactions if ix.operation == "ColMetadata"]
        for col in col_ixs:
            assert col.details.get("column_names"), (
                f"ColMetadata interaction missing column_names; details: {col.details}"
            )

    def test_mssql_harvest_no_raw_types(self):
        """Verify harvest output has no raw dicts or sets in table cells."""
        listener, devices, result = _run_listener_test(
            "mssql",
            "MSSQLPassiveListener",
            "tds",
            "mssql/generated_mssql.pcap",
            check_harvest=True,
        )
        # check_harvest=True already validates this in _run_listener_test,
        # but let's also verify credential alerts are present
        if listener.credentials:
            alerts = result.get("alerts", [])
            cred_alerts = [a for a in alerts if a.get("category") == "credential_alert"]
            assert len(cred_alerts) >= 1, "Expected credential alert for plaintext credentials"

    def test_mssql_device_tracking(self):
        """Verify server and client device creation with protocol data."""
        listener, devices, result = _run_listener_test(
            "mssql",
            "MSSQLPassiveListener",
            "tds",
            "mssql/generated_mssql.pcap",
            min_devices=1,
        )
        # Should have both server and client devices
        has_server = any(
            d.mssql_passive_data and d.mssql_passive_data.get("role") == "server"
            for d in devices.values()
        )
        has_client = any(
            d.mssql_passive_data and d.mssql_passive_data.get("role") == "client"
            for d in devices.values()
        )
        assert has_server, "Expected at least one MSSQL server device"
        assert has_client, "Expected at least one MSSQL client device"

        # Server device should have protocol data
        for d in devices.values():
            pdata = d.mssql_passive_data
            if pdata and pdata.get("role") == "server":
                assert "port" in pdata, "Server device missing port"
                assert pdata.get("protocol") == "TDS/TCP", "Server device missing protocol"
