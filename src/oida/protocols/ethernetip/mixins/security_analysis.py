"""
EtherNet/IP Security Analysis Mixin

Handles security analysis and finding reporting:
- Analyze security configuration (CIP Security, TLS, authentication)
- Evaluate controller mode security implications
- Report findings (identity, tags, topology, vulnerabilities)
- Override security printing for inline display
"""

from __future__ import annotations

from typing import Any, Dict, TYPE_CHECKING

from oida.utils import SecurityAnalyzer

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


def _count_writable_attrs(write_test_results: Dict[str, Any]) -> int:
    """Count attributes with `writable=True` in a write_test_results dict.

    Shape: {class_id: {"class_attributes": {attr_id: {"writable": bool}},
                       "instances": {inst_id: {attr_id: {"writable": bool}}}}}.
    """
    total = 0
    for write_info in write_test_results.values():
        if not isinstance(write_info, dict):
            continue
        for attr_data in (write_info.get("class_attributes") or {}).values():
            if isinstance(attr_data, dict) and attr_data.get("writable"):
                total += 1
        for inst_attrs in (write_info.get("instances") or {}).values():
            if not isinstance(inst_attrs, dict):
                continue
            for attr_data in inst_attrs.values():
                if isinstance(attr_data, dict) and attr_data.get("writable"):
                    total += 1
    return total


def _count_fuzz_crashes(fuzz_results: Dict[str, Any]) -> int:
    """Sum `crashes` across a fuzz_results dict.

    Shape (built by _fuzz_attributes): {class_id: {"class_attributes":
    {attr_id: {"crashes": int}}, "instances": {inst_id: {attr_id:
    {"crashes": int}}}}}. The previous inline sum iterated only the top
    "class_attributes"/"instances" sub-dicts (which carry no `crashes` key),
    so the count was always 0. This walks to the per-attribute leaf dicts.
    """
    total = 0
    for class_results in fuzz_results.values():
        if not isinstance(class_results, dict):
            continue
        for attr_data in (class_results.get("class_attributes") or {}).values():
            if isinstance(attr_data, dict):
                total += attr_data.get("crashes", 0) or 0
        for inst_attrs in (class_results.get("instances") or {}).values():
            if not isinstance(inst_attrs, dict):
                continue
            for attr_data in inst_attrs.values():
                if isinstance(attr_data, dict):
                    total += attr_data.get("crashes", 0) or 0
    return total


class SecurityAnalysisMixin(_ScannerBase):
    """Mixin providing security analysis and reporting for EtherNet/IP."""

    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security configuration"""
        # Check if CIP Security is implemented (from detailed security dump)
        security = results.get("security") or {}
        cip_sec = security.get("cip_security") or {}

        # Determine if security is actually enabled (not just accessible)
        # State 0 = Factory Default (not enabled), State 1+ = configured
        cip_state_raw = cip_sec.get("state_raw", 0)
        has_cip_security = cip_sec.get("accessible", False) and cip_state_raw > 0

        # Check for TLS support in EIP Security
        eip_sec = security.get("eip_security") or {}
        has_tls = eip_sec.get("capabilities_raw", 0) > 0

        # Check authentication methods from password_auth
        auth_methods = []
        if security.get("password_auth"):
            auth_methods.append("password")
        certs = security.get("certificates") or {}
        if certs.get("installed_certificates", 0) > 0:
            auth_methods.append("certificate")

        # access_control: we can only assert this when --write actually ran
        # AND found zero writable attributes. Without --write the dict is
        # empty for an entirely different reason (test wasn't run), so the
        # old `len(...) == 0` gave us a false 'access controlled' verdict
        # whenever the operator didn't pass --write. None means 'unknown'.
        write_test_results = results.get("write_test_results") or {}
        if not write_test_results:
            access_control = None
        else:
            access_control = _count_writable_attrs(write_test_results) == 0

        analysis = SecurityAnalyzer.assess_protocol_security(
            {
                "authentication": len(auth_methods) > 0,
                "authorization": False,  # No built-in authorization
                "encryption": has_tls,
                "integrity_check": has_cip_security,
                "access_control": access_control,
            }
        )

        # Add EtherNet/IP specific security concerns
        analysis["concerns"] = []

        # CIP Security concerns
        if not has_cip_security:
            # Check if it's "not supported" vs "not configured"
            if cip_sec.get("accessible"):
                analysis["concerns"].append(
                    "CIP Security not configured (Factory Default) - no authentication/encryption"
                )
                self.logger.security_finding(
                    "No authentication",
                    detail="CIP Security in Factory Default state",
                )
            else:
                analysis["concerns"].append(
                    "CIP Security not supported - no authentication/encryption"
                )
                self.logger.security_finding(
                    "No authentication",
                    detail="CIP Security not supported",
                )

        if not has_tls:
            analysis["concerns"].append("TLS/DTLS not supported - traffic is unencrypted")
            self.logger.security_finding(
                "No encryption",
                detail="CIP Security (TLS/DTLS) not supported - traffic is unencrypted",
            )

        # Controller mode security concerns
        controller_mode = results.get("controller_mode", {})
        if controller_mode:
            mode = controller_mode.get("mode", "")
            keyswitch = controller_mode.get("keyswitch", "")

            # Check if controller is in an editable mode (PROGRAM or TEST)
            if controller_mode.get("is_editable"):
                analysis["concerns"].append(
                    f"Controller in editable mode ({mode}) - program can be modified"
                )
                self.logger.security_finding(
                    "Insecure configuration",
                    detail=f"Controller in editable mode: {mode}",
                )

            # Check if keyswitch is in REMOTE position (mode changeable via software)
            if controller_mode.get("is_remote"):
                analysis["concerns"].append(
                    f"Remote keyswitch position ({keyswitch}) - mode can be changed via software"
                )
                # This is a configuration concern but may be intentional
                self.logger.debug("Remote keyswitch - software mode changes possible")

            # Check if controller is faulted
            if controller_mode.get("is_faulted"):
                analysis["concerns"].append("Controller has active fault condition")
                self.logger.security_finding(
                    "Insecure configuration",
                    detail="Controller in faulted state - may indicate safety issue",
                )

        # Identity status-based concerns
        identity = results.get("identity", {})
        if identity.get("status_faulted"):
            if "Controller has active fault" not in str(analysis.get("concerns", [])):
                analysis["concerns"].append(
                    f"Device has active fault (status: 0x{identity.get('status', 0):04X})"
                )

        # Writable attributes. The old code did
        # sum(len(attrs) for attrs in write_test_results.values()) which
        # measured "number of keys in each class dict" (always 2 —
        # 'class_attributes' + 'instances'), not "number of writable
        # attributes". So every scan reported `2 × num_classes` writables.
        if results.get("write_test_results"):
            writable_count = _count_writable_attrs(results["write_test_results"])
            if writable_count > 0:
                analysis["concerns"].append(f"{writable_count} writable attributes found")
                self.logger.security_finding(
                    "Writable access",
                    detail=f"{writable_count} CIP attributes are writable",
                )

        # Dangerous tags
        dangerous_tags = results.get("dangerous_tags", [])
        if dangerous_tags:
            high_risk = [t for t in dangerous_tags if t.get("risk") == "high"]
            if high_risk:
                analysis["concerns"].append(
                    f"{len(high_risk)} HIGH-RISK safety tags accessible (ESTOP, SAFETY, EMERGENCY)"
                )
                tag_names = ", ".join([t["tag"] for t in high_risk[:3]])
                self.logger.fail(f"DANGER: {len(high_risk)} safety-critical tags accessible")
                self.logger.security_finding(
                    "Insecure configuration",
                    detail=f"Safety-critical tags accessible: {tag_names}",
                )
            else:
                analysis["concerns"].append(
                    f"{len(dangerous_tags)} potentially dangerous tags accessible"
                )
                tag_names = ", ".join([t["tag"] for t in dangerous_tags[:3]])
                self.logger.security_finding(
                    "Insecure configuration",
                    detail=f"Potentially dangerous tags accessible: {tag_names}",
                )

        # Fuzz results
        if results.get("fuzz_results"):
            crash_count = _count_fuzz_crashes(results["fuzz_results"])
            if crash_count > 0:
                analysis["concerns"].append(f"{crash_count} potential crashes during fuzzing")

        return analysis

    def _report_findings(self, results: Dict[str, Any]) -> None:
        """Report scanner findings"""
        host, port = self.get_target_info()

        # Report host and service
        self.report_host_info(host)
        self.report_service_info(host, port=port, name="ethernetip", proto="tcp")

        # Note: Device identity and CIP Security status already displayed
        # in _list_identity() and _report_security_status()

        # Report dangerous tags
        dangerous_tags = results.get("dangerous_tags", [])
        if dangerous_tags:
            high_risk = [t for t in dangerous_tags if t.get("risk") == "high"]
            if high_risk:
                self.logger.fail(f"DANGER: {len(high_risk)} safety-critical tags accessible:")
                for t in high_risk[:3]:
                    self.logger.fail(f"  - {t['tag']}")

        # Report broadcast discovery results
        broadcast_devices = results.get("broadcast_devices", [])
        if broadcast_devices:
            self.logger.display(f"Broadcast Discovery: {len(broadcast_devices)} device(s) found")
            for dev in broadcast_devices:
                self.logger.display(
                    f"  - {dev.get('ip_address')}: {dev.get('vendor_name')} {dev.get('product_name')}"
                )

        # Report chassis topology / communication ports
        topology = results.get("chassis_topology", {})
        ports = topology.get("ports", [])
        if ports:
            port_types = [p.get("type", "Unknown") for p in ports]
            self.logger.display(f"Communication Ports: {', '.join(port_types)}")

        # Report security concerns
        security_analysis = results.get("security_analysis", {})
        for concern in security_analysis.get("concerns", []):
            self.report_vulnerability(host, "enip_security", description=concern)
