"""
TASE.2 Security Mixin

Handles security analysis and reporting:
- Comprehensive security configuration analysis
- TLS/SSL compliance checks
- Bilateral table access control
- Device control security (CheckBackID, timeouts, tags)
- Data access permissions
- Transfer set security (Critical flag)
- Risk scoring
- Findings reporting
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict

from ....utils import SecurityAnalyzer

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class SecurityMixin(_ScannerBase):
    """Mixin providing TASE.2 security analysis and reporting."""

    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security configuration.

        Security checks include:
        - TLS/SSL compliance
        - Bilateral table access control
        - Device control security (CheckBackID, timeouts, tags)
        - Data access permissions
        - Transfer set security (Critical flag)
        """
        # Count accessible items
        readable_points = sum(1 for p in results.get("data_points", []) if p.get("readable"))
        writable_points = sum(1 for p in results.get("data_points", []) if p.get("writable"))
        control_points = len(results.get("control_points", []))

        # Check for TLS security
        tls_enabled = results.get("tls_enabled", False)
        cert_info = results.get("certificate_info", {})

        analysis = SecurityAnalyzer.assess_protocol_security(
            {
                "authentication": tls_enabled and bool(cert_info),
                "encryption": tls_enabled,
                "authorization": bool(results.get("bilateral_table", {}).get("table_id")),
                "access_control": bool(results.get("bilateral_table", {}).get("table_count")),
            }
        )

        # Initialize security findings
        analysis["concerns"] = []
        analysis["recommendations"] = []
        analysis["iec62351_compliant"] = tls_enabled

        # =====================================================================
        # TLS Security Checks
        # =====================================================================
        if not tls_enabled:
            analysis["concerns"].append("No TLS/SSL - data transmitted in plaintext")
            analysis["recommendations"].append("Enable TLS security")
        else:
            analysis["concerns"].append("TLS enabled")
            if cert_info:
                if cert_info.get("self_signed"):
                    analysis["concerns"].append("TLS certificate is self-signed")
                if cert_info.get("expired"):
                    analysis["concerns"].append("TLS certificate has expired")

        # =====================================================================
        # Bilateral Table Access Control
        # =====================================================================
        blt = results.get("bilateral_table", {})
        if not blt.get("table_id"):
            analysis["concerns"].append("No Bilateral_Table_ID - access control may be disabled")
            analysis["recommendations"].append("Configure bilateral agreement")
        else:
            analysis["bilateral_table_id"] = blt.get("table_id")

        # Check for Access_violation event enrollment
        access_violation_event = results.get("access_violation_event", False)
        if not access_violation_event:
            analysis["recommendations"].append("Enable Access_violation event notification")

        # =====================================================================
        # Data Point Security
        # =====================================================================
        if readable_points > 0:
            analysis["concerns"].append(f"{readable_points} data points accessible for reading")

        if writable_points > 0:
            analysis["concerns"].append(f"CRITICAL: {writable_points} data points are WRITABLE")
            analysis["recommendations"].append("Review write access permissions in bilateral table")

        # =====================================================================
        # Device Control Security
        # =====================================================================
        if control_points > 0:
            analysis["concerns"].append(f"{control_points} device control points discovered")

            # CheckBackID predictability analysis
            check_back_ids = results.get("check_back_ids", [])
            if len(check_back_ids) >= 2:
                # Check if sequential (predictable)
                sorted_ids = sorted(check_back_ids)
                is_sequential = all(
                    sorted_ids[i + 1] - sorted_ids[i] == 1 for i in range(len(sorted_ids) - 1)
                )
                if is_sequential:
                    analysis["concerns"].append(
                        "CheckBackID values appear sequential - may be predictable"
                    )
                    analysis["recommendations"].append("Use randomized CheckBackID values")

        # =====================================================================
        # Device Tag Security
        # =====================================================================
        device_tags = results.get("device_tags", [])
        tagged_devices = [t for t in device_tags if t.get("tag_value") != "NO_TAG"]
        if tagged_devices:
            inhibit_devices = [
                t for t in tagged_devices if t.get("tag_value") == "OPEN_AND_CLOSE_INHIBIT"
            ]
            close_only = [
                t
                for t in tagged_devices
                if t.get("tag_value") in ("CLOSE_ONLY", "CLOSE_ONLY_INHIBIT")
            ]

            if inhibit_devices:
                analysis["concerns"].append(
                    f"{len(inhibit_devices)} device(s) tagged OPEN_AND_CLOSE_INHIBIT "
                    "(fully locked out)"
                )
            if close_only:
                analysis["concerns"].append(
                    f"{len(close_only)} device(s) tagged CLOSE_ONLY (partial lockout)"
                )
        else:
            if control_points > 0:
                analysis["recommendations"].append(
                    "Consider device tagging for critical control points"
                )

        # =====================================================================
        # Conformance Block Security Analysis
        # =====================================================================
        features = results.get("supported_features", self.supported_features)
        if features:
            enabled_blocks = [k for k, v in features.items() if v and k != "block1"]
            analysis["supported_blocks"] = enabled_blocks

            if features.get("block5"):
                analysis["concerns"].append(
                    "Block 5 (Device Control) enabled - remote control operations possible"
                )
                if not tagged_devices and control_points > 0:
                    analysis["recommendations"].append(
                        "Implement device tagging for Block 5 control operations"
                    )

            if features.get("block2"):
                analysis["concerns"].append(
                    "Block 2 (RBE) enabled - automatic data streaming available"
                )

            # Block 4 (Information Messages): delegate to _analyze_im_security so
            # the IM-store risk findings (F18 large-capacity exfiltration, F19
            # write-injection) are emitted alongside the base "enabled" concern.
            # _analyze_im_security already emits the "enabled" line itself and
            # no-ops cleanly when block4 is absent, so this is the single source
            # for every Block 4 concern (no duplicate "enabled" line).
            analysis["concerns"].extend(self._analyze_im_security(results, features))

            if features.get("block11") or features.get("block12"):
                analysis["concerns"].append("Historical data blocks enabled - past data accessible")

        # =====================================================================
        # Transfer Set Security
        # =====================================================================
        transfer_sets = results.get("transfer_sets", [])
        critical_ts = [ts for ts in transfer_sets if ts.get("critical", False)]
        if transfer_sets and not critical_ts:
            analysis["recommendations"].append(
                "Consider enabling Critical flag on transfer sets for acknowledgment"
            )

        # =====================================================================
        # TASE.2 Version Check
        # =====================================================================
        version = results.get("tase2_version", self.tase2_version)
        if version and version.get("major", 0) > 0:
            analysis["tase2_version"] = f"{version['major']}.{version.get('minor', 0):02d}"
            # Version 2000.08 is current per spec
            if version.get("major", 0) < 2000:
                analysis["concerns"].append(
                    f"Outdated TASE.2 version {version['major']} - current is 2000.08"
                )

        # Calculate risk score
        critical_count = sum(1 for c in analysis["concerns"] if "CRITICAL" in c)
        warning_count = sum(1 for c in analysis["concerns"] if "WARNING" in c)
        analysis["risk_score"] = min(
            10, critical_count * 3 + warning_count * 2 + len(analysis["concerns"]) // 2
        )

        return analysis

    def _report_findings(self, results: Dict[str, Any]) -> None:
        """Report scanner findings."""
        host, port = self.get_target_info()

        # Report host and service
        self.report_host_info(host)
        self.report_service_info(host, port=port, name="tase2", proto="tcp")

        # Report bilateral table
        blt = results.get("bilateral_table", {})
        if blt.get("table_id"):
            self.logger.display(f"Bilateral Table: {blt['table_id']}")

        # Report server block enumeration
        server_blocks = results.get("server_blocks", {})
        if server_blocks.get("blocks"):
            total = server_blocks.get("total_supported", 0)
            summary = server_blocks.get("summary", "none")
            self.logger.display(f"Conformance Blocks: {total}/5 ({summary})")

        # Report security concerns
        security = results.get("security_analysis", {})
        for concern in security.get("concerns", []):
            self.report_vulnerability(host, "tase2_security", description=concern)
