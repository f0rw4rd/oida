"""
HL7 Security Mixin

Handles security analysis:
- Authentication assessment
- Access control evaluation
- Encryption status checking
"""

from oida.protocols.hl7.mixins._helpers import ack_accepted


class SecurityMixin:
    """Mixin providing HL7 security analysis."""

    def _analyze_security(self):
        """Analyze HL7 endpoint security"""
        issues = []

        # HL7 has no native authentication
        issues.append(
            {
                "flag": "AUTH",
                "issue": "No Authentication",
                "description": "HL7 v2 MLLP has no native authentication mechanism",
                "recommendation": "Implement network-level controls (VPN, firewall, VLANs)",
            }
        )

        # Check if endpoint accepts any message
        if ack_accepted(self.results["data"].get("ack_code")):
            issues.append(
                {
                    "flag": "ACCESS",
                    "issue": "Accepts Unknown Sender",
                    "description": "Endpoint accepted message from unknown sending application",
                    "recommendation": "Configure application-level sender validation",
                }
            )

        # No encryption
        if not getattr(self.args, "tls", False):
            issues.append(
                {
                    "flag": "CRYPTO",
                    "issue": "Unencrypted Communication",
                    "description": "MLLP traffic transmitted in plaintext (PHI exposure risk)",
                    "recommendation": "Use MLLP over TLS or VPN tunnel",
                }
            )

        self.results["data"]["security_issues"] = issues

        # Report findings with category flags (similar to DICOM's [PHI], [PRIV])
        for issue in issues:
            self.logger.warning(f"[{issue['flag']}] {issue['issue']}: {issue['description']}")
