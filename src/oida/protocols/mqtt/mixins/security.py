"""
MQTT Security Mixin

Handles security analysis and finding reporting.
"""

from typing import Any, Dict, List


class SecurityMixin:
    """Mixin providing MQTT security analysis."""

    def _analyze_security(self, results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Analyze security issues"""
        issues = []

        # Anonymous auth
        if results.get("auth", {}).get("anonymous_allowed"):
            issues.append(
                {
                    "issue": "Anonymous authentication enabled",
                    "description": "Broker accepts connections without credentials",
                }
            )
            self.logger.security_finding(
                "Anonymous access",
                detail="Anonymous authentication allowed",
            )

        # $SYS exposure
        sys_count = results.get("broker_info", {}).get("sys_topic_count", 0)
        if sys_count > 0:
            issues.append(
                {
                    "issue": f"$SYS topics exposed ({sys_count} topics)",
                    "description": "Broker system information is readable",
                }
            )
            self.logger.security_finding(
                "Insecure configuration",
                detail=f"$SYS topics exposed ({sys_count} topics)",
            )

        # Wildcard subscriptions
        topic_count = len(results.get("topics", []))
        if "#" in self.topics_pattern and topic_count > 0:
            issues.append(
                {
                    "issue": f"Wildcard subscriptions allowed ({topic_count} topics)",
                    "description": f"Wildcard subscription (#) allowed - {topic_count} topics readable",
                }
            )
            self.logger.security_finding(
                "Insecure configuration",
                detail=f"Wildcard subscriptions allowed ({topic_count} topics)",
            )

        # Weak credentials found
        if results.get("auth", {}).get("brute_results", {}).get("valid"):
            valid_creds = results["auth"]["brute_results"]["valid"]
            issues.append(
                {
                    "issue": "Weak credentials detected",
                    "description": f"Found {len(valid_creds)} valid credential pairs",
                }
            )
            for cred in valid_creds:
                self.logger.security_finding(
                    "Default credentials",
                    detail=f"Username: {cred.get('username', 'unknown')}",
                )

        # No TLS
        if not self.use_tls:
            issues.append(
                {
                    "issue": "Plaintext communication",
                    "description": "Connection is not encrypted (no TLS)",
                }
            )
            self.logger.security_finding(
                "No encryption",
                detail="Communication is unencrypted",
            )

        return issues
