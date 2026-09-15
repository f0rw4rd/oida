"""
FHIR R4 NXC-Style Connection Class

Provides the NXC-style callable fhir class that auto-executes
on instantiation, following the NetExec pattern.

The class uses mixins to organize functionality into logical groups:
- SearchMixin: Resource search and display for all FHIR types
- SecurityMixin: Auth testing, brute force, security analysis
- CRUDMixin: Create, update, delete operations
"""

import json
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from ...connection import NetworkConnection

from .helpers import (
    FHIR_SECURITY_MODES,
    FHIR_VENDOR_MAP,
    _get_fhir_validation_error,
    capabilitystatement,
    fhirclient,
    is_fhirclient_available,
    validate_credential_path,
)
from .mixins import CRUDMixin, SearchMixin, SecurityMixin


class fhir(SearchMixin, SecurityMixin, CRUDMixin, NetworkConnection):
    """FHIR R4 REST API Scanner (NXC-style)

    Inherits from mixins providing modular functionality groups.
    """

    def __init__(self, args: Any, db: Optional[Any], host: str):
        self.protocol_name = "fhir"
        self.default_port = 443  # FHIR servers typically use HTTPS
        self.smart_client = None
        self.conn = None  # Initialize early for cleanup

        super().__init__(args, db, host)

    def _get_base_url(self) -> str:
        """Get FHIR base URL from target"""
        target = self.host

        # An explicit scheme in the target always wins, so an https:// target is
        # never downgraded to cleartext (and an http:// target is honored as-is).
        if target.startswith("http://") or target.startswith("https://"):
            return target.rstrip("/")

        port = getattr(self.args, "port", self.default_port)
        # FHIR is HTTPS-by-default: proto_args sets --tls default True (with an
        # explicit --no-tls opt-out), matching default_port 443. The getattr
        # fallback mirrors that default so a bare-hostname target is not silently
        # scanned over cleartext HTTP.
        use_tls = getattr(self.args, "tls", True)

        scheme = "https" if use_tls else "http"

        # Only append a genuinely non-standard port. The FHIR CLI has no --port
        # flag (so from the CLI `port` is always default_port=443 and this branch
        # is inert), but a library caller may set args.port; honour it, while
        # avoiding a spurious ":443"/":80" on the standard scheme.
        if port and port not in (80, 443):
            return f"{scheme}://{target}:{port}"

        return f"{scheme}://{target}"

    def proto_flow(self):
        """Main FHIR scanning workflow"""

        # Check dependencies
        if not is_fhirclient_available():
            self.logger.fail(
                "fhirclient library not available. Install with: pip install oida-ics[fhir]"
            )
            self.results["error"] = "fhirclient not installed"
            return

        # Handle --enum-all as alias for all enumeration options
        if getattr(self.args, "enum_all", False):
            self.args.search_patients = True
            self.args.search_observations = True
            self.args.search_medications = True
            self.args.search_conditions = True
            self.args.search_encounters = True
            self.args.search_procedures = True
            self.args.search_allergies = True
            self.args.search_immunizations = True
            self.args.search_diagnostics = True
            self.args.search_documents = True
            self.args.search_practitioners = True
            self.args.search_organizations = True
            self.args.search_locations = True
            self.args.search_devices = True
            self.args.search_orders = True

        # Create connection
        if not self.create_conn_obj():
            return

        # Enumerate host info (CapabilityStatement)
        if not self.enum_host_info():
            return

        self.print_host_info()

        # Display full CapabilityStatement if --caps flag is set
        if getattr(self.args, "caps", False):
            cap_json = self.results.get("data", {}).get("capability_statement")
            if cap_json:
                self.logger.display("\nCapabilityStatement (full JSON):")
                self.logger.display(json.dumps(cap_json, indent=2, default=str))
            else:
                self.logger.warning("CapabilityStatement not available")

        # Resource search operations
        if getattr(self.args, "search_patients", False):
            self._search_patients()

        if getattr(self.args, "search_observations", False):
            self._search_observations()

        if getattr(self.args, "search_medications", False):
            self._search_medications()

        if getattr(self.args, "search_conditions", False):
            self._search_conditions()

        if getattr(self.args, "search_encounters", False):
            self._search_encounters()

        if getattr(self.args, "search_procedures", False):
            self._search_procedures()

        if getattr(self.args, "search_allergies", False):
            self._search_allergies()

        if getattr(self.args, "search_immunizations", False):
            self._search_immunizations()

        if getattr(self.args, "search_diagnostics", False):
            self._search_diagnostic_reports()

        if getattr(self.args, "search_documents", False):
            self._search_documents()

        # Additional resource searches
        if getattr(self.args, "search_practitioners", False):
            self._search_practitioners()

        if getattr(self.args, "search_organizations", False):
            self._search_organizations()

        if getattr(self.args, "search_locations", False):
            self._search_locations()

        if getattr(self.args, "search_devices", False):
            self._search_devices()

        if getattr(self.args, "search_orders", False):
            self._search_orders()

        # Read specific resource by ID
        if getattr(self.args, "read_patient", None):
            self._read_resource("Patient", self.args.read_patient)

        if getattr(self.args, "read_observation", None):
            self._read_resource("Observation", self.args.read_observation)

        if getattr(self.args, "read_medication", None):
            self._read_resource("MedicationRequest", self.args.read_medication)

        if getattr(self.args, "read_condition", None):
            self._read_resource("Condition", self.args.read_condition)

        if getattr(self.args, "read_encounter", None):
            self._read_resource("Encounter", self.args.read_encounter)

        # Security testing
        if getattr(self.args, "test_auth", False):
            self._test_authentication()

        if getattr(self.args, "test_cross_patient", False):
            self._test_cross_patient_access()

        if getattr(self.args, "test_scope", False):
            self._test_scope_bypass()

        # Write operations (require --confirm)
        if getattr(self.args, "create_patient", False):
            self._create_patient()

        if getattr(self.args, "update_patient", None):
            self._update_patient()

        if getattr(self.args, "delete_patient", None):
            self._delete_patient()

        if getattr(self.args, "create_observation", False):
            self._create_observation()

        # Brute force credential testing
        if getattr(self.args, "brute", False) or getattr(self.args, "default_creds", False):
            self._brute_force_credentials()

        # Analyze security
        self._analyze_security()

        # Export results
        self._export_results()

        # Cleanup
        self._disconnect()

    def _apply_session_config(self, client, timeout: Optional[float] = None) -> None:
        """Apply timeout + TLS session settings to a FHIRClient's requests session.

        Shared by create_conn_obj() and SecurityMixin._test_authentication()'s
        ad-hoc probe clients, so every FHIRClient this scanner builds honors
        --timeout/--tls-cert/--tls-key/--tls-insecure/--tls-ca instead of a probe
        silently using unbounded default timeouts or unconfigured cert
        verification against a self-signed/private-CA target.
        """
        if not (hasattr(client, "server") and client.server):
            return

        from requests.adapters import HTTPAdapter

        class TimeoutHTTPAdapter(HTTPAdapter):
            def __init__(self, timeout=30, *args, **kwargs):
                self.timeout = timeout
                super().__init__(*args, **kwargs)

            def send(self, request, **kwargs):
                kwargs.setdefault("timeout", self.timeout)
                return super().send(request, **kwargs)

        if timeout is None:
            timeout = getattr(self.args, "timeout", 30)

        adapter = TimeoutHTTPAdapter(timeout=timeout)
        session = client.server.session
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Mutual-TLS client cert/key. validate_credential_path blocks
        # directory traversal and resolves to an absolute path. requests
        # accepts either a combined cert+key file (cert="...") or a
        # (cert, key) tuple when supplied separately.
        tls_cert = getattr(self.args, "tls_cert", None)
        tls_key = getattr(self.args, "tls_key", None)
        if tls_cert:
            cert_path = validate_credential_path(tls_cert)
            if tls_key:
                session.cert = (cert_path, validate_credential_path(tls_key))
            else:
                session.cert = cert_path

        # Verification precedence: --tls-insecure disables verification
        # outright; otherwise a --tls-ca bundle overrides the default
        # trust store for server-certificate verification.
        if getattr(self.args, "tls_insecure", False):
            session.verify = False
        else:
            tls_ca = getattr(self.args, "tls_ca", None)
            if tls_ca:
                session.verify = validate_credential_path(tls_ca)

    def create_conn_obj(self) -> bool:
        """Create FHIR client connection"""
        base_url = self._get_base_url()
        timeout = getattr(self.args, "timeout", 30)

        self.logger.info(f"Connecting to {base_url}")

        try:
            settings = {
                "app_id": "oida_fhir_scanner",
                "api_base": base_url,
            }

            token = getattr(self.args, "token", None)
            if token:
                settings["access_token"] = token.replace("Bearer ", "")

            self.smart_client = fhirclient.FHIRClient(settings=settings)

            if hasattr(self.smart_client, "server") and self.smart_client.server:
                self._apply_session_config(self.smart_client, timeout=timeout)
                session = self.smart_client.server.session

                username = getattr(self.args, "username", None)
                password = getattr(self.args, "password", None)
                if username and password and not getattr(self.args, "brute", False):
                    from requests.auth import HTTPBasicAuth

                    session.auth = HTTPBasicAuth(username, password)

            self.logger.info(f"Configured FHIR client for {base_url}")

            if base_url.startswith("https://"):
                self._check_tls_certificate(base_url)

            self.conn = self.smart_client
            self.results["data"]["base_url"] = base_url
            self.results["data"]["tls_enabled"] = base_url.startswith("https://")
            return True

        except Exception as e:
            self.logger.debug("Connection setup failed: %s", e)
            self.logger.fail(f"Connection failed: {e}")
            self.results["data"]["connected"] = False
            self.results["error"] = str(e)
            return False

    def _check_tls_certificate(self, url: str):
        """Check TLS certificate for security issues"""
        from ...utils.socket_helpers import check_tls_certificate

        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        # Snapshot the slice of the shared logger.findings accumulator that the
        # certificate probe contributes, so _analyze_security can pull only the
        # cert findings instead of relabeling every accumulated finding (auth,
        # brute force, ...) as CERTIFICATE.
        cert_start_idx = len(self.logger.findings)

        check_tls_certificate(
            host=hostname,
            port=port,
            logger=self.logger,
            protocol="fhir",
            timeout=10,
            verbose=getattr(self.args, "verbose", 0) > 0,
        )

        self._cert_findings = list(self.logger.findings[cert_start_idx:])

    def enum_host_info(self) -> bool:
        """Retrieve and parse CapabilityStatement. Returns False on fatal errors."""
        FHIRValidationError = _get_fhir_validation_error()
        try:
            cap_stmt = capabilitystatement.CapabilityStatement.read_from(
                "metadata", self.smart_client.server
            )

            # Reachability is only proven once the /metadata round-trip succeeds;
            # mark the connection live here rather than at client-construction time.
            self.results["data"]["connected"] = True
            self.logger.success(f"Connected to FHIR endpoint: {self._get_base_url()}")

            # Cleartext gate: emit only when this confirmed-reachable endpoint was
            # reached over plain HTTP (not HTTPS/TLS). tls_enabled is set in
            # create_conn_obj() from base_url.startswith("https://").
            if not self.results["data"].get("tls_enabled", True):
                self.logger.security_finding(
                    "No encryption",
                    detail="FHIR server accessed over HTTP -- PHI transmitted in cleartext (no TLS)",
                )

            try:
                self.results["data"]["capability_statement"] = cap_stmt.as_json()
            except Exception as e:
                self.logger.debug(f"Failed to serialize CapabilityStatement: {e}")

            server_info = {
                "fhir_version": cap_stmt.fhirVersion if hasattr(cap_stmt, "fhirVersion") else None,
                "software_name": None,
                "software_version": None,
                "publisher": cap_stmt.publisher if hasattr(cap_stmt, "publisher") else None,
                "implementation_description": None,
                "implementation_url": None,
                "vendor": None,
                "product_type": None,
            }

            if hasattr(cap_stmt, "software") and cap_stmt.software:
                server_info["software_name"] = cap_stmt.software.name
                server_info["software_version"] = cap_stmt.software.version

            if hasattr(cap_stmt, "implementation") and cap_stmt.implementation:
                server_info["implementation_description"] = cap_stmt.implementation.description
                server_info["implementation_url"] = cap_stmt.implementation.url

            software_name = server_info["software_name"] or ""
            publisher = server_info["publisher"] or ""
            vendor, product = self._identify_vendor(software_name, publisher)
            server_info["vendor"] = vendor
            server_info["product_type"] = product

            supported_resources = []
            if hasattr(cap_stmt, "rest") and cap_stmt.rest:
                for rest in cap_stmt.rest:
                    if hasattr(rest, "resource") and rest.resource:
                        for res in rest.resource:
                            resource_info = {
                                "type": res.type,
                                "interactions": [],
                                "search_params": [],
                            }
                            if hasattr(res, "interaction") and res.interaction:
                                resource_info["interactions"] = [
                                    i.code for i in res.interaction if hasattr(i, "code")
                                ]
                            if hasattr(res, "searchParam") and res.searchParam:
                                resource_info["search_params"] = [
                                    p.name for p in res.searchParam if hasattr(p, "name")
                                ]
                            supported_resources.append(resource_info)

            server_info["supported_resources"] = supported_resources
            server_info["resource_count"] = len(supported_resources)

            security_info = self._parse_security_info(cap_stmt)
            server_info["security"] = security_info

            self.results["data"]["server_info"] = server_info
            return True

        except FHIRValidationError as e:
            # The /metadata body was received; only schema validation failed, so the
            # endpoint is reachable. Mark connected (it is not set when read_from raises).
            self.results["data"]["connected"] = True
            self.logger.debug(f"CapabilityStatement validation warning: {e}")
            self.results["data"]["server_info"] = {"error": "Partial CapabilityStatement"}
            return True

        except Exception as e:
            error_str = str(e)
            if "404" in error_str or "Response [404]" in error_str:
                self.logger.fail(f"FHIR endpoint not found (404): {self._get_base_url()}")
                self.results["data"]["server_info"] = {"error": "Endpoint not found (404)"}
                self.results["error"] = "FHIR endpoint not found"
                return False

            if "Connection refused" in error_str or "NewConnectionError" in error_str:
                self.logger.fail(f"Connection refused: {self._get_base_url()}")
                self.results["data"]["server_info"] = {"error": "Connection refused"}
                self.results["error"] = "Connection refused"
                return False

            self.logger.warning(f"Failed to get CapabilityStatement: {e}")
            self.results["data"]["server_info"] = {"error": str(e)}
            return True

    def _parse_security_info(self, cap_stmt) -> Dict[str, Any]:
        """Parse security information from CapabilityStatement"""
        security_info = {
            "cors_enabled": False,
            "security_services": [],
            "oauth_endpoints": {},
            "description": None,
        }

        try:
            if hasattr(cap_stmt, "rest") and cap_stmt.rest:
                for rest in cap_stmt.rest:
                    if hasattr(rest, "security") and rest.security:
                        sec = rest.security

                        if hasattr(sec, "cors"):
                            security_info["cors_enabled"] = sec.cors

                        if hasattr(sec, "description"):
                            security_info["description"] = sec.description

                        if hasattr(sec, "service") and sec.service:
                            for svc in sec.service:
                                if hasattr(svc, "coding") and svc.coding:
                                    for coding in svc.coding:
                                        svc_info = {
                                            "system": getattr(coding, "system", None),
                                            "code": getattr(coding, "code", None),
                                            "display": getattr(coding, "display", None),
                                        }
                                        security_info["security_services"].append(svc_info)

                        if hasattr(sec, "extension") and sec.extension:
                            for ext in sec.extension:
                                if ext.url and "oauth-uris" in ext.url:
                                    if hasattr(ext, "extension"):
                                        for inner_ext in ext.extension:
                                            url = getattr(inner_ext, "url", None)
                                            uri = getattr(inner_ext, "valueUri", None)
                                            if url and uri:
                                                security_info["oauth_endpoints"][url] = uri

        except Exception as e:
            self.logger.debug(f"Failed to parse security info: {e}")

        return security_info

    def _identify_vendor(self, software_name: str, publisher: str) -> tuple:
        """Identify vendor from software name or publisher"""
        if not software_name and not publisher:
            return (None, None)

        name_upper = (software_name or "").upper().strip()
        publisher_upper = (publisher or "").upper().strip()

        for key, (vendor, product) in FHIR_VENDOR_MAP.items():
            if key in name_upper:
                return (vendor, product)

        for key, (vendor, product) in FHIR_VENDOR_MAP.items():
            if key in publisher_upper:
                return (vendor, product)

        return (None, None)

    def print_host_info(self):
        """Display discovered FHIR endpoint info"""
        data = self.results.get("data", {})
        server_info = data.get("server_info", {})

        if "error" in server_info:
            self.logger.warning(f"  Server info incomplete: {server_info.get('error')}")
            return

        software = server_info.get("software_name", "Unknown")
        version = server_info.get("software_version", "")
        vendor = server_info.get("vendor")
        product = server_info.get("product_type")

        if vendor:
            self.logger.display(f"  Server: {software} {version} ({vendor} - {product})")
        else:
            self.logger.display(f"  Server: {software} {version}")

        fhir_version = server_info.get("fhir_version", "Unknown")
        self.logger.display(f"  FHIR Version: {fhir_version}")

        publisher = server_info.get("publisher")
        if publisher:
            self.logger.display(f"  Publisher: {publisher}")

        resource_count = server_info.get("resource_count", 0)
        self.logger.display(f"  Supported Resources: {resource_count}")

        security = server_info.get("security", {})
        services = security.get("security_services", [])
        if services:
            service_names = []
            for svc in services:
                if not svc:
                    continue
                # Prefer the human-readable mode description keyed by
                # "<system>|<code>" (see FHIR_SECURITY_MODES), then fall back
                # to the server-supplied display / raw code.
                system = svc.get("system") or ""
                code = svc.get("code") or ""
                mode = FHIR_SECURITY_MODES.get(f"{system}|{code}") or FHIR_SECURITY_MODES.get(code)
                service_names.append(mode or svc.get("display") or code)
            self.logger.display(f"  Security: {', '.join(filter(None, service_names))}")
        else:
            self.logger.security_finding(
                "No authentication",
                detail="No security services configured (anonymous access)",
            )

        if security.get("cors_enabled"):
            self.logger.display("  CORS: Enabled")

    def _export_results(self):
        """Export results to file if requested"""
        self._save_response_if_requested(self.results.get("data", {}))

        output_dir = getattr(self.args, "output", None)
        if not output_dir:
            return

        export_format = getattr(self.args, "format", "json")

        try:
            if "json" in export_format.lower() or export_format.lower() == "all":
                from oida.utils.export_utils import export_json

                safe_host = self.host.replace("/", "_").replace(":", "_")
                export_json(self.results, output_dir, f"fhir_{safe_host}.json", logger=self.logger)

            if (
                "csv" in export_format.lower() or export_format.lower() == "all"
            ) and self.results.get("data", {}).get("patients", {}).get("records"):
                from ...utils.export_utils import export_data

                patients = self.results["data"]["patients"]["records"]
                headers = ["id", "name", "birth_date", "gender", "phone", "address"]
                rows = [[p.get(h, "") for h in headers] for p in patients]
                export_data(
                    rows,
                    headers,
                    output_format="csv",
                    output_dir=output_dir,
                    filename_prefix="fhir_patients",
                    logger=self.logger,
                )

        except Exception as e:
            self.logger.warning(f"Failed to export results: {e}")

    def _disconnect(self):
        """Cleanup connection"""
        self.smart_client = None
        self.conn = None
