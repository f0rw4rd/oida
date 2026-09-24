"""TLS/SSL helper utilities for protocol scanners.

Provides shared TLS context creation, certificate checking, and local-IP
detection used across multiple protocol implementations.
"""

import socket
import ssl
from typing import Optional, Any, Tuple


def get_local_ip(target_host: str, fallback: str = "127.0.0.1") -> Tuple[str, Optional[Exception]]:
    """Detect the local IP that would be used to reach ``target_host``.

    Uses the standard "UDP connect trick" — connecting a UDP socket does not
    send any packets, but populates the local-address tuple based on the
    routing table for the target. Avoids guessing or hard-coded fallbacks.

    The previous BACnet helper used ``socket.connect(("8.8.8.8", 80))`` to
    detect the local IP — that breaks offline, leaks scan activity to Google,
    and may be inappropriate in air-gapped ICS environments. This helper
    routes against the actual target instead, so it works on disconnected
    lab networks.

    Args:
        target_host: Host the scanner will talk to (used as the routing target).
        fallback: IP to return when detection fails (e.g. offline, no route).

    Returns:
        ``(local_ip, error)`` where ``error`` is ``None`` on success and the
        underlying exception when the fallback was used.
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_host, 1))
        return s.getsockname()[0], None
    except OSError as exc:
        return fallback, exc
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def build_tls_context(
    args: dict,
    logger: Any = None,
) -> ssl.SSLContext:
    """Build an SSL context for security testing from standard TLS args.

    Central function for all protocols to create TLS contexts. By default it
    does not validate certificates (ICS devices rarely have proper PKI), but a
    caller-supplied CA via ``tls-ca`` enables proper server verification — as
    required for IEC 62351-style mTLS deployments. Supports an optional client
    certificate for mutual TLS.

    Reads standard args from ``add_tls_options()``:
        - ``tls-cert``: Client certificate file path
        - ``tls-key``: Client private key file path
        - ``tls-ca``: CA certificate file path (enables server verification)
        - ``tls-insecure``: Skip server verification even if a CA is given

    Args:
        args: Protocol args dict (hyphenated keys from ``add_tls_options``)
        logger: Optional logger with ``.display()`` and ``.fail()`` methods

    Returns:
        SSL context configured for security testing
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    tls_cert = args.get("tls-cert")
    tls_key = args.get("tls-key")
    tls_ca = args.get("tls-ca")
    tls_insecure = args.get("tls-insecure")

    # A CA bundle enables real server-certificate verification (mTLS). Skip it
    # when --tls-insecure is set so operators can still probe broken/self-signed
    # endpoints without removing the CA flag.
    if tls_ca and not tls_insecure:
        try:
            context.load_verify_locations(cafile=tls_ca)
            context.verify_mode = ssl.CERT_REQUIRED
            # A pinned CA is meaningless without hostname/SAN matching: otherwise
            # any cert chaining to the trusted CA passes, allowing MITM. Enable
            # hostname verification (verify_mode is already CERT_REQUIRED here, so
            # this is a legal transition). Callers must pass the DNS name (or an IP
            # present in the cert's SAN) as ``server_hostname``.
            context.check_hostname = True
            if logger:
                logger.display(f"Verifying server certificate against CA: {tls_ca}")
        except Exception as e:
            if logger:
                logger.fail(f"Failed to load CA certificate: {e}")

    if tls_cert:
        try:
            context.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
            if logger:
                logger.display(f"Using client certificate: {tls_cert}")
        except Exception as e:
            if logger:
                logger.fail(f"Failed to load client certificate: {e}")

    return context


def check_tls_certificate(
    host: str,
    port: int,
    logger: Any,
    protocol: str = "tls",
    timeout: int = 10,
    verbose: bool = False,
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
    **kwargs,
) -> Optional[dict]:
    """Probe a TLS endpoint and check the server certificate.

    Performs a lightweight TLS handshake (no validation) to retrieve the peer
    certificate, then runs security checks via ``display_cert_info``. Useful
    when the protocol library handles TLS internally (e.g. c104/mbedtls) and
    doesn't expose the peer certificate to Python.

    Args:
        host: Target hostname or IP
        port: Target port
        logger: ICSLogger with ``.display()``, ``.warning()``, ``.security_finding()`` methods
        protocol: Protocol name for findings (e.g. "iec104", "modbus")
        timeout: Connection timeout in seconds
        verbose: Show detailed certificate chain/extensions info
        certfile: Optional client certificate for mutual TLS endpoints
        keyfile: Optional client private key for mutual TLS endpoints

    Returns:
        Certificate info dict with 'issues' key, or None on failure
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if certfile and keyfile:
            ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    from oida.utils.security_findings import display_cert_info

                    return display_cert_info(
                        logger=logger,
                        cert=cert_der,
                        protocol=protocol,
                        target=f"{host}:{port}",
                        verbose=verbose,
                    )
                else:
                    logger.debug("No peer certificate available")
                    return None
    except Exception as e:
        logger.debug(f"TLS certificate probe failed: {e}")
        return None
