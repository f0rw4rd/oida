"""TLS/SSL helper utilities for protocol scanners.

Provides shared TLS context creation and certificate checking used
across multiple protocol implementations.
"""

import socket
import ssl
from typing import Optional, Any


def build_tls_context(
    args: dict,
    logger: Any = None,
) -> ssl.SSLContext:
    """Build an SSL context for security testing from standard TLS args.

    Central function for all protocols to create TLS contexts. Never validates
    certificates (ICS devices rarely have proper PKI). Supports optional client
    certificate for mutual TLS.

    Reads standard args from ``add_tls_options()``:
        - ``tls-cert``: Client certificate file path
        - ``tls-key``: Client private key file path

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
                    from .security_findings import display_cert_info

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
