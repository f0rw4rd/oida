"""
Authentication Transformers

This module provides transformers for HTTP authentication schemes:
Basic Auth, Bearer tokens, JWT, and Digest authentication.

These transformers handle the encoding and credential formatting required
by various authentication mechanisms, enabling proper fuzzing of auth headers.
"""

import hmac
import hashlib
import json
import time
from typing import Dict, Optional, Any
from .base import BaseTransformer
from .encoding import Base64Transformer

import logging

logger = logging.getLogger(__name__)


class BasicAuthTransformer(BaseTransformer):
    """
    HTTP Basic Authentication transformer (RFC 7617).

    Formats credentials as "username:password" and Base64-encodes them.
    Optionally adds "Basic " prefix for Authorization header.

    Common use:
    - Authorization: Basic <base64(username:password)>

    Example:
        >>> transformer = BasicAuthTransformer(prefix=b"Basic ")
        >>> # Input: b"admin\\x00:password123"
        >>> transformer.encode(b"admin:password123")
        b'Basic YWRtaW46cGFzc3dvcmQxMjM='

    Usage with boofuzz:
        >>> Block("Authorization", encoder=BasicAuthTransformer(prefix=b"Basic ").to_encoder_func(),
        ...       children=(
        ...           SmartString("username", "admin"),
        ...           Delim(":", ":"),
        ...           SmartString("password", "password123"),
        ...       ))
    """

    def __init__(self, prefix: bytes = b"Basic ", add_header: bool = False):
        """
        Initialize Basic Auth transformer.

        Args:
            prefix: Prefix before base64 (typically "Basic ")
            add_header: If True, prepend "Authorization: "

        Example:
            >>> # Just the encoded value
            >>> BasicAuthTransformer(prefix=b"")

            >>> # Full header
            >>> BasicAuthTransformer(add_header=True)
        """
        self.prefix = prefix
        self.add_header = add_header
        self.base64 = Base64Transformer()

    def encode(self, data: bytes) -> bytes:
        """Encode credentials to Basic Auth format"""
        # Base64 encode the credentials
        encoded = self.base64.encode(data)

        # Add prefix (e.g., "Basic ")
        result = self.prefix + encoded

        # Optionally add header name
        if self.add_header:
            result = b"Authorization: " + result

        return result

    def decode(self, data: bytes) -> bytes:
        """Decode Basic Auth to credentials"""
        # Remove header if present
        if self.add_header:
            data = data.removeprefix(b"Authorization: ")

        # Remove prefix
        data = data.removeprefix(self.prefix)

        # Base64 decode
        return self.base64.decode(data)

    @property
    def name(self) -> str:
        return "BasicAuth"


class BearerTokenTransformer(BaseTransformer):
    """
    HTTP Bearer Token transformer (RFC 6750).

    Formats tokens with "Bearer " prefix for Authorization header.
    Used for OAuth 2.0 access tokens and API keys.

    Common use:
    - Authorization: Bearer <token>

    Example:
        >>> transformer = BearerTokenTransformer()
        >>> transformer.encode(b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        b'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'

    Usage with boofuzz:
        >>> Block("Authorization", encoder=BearerTokenTransformer().to_encoder_func(),
        ...       children=(
        ...           SmartString("token", "my_api_token_12345", max_len=1024),
        ...       ))
    """

    def __init__(self, prefix: bytes = b"Bearer ", add_header: bool = False):
        """
        Initialize Bearer Token transformer.

        Args:
            prefix: Prefix before token (typically "Bearer ")
            add_header: If True, prepend "Authorization: "
        """
        self.prefix = prefix
        self.add_header = add_header

    def encode(self, data: bytes) -> bytes:
        """Format token with Bearer prefix"""
        result = self.prefix + data

        if self.add_header:
            result = b"Authorization: " + result

        return result

    def decode(self, data: bytes) -> bytes:
        """Extract token from Bearer format"""
        if self.add_header:
            data = data.removeprefix(b"Authorization: ")

        return data.removeprefix(self.prefix)

    @property
    def name(self) -> str:
        return "BearerToken"


class JWTTransformer(BaseTransformer):
    """
    JSON Web Token (JWT) transformer (RFC 7519).

    Creates JWT tokens with header, payload, and HMAC signature.
    Supports multiple algorithms: HS256, HS384, HS512, and 'none' (insecure).

    JWT Structure: <header>.<payload>.<signature>
    Each part is Base64URL-encoded JSON.

    Common uses:
    - Authorization: Bearer <JWT>
    - API authentication
    - Session tokens

    Security Testing:
    - Algorithm confusion attacks (RS256 → HS256)
    - None algorithm bypass (alg=none)
    - Claim injection (iss, sub, aud, exp tampering)
    - Signature stripping
    - Key confusion

    Example:
        >>> transformer = JWTTransformer(
        ...     secret_key=b"my_secret",
        ...     algorithm="HS256"
        ... )
        >>> # Input data used as payload "sub" claim
        >>> transformer.encode(b"user123")
        b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0...'

    Advanced Example - Custom Claims:
        >>> transformer = JWTTransformer(
        ...     secret_key=b"secret",
        ...     algorithm="HS256",
        ...     custom_payload={
        ...         "sub": "admin",
        ...         "role": "superuser",
        ...         "exp": int(time.time()) + 3600
        ...     }
        ... )
        >>> transformer.encode(b"ignored")  # custom_payload takes precedence
    """

    # Supported HMAC algorithms
    ALGORITHMS = {
        "HS256": lambda key, data: hmac.new(key, data, hashlib.sha256).digest(),
        "HS384": lambda key, data: hmac.new(key, data, hashlib.sha384).digest(),
        "HS512": lambda key, data: hmac.new(key, data, hashlib.sha512).digest(),
        "none": lambda key, data: b"",  # No signature (security vulnerability test)
    }

    def __init__(
        self,
        secret_key: bytes = b"secret",
        algorithm: str = "HS256",
        custom_header: Optional[Dict[str, Any]] = None,
        custom_payload: Optional[Dict[str, Any]] = None,
        add_bearer: bool = False,
    ):
        """
        Initialize JWT transformer.

        Args:
            secret_key: HMAC signing key
            algorithm: Signing algorithm (HS256, HS384, HS512, none)
            custom_header: Custom JWT header dict (overrides default)
            custom_payload: Custom JWT payload dict (input data ignored if set)
            add_bearer: If True, prefix with "Bearer "

        Example - Algorithm Confusion Attack:
            >>> # Test 'none' algorithm bypass
            >>> JWTTransformer(algorithm='none')

        Example - Custom Claims:
            >>> JWTTransformer(
            ...     custom_payload={
            ...         "sub": "admin",
            ...         "role": "admin",
            ...         "exp": 9999999999  # Far future
            ...     }
            ... )
        """
        self.secret_key = secret_key if isinstance(secret_key, bytes) else secret_key.encode()
        self.algorithm = algorithm
        self.custom_header = custom_header
        self.custom_payload = custom_payload
        self.add_bearer = add_bearer
        self.base64url = Base64Transformer(urlsafe=True, strip_padding=True)

        if algorithm not in self.ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm: {algorithm}. Supported: {list(self.ALGORITHMS.keys())}"
            )

    def encode(self, data: bytes) -> bytes:
        """
        Create JWT token.

        Args:
            data: Used as payload "sub" claim if custom_payload not set

        Returns:
            JWT token: <header>.<payload>.<signature>
        """
        # Build header
        header = self.custom_header or {"alg": self.algorithm, "typ": "JWT"}
        header_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
        header_b64 = self.base64url.encode(header_json)

        # Build payload
        if self.custom_payload:
            payload = self.custom_payload
        else:
            # Use input data as "sub" claim
            try:
                sub = data.decode("utf-8")
            except UnicodeDecodeError:
                sub = data.decode("latin-1")

            payload = {
                "sub": sub,
                "iat": int(time.time()),  # Issued at
            }

        payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        payload_b64 = self.base64url.encode(payload_json)

        # Build signature
        signing_input = header_b64 + b"." + payload_b64

        if self.algorithm == "none":
            # No signature for 'none' algorithm
            signature_b64 = b""
        else:
            signature_raw = self.ALGORITHMS[self.algorithm](self.secret_key, signing_input)
            signature_b64 = self.base64url.encode(signature_raw)

        # Assemble JWT: header.payload.signature
        if signature_b64:
            jwt = header_b64 + b"." + payload_b64 + b"." + signature_b64
        else:
            # 'none' algorithm: header.payload.
            jwt = header_b64 + b"." + payload_b64 + b"."

        # Add Bearer prefix if requested
        if self.add_bearer:
            jwt = b"Bearer " + jwt

        return jwt

    def decode(self, data: bytes) -> bytes:
        """
        Decode JWT token (extract payload).

        Args:
            data: JWT token

        Returns:
            Decoded payload JSON
        """
        # Remove Bearer prefix if present
        data = data.removeprefix(b"Bearer ")

        # Split JWT parts
        parts = data.split(b".")
        if len(parts) < 2:
            raise ValueError("Invalid JWT format: expected header.payload[.signature]")

        # Decode payload (second part)
        payload_b64 = parts[1]
        payload_json = self.base64url.decode(payload_b64)

        return payload_json

    @property
    def name(self) -> str:
        bearer = "-Bearer" if self.add_bearer else ""
        return f"JWT-{self.algorithm}{bearer}"


class DigestAuthTransformer(BaseTransformer):
    """
    HTTP Digest Authentication transformer (RFC 7616).

    Implements MD5 and SHA-256 digest calculation for challenge-response auth.
    More secure than Basic Auth as password is hashed, not sent in cleartext.

    Digest Auth Flow:
    1. Client requests resource
    2. Server sends 401 with WWW-Authenticate: Digest realm=..., nonce=...
    3. Client calculates response hash and sends Authorization: Digest ...

    Response calculation:
        HA1 = MD5(username:realm:password)
        HA2 = MD5(method:uri)
        response = MD5(HA1:nonce:nc:cnonce:qop:HA2)

    Example:
        >>> transformer = DigestAuthTransformer(
        ...     username="admin",
        ...     password="password",
        ...     realm="test@example.com",
        ...     nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        ...     uri="/api/data",
        ...     method="GET"
        ... )
        >>> # Input data ignored (uses constructor params)
        >>> transformer.encode(b"")
        b'Digest username="admin", realm="test@example.com", ...'

    Note:
        This transformer requires challenge values (realm, nonce) from
        server's WWW-Authenticate header. For fuzzing, you can use
        hardcoded/fuzzable values or implement challenge parsing.
    """

    def __init__(
        self,
        username: str = "admin",
        password: str = "password",
        realm: str = "test",
        nonce: str = "dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri: str = "/",
        method: str = "GET",
        algorithm: str = "MD5",
        qop: str = "auth",
        nc: str = "00000001",
        cnonce: Optional[str] = None,
    ):
        """
        Initialize Digest Auth transformer.

        Args:
            username: Username credential
            password: Password credential
            realm: Realm from server challenge
            nonce: Nonce from server challenge
            uri: Request URI
            method: HTTP method
            algorithm: Hash algorithm (MD5, SHA-256, SHA-512-256)
            qop: Quality of Protection (auth, auth-int, or empty)
            nc: Nonce count (hexadecimal)
            cnonce: Client nonce (generated if not provided)
        """
        self.username = username
        self.password = password
        self.realm = realm
        self.nonce = nonce
        self.uri = uri
        self.method = method
        self.algorithm = algorithm
        self.qop = qop
        self.nc = nc
        self.cnonce = cnonce or self._generate_cnonce()

        # Select hash function
        if algorithm == "MD5":
            self.hash_func = hashlib.md5
        elif algorithm == "SHA-256":
            self.hash_func = hashlib.sha256
        elif algorithm == "SHA-512-256":
            self.hash_func = lambda data: hashlib.new("sha512_256", data)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    def _generate_cnonce(self) -> str:
        """Generate client nonce"""
        import secrets

        return secrets.token_hex(8)

    def _hash(self, data: str) -> str:
        """Calculate hash and return hex digest"""
        return self.hash_func(data.encode("utf-8")).hexdigest()

    def encode(self, data: bytes) -> bytes:
        """
        Calculate Digest Auth response.

        Input data is ignored; uses constructor parameters.
        """
        # HA1 = MD5(username:realm:password)
        ha1 = self._hash(f"{self.username}:{self.realm}:{self.password}")

        # HA2 = MD5(method:uri)
        ha2 = self._hash(f"{self.method}:{self.uri}")

        # Calculate response
        if self.qop in ("auth", "auth-int"):
            # response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
            response = self._hash(f"{ha1}:{self.nonce}:{self.nc}:{self.cnonce}:{self.qop}:{ha2}")
        else:
            # Legacy: response = MD5(HA1:nonce:HA2)
            response = self._hash(f"{ha1}:{self.nonce}:{ha2}")

        # Build Digest header value
        parts = [
            f'username="{self.username}"',
            f'realm="{self.realm}"',
            f'nonce="{self.nonce}"',
            f'uri="{self.uri}"',
            f'response="{response}"',
        ]

        if self.algorithm != "MD5":
            parts.append(f"algorithm={self.algorithm}")

        if self.qop:
            parts.extend(
                [
                    f"qop={self.qop}",
                    f"nc={self.nc}",
                    f'cnonce="{self.cnonce}"',
                ]
            )

        digest_value = "Digest " + ", ".join(parts)
        return digest_value.encode("utf-8")

    def decode(self, data: bytes) -> bytes:
        """
        Decode not implemented for Digest Auth.

        Digest Auth is a one-way hash; cannot extract password.
        """
        raise NotImplementedError("Digest Auth cannot be decoded (one-way hash)")

    @property
    def name(self) -> str:
        return f"DigestAuth-{self.algorithm}"
