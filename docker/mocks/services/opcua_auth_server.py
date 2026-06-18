#!/usr/bin/env python3
"""
Strict Authentication Mock OPC UA Server

This server ENFORCES username/password authentication.
Invalid credentials are REJECTED with BadUserAccessDenied.

Valid credentials:
  admin:admin123        (Admin role)
  operator:oper@t0r     (Operator role)
  readonly:readonly     (Read-only role)
  guest:guest           (Guest - limited access)

Anonymous access is DISABLED.
"""

import asyncio
import logging
import os
from asyncua import Server, ua
from asyncua.server.users import User, UserRole

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger(__name__)


# Valid credentials - username: (password, role)
VALID_CREDENTIALS = {
    "admin": ("admin123", UserRole.Admin),
    "operator": ("oper@t0r", UserRole.User),
    "readonly": ("readonly", UserRole.User),
    "guest": ("guest", UserRole.User),
}


class StrictUserManager:
    """
    Strict user manager that REJECTS invalid credentials.

    Unlike the default behavior, this raises BadUserAccessDenied
    for any authentication failure.
    """

    def __init__(self):
        self.credentials = VALID_CREDENTIALS.copy()
        self.failed_attempts = {}  # Track failed attempts per IP
        log.info(f"StrictUserManager initialized with {len(self.credentials)} users")
        for user in self.credentials:
            log.info(f"  - {user}")

    def get_user(self, iserver, username=None, password=None, certificate=None):
        """
        Authenticate user - STRICT mode.

        Returns User object on success, raises BadUserAccessDenied on failure.
        """
        log.info(f"AUTH: Attempt for user='{username}'")

        # Reject empty username
        if not username:
            log.warning("AUTH: REJECTED - empty username")
            raise ua.UaError("BadUserAccessDenied: Username required")

        # Check if user exists
        if username not in self.credentials:
            log.warning(f"AUTH: REJECTED - unknown user '{username}'")
            raise ua.UaError("BadUserAccessDenied: Invalid username or password")

        expected_password, role = self.credentials[username]

        # Validate password
        if password != expected_password:
            log.warning(f"AUTH: REJECTED - wrong password for '{username}'")
            raise ua.UaError("BadUserAccessDenied: Invalid username or password")

        # Success
        log.info(f"AUTH: SUCCESS - {username} (role={role})")
        return User(role=role)


async def create_address_space(server: Server, idx: int):
    """Create minimal address space for testing"""

    objects = server.get_objects_node()

    # Device folder
    device = await objects.add_folder(idx, "Device")

    # Some test variables
    status = await device.add_variable(idx, "Status", "Online")
    temperature = await device.add_variable(idx, "Temperature", 25.5)
    counter = await device.add_variable(idx, "Counter", 0)

    await temperature.set_writable()
    await counter.set_writable()

    # Sensitive folder (admin only in real scenario)
    config = await device.add_folder(idx, "Configuration")
    secret_key = await config.add_variable(idx, "SecretKey", "REDACTED-USE-ADMIN")
    admin_password = await config.add_variable(idx, "AdminPassword", "REDACTED")

    log.info("Address space created")

    return {"counter": counter}


async def update_counter(nodes):
    """Simulate activity"""
    count = 0
    while True:
        count += 1
        try:
            await nodes["counter"].write_value(count)
        except Exception:
            pass
        await asyncio.sleep(1)


async def main():
    port = int(os.environ.get("OPCUA_PORT", "4841"))

    log.info("=" * 60)
    log.info("STRICT AUTH OPC UA SERVER")
    log.info("=" * 60)
    log.info("")
    log.info("Valid credentials:")
    for user, (pwd, role) in VALID_CREDENTIALS.items():
        log.info(f"  {user}:{pwd} ({role})")
    log.info("")
    log.info("Anonymous access: DISABLED")
    log.info("=" * 60)

    # Create server with strict user manager
    user_manager = StrictUserManager()
    server = Server(user_manager=user_manager)

    await server.init()

    # Configure endpoint
    server.set_endpoint(f"opc.tcp://0.0.0.0:{port}/SIMATIC/S7-1500/OPC-UA")
    server.set_server_name("Strict Auth OPC UA Server")

    # Register namespace
    uri = "http://oida.mock.strict-auth"
    idx = await server.register_namespace(uri)

    # CRITICAL: Disable anonymous, only allow username/password
    server.set_security_IDs(["Username"])

    # Security policy - None (unencrypted) but WITH authentication
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])

    # Create address space
    nodes = await create_address_space(server, idx)

    log.info(f"Server starting on opc.tcp://0.0.0.0:{port}")

    async with server:
        log.info("Server RUNNING - waiting for connections...")

        # Start counter update
        update_task = asyncio.create_task(update_counter(nodes))

        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            update_task.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Server stopped")
