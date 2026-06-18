#!/usr/bin/env python3
"""
Mock OPC UA Global Discovery Server (GDS) for testing OIDA OPC UA scanner

Features:
- FindServers service
- FindServersOnNetwork service (LDS functionality)
- Server registration (RegisterServer2)
- Intentionally weak security for testing rogue server attacks
"""

import asyncio
import logging
import os
from datetime import datetime
from asyncua import Server, ua
from asyncua.common.methods import uamethod

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ============================================================================
# Registered servers database
# ============================================================================
REGISTERED_SERVERS = {}


def add_mock_servers():
    """Add some pre-registered mock servers for discovery testing"""
    REGISTERED_SERVERS["urn:oida:mock:server1"] = {
        "server_uri": "urn:oida:mock:server1",
        "product_uri": "urn:oida:products:controller",
        "server_names": ["Industrial Controller 1"],
        "server_type": ua.ApplicationType.Server,
        "gateway_uri": "",
        "discovery_urls": ["opc.tcp://192.168.1.10:4840"],
        "semaphore_path": "",
        "is_online": True,
        "capabilities": ["DA", "HD"],
        "registered_at": datetime.utcnow().isoformat(),
    }

    REGISTERED_SERVERS["urn:oida:mock:server2"] = {
        "server_uri": "urn:oida:mock:server2",
        "product_uri": "urn:oida:products:hmi",
        "server_names": ["HMI Server"],
        "server_type": ua.ApplicationType.Server,
        "gateway_uri": "",
        "discovery_urls": ["opc.tcp://192.168.1.20:4840"],
        "semaphore_path": "",
        "is_online": True,
        "capabilities": ["DA"],
        "registered_at": datetime.utcnow().isoformat(),
    }

    REGISTERED_SERVERS["urn:oida:mock:server3"] = {
        "server_uri": "urn:oida:mock:server3",
        "product_uri": "urn:oida:products:historian",
        "server_names": ["Historian Server"],
        "server_type": ua.ApplicationType.Server,
        "gateway_uri": "",
        "discovery_urls": ["opc.tcp://192.168.1.30:4840", "opc.tcp://192.168.1.30:4841"],
        "semaphore_path": "",
        "is_online": False,  # Simulate offline server
        "capabilities": ["DA", "HD", "AC"],
        "registered_at": datetime.utcnow().isoformat(),
    }

    log.info(f"Pre-registered {len(REGISTERED_SERVERS)} mock servers")


# ============================================================================
# GDS Methods
# ============================================================================
@uamethod
def find_servers_on_network_method(parent, starting_record_id: int, max_records: int):
    """
    FindServersOnNetwork - returns list of servers registered with this LDS/GDS

    This is the key method for network-wide discovery.
    In a real GDS, this would query mDNS or a central registry.
    """
    log.info(f"FindServersOnNetwork called: start={starting_record_id}, max={max_records}")

    servers = []
    record_id = 0

    for server_uri, server_info in REGISTERED_SERVERS.items():
        if record_id >= starting_record_id:
            if max_records > 0 and len(servers) >= max_records:
                break

            # Create ServerOnNetwork structure
            server_record = {
                "record_id": record_id,
                "server_name": server_info["server_names"][0]
                if server_info["server_names"]
                else "",
                "discovery_url": server_info["discovery_urls"][0]
                if server_info["discovery_urls"]
                else "",
                "server_capabilities": server_info.get("capabilities", []),
            }
            servers.append(str(server_record))

        record_id += 1

    log.info(f"Returning {len(servers)} servers")
    import json

    return json.dumps(servers)


@uamethod
def register_server_method(parent, server_uri: str, server_name: str, discovery_url: str):
    """
    RegisterServer2 - register a new server with the GDS

    WARNING: This mock intentionally has NO authentication requirement
    to test for rogue server registration vulnerabilities.
    """
    log.warning(f"RegisterServer called (NO AUTH CHECK): uri={server_uri}, name={server_name}")

    REGISTERED_SERVERS[server_uri] = {
        "server_uri": server_uri,
        "product_uri": "",
        "server_names": [server_name],
        "server_type": ua.ApplicationType.Server,
        "gateway_uri": "",
        "discovery_urls": [discovery_url],
        "semaphore_path": "",
        "is_online": True,
        "capabilities": [],
        "registered_at": datetime.utcnow().isoformat(),
    }

    log.warning(f"ROGUE SERVER REGISTERED: {server_uri} -> {discovery_url}")
    return f"Server registered: {server_uri}"


@uamethod
def unregister_server_method(parent, server_uri: str):
    """UnregisterServer - remove a server from the registry"""
    log.info(f"UnregisterServer called: {server_uri}")

    if server_uri in REGISTERED_SERVERS:
        del REGISTERED_SERVERS[server_uri]
        return f"Server unregistered: {server_uri}"
    else:
        return f"Server not found: {server_uri}"


@uamethod
def get_registered_servers_method(parent):
    """Get all registered servers (debugging method)"""
    import json

    return json.dumps(list(REGISTERED_SERVERS.keys()))


async def create_gds_namespace(server: Server):
    """Create GDS namespace with discovery methods"""

    objects = server.get_objects_node()

    # Create GDS folder
    gds_folder = await objects.add_folder("ns=2;i=1", "DiscoveryServices")

    # FindServersOnNetwork method
    find_servers_input = [
        ua.Argument("StartingRecordId", ua.NodeId(ua.ObjectIds.UInt32), ua.ValueRank.Scalar),
        ua.Argument("MaxRecordsToReturn", ua.NodeId(ua.ObjectIds.UInt32), ua.ValueRank.Scalar),
    ]
    find_servers_output = [
        ua.Argument("ServerRecords", ua.NodeId(ua.ObjectIds.String), ua.ValueRank.Scalar),
    ]
    await gds_folder.add_method(
        "ns=2;i=100",
        "FindServersOnNetwork",
        find_servers_on_network_method,
        find_servers_input,
        find_servers_output,
    )

    # RegisterServer method (intentionally unsecured for testing)
    register_input = [
        ua.Argument("ServerUri", ua.NodeId(ua.ObjectIds.String), ua.ValueRank.Scalar),
        ua.Argument("ServerName", ua.NodeId(ua.ObjectIds.String), ua.ValueRank.Scalar),
        ua.Argument("DiscoveryUrl", ua.NodeId(ua.ObjectIds.String), ua.ValueRank.Scalar),
    ]
    register_output = [
        ua.Argument("Result", ua.NodeId(ua.ObjectIds.String), ua.ValueRank.Scalar),
    ]
    await gds_folder.add_method(
        "ns=2;i=200",
        "RegisterServer",
        register_server_method,
        register_input,
        register_output,
    )

    # UnregisterServer method
    unregister_input = [
        ua.Argument("ServerUri", ua.NodeId(ua.ObjectIds.String), ua.ValueRank.Scalar),
    ]
    unregister_output = [
        ua.Argument("Result", ua.NodeId(ua.ObjectIds.String), ua.ValueRank.Scalar),
    ]
    await gds_folder.add_method(
        "ns=2;i=300",
        "UnregisterServer",
        unregister_server_method,
        unregister_input,
        unregister_output,
    )

    # GetRegisteredServers method (debugging)
    await gds_folder.add_method(
        "ns=2;i=400",
        "GetRegisteredServers",
        get_registered_servers_method,
        [],
        [ua.Argument("Servers", ua.NodeId(ua.ObjectIds.String), ua.ValueRank.Scalar)],
    )

    # Add some status variables
    status_folder = await gds_folder.add_folder("ns=2;i=2", "Status")
    await status_folder.add_variable(
        "ns=2;i=20",
        "RegisteredServerCount",
        len(REGISTERED_SERVERS),
        ua.VariantType.UInt32,
    )
    await status_folder.add_variable(
        "ns=2;i=21",
        "LastRegistrationTime",
        datetime.utcnow().isoformat(),
        ua.VariantType.String,
    )

    log.info("Created GDS namespace with discovery methods")


async def update_status_loop(server: Server):
    """Periodically update status variables"""
    while True:
        try:
            status_node = server.get_node("ns=2;i=20")
            await status_node.write_value(len(REGISTERED_SERVERS))
            await asyncio.sleep(5)
        except Exception as e:
            log.error(f"Error updating status: {e}")
            await asyncio.sleep(10)


async def main():
    """Start the mock GDS server"""
    port = int(os.environ.get("GDS_PORT", "4850"))

    log.info(f"Starting Mock OPC UA GDS on port {port}")

    # Add pre-registered mock servers
    add_mock_servers()

    server = Server()
    await server.init()

    # Configure as discovery server
    server.set_endpoint(f"opc.tcp://0.0.0.0:{port}/gds/")
    server.set_server_name("OIDA Mock Global Discovery Server")

    # Set application type to DiscoveryServer
    # This tells clients this is a discovery service
    server.application_type = ua.ApplicationType.DiscoveryServer

    # Setup namespace
    uri = "http://oida.mock.gds"
    idx = await server.register_namespace(uri)

    # Create GDS namespace
    await create_gds_namespace(server)

    # INTENTIONALLY NO SECURITY - to test rogue server registration
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    log.warning("GDS running WITHOUT security - intentionally vulnerable for testing")

    async with server:
        log.info(f"GDS started on opc.tcp://0.0.0.0:{port}/gds/")
        log.info(f"Pre-registered servers: {len(REGISTERED_SERVERS)}")

        # Start status update task
        status_task = asyncio.create_task(update_status_loop(server))

        try:
            await status_task
        except KeyboardInterrupt:
            log.info("Shutting down GDS...")
            status_task.cancel()
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    asyncio.run(main())
