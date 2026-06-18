#!/usr/bin/env python3
"""
Enhanced Mock OPC UA Server for testing OIDA OPC UA scanner

Features:
- Callable methods (start_pump, stop_pump, reset_device, set_temperature)
- Dynamic changing values (sensors update every 2 seconds)
- Event/alarm triggering
- Multiple security modes (None, Sign, SignAndEncrypt)
- User authentication (admin/admin, operator/operator123, readonly/readonly)
"""

import asyncio
import logging
import os
from datetime import datetime
from asyncua import Server, ua
from asyncua.common.methods import uamethod
from asyncua.server.user_managers import User, UserRole

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ============================================================================
# Global state for methods
# ============================================================================
DEVICE_STATE = {
    "pump_running": False,
    "motor_running": True,
    "system_reset_count": 0,
    "last_command": None,
    "last_command_time": None,
}


# ============================================================================
# OPC UA Methods (using @uamethod decorator)
# ============================================================================
@uamethod
def start_pump(parent):
    """Start the pump - returns status message"""
    DEVICE_STATE["pump_running"] = True
    DEVICE_STATE["last_command"] = "start_pump"
    DEVICE_STATE["last_command_time"] = datetime.now().isoformat()
    log.info("Method called: start_pump()")
    return "Pump started successfully"


@uamethod
def stop_pump(parent):
    """Stop the pump - returns status message"""
    DEVICE_STATE["pump_running"] = False
    DEVICE_STATE["last_command"] = "stop_pump"
    DEVICE_STATE["last_command_time"] = datetime.now().isoformat()
    log.info("Method called: stop_pump()")
    return "Pump stopped successfully"


@uamethod
def reset_device(parent):
    """Reset the device - potentially dangerous operation"""
    DEVICE_STATE["system_reset_count"] += 1
    DEVICE_STATE["pump_running"] = False
    DEVICE_STATE["motor_running"] = False
    DEVICE_STATE["last_command"] = "reset_device"
    DEVICE_STATE["last_command_time"] = datetime.now().isoformat()
    log.warning("Method called: reset_device() - DANGEROUS OPERATION")
    return f"Device reset complete. Reset count: {DEVICE_STATE['system_reset_count']}"


@uamethod
def set_temperature(parent, value: float):
    """Set target temperature - takes float parameter"""
    if value < -50 or value > 200:
        raise ua.UaError(f"Temperature {value} out of valid range (-50 to 200)")
    DEVICE_STATE["last_command"] = f"set_temperature({value})"
    DEVICE_STATE["last_command_time"] = datetime.now().isoformat()
    log.info(f"Method called: set_temperature({value})")
    return f"Temperature setpoint changed to {value}°C"


@uamethod
def emergency_stop(parent):
    """Emergency stop - critical safety method"""
    DEVICE_STATE["pump_running"] = False
    DEVICE_STATE["motor_running"] = False
    DEVICE_STATE["last_command"] = "emergency_stop"
    DEVICE_STATE["last_command_time"] = datetime.now().isoformat()
    log.critical("Method called: emergency_stop() - EMERGENCY!")
    return "EMERGENCY STOP ACTIVATED - All systems halted"


@uamethod
def get_diagnostics(parent):
    """Get device diagnostics - read-only method"""
    import json

    return json.dumps(DEVICE_STATE, indent=2)


@uamethod
def execute_command(parent, command: str):
    """Execute arbitrary command - VERY DANGEROUS (simulated)"""
    log.critical(f"Method called: execute_command('{command}') - SIMULATED RCE")
    DEVICE_STATE["last_command"] = f"execute_command({command})"
    DEVICE_STATE["last_command_time"] = datetime.now().isoformat()
    # Don't actually execute anything - just simulate
    return f"Command executed (simulated): {command}"


# ============================================================================
# User Manager for authentication
# ============================================================================
class CustomUserManager:
    """Custom user manager with predefined test credentials"""

    def __init__(self):
        # Define test users: username -> (password, role)
        self.users = {
            "admin": ("admin", UserRole.Admin),
            "operator": ("operator123", UserRole.User),
            "readonly": ("readonly", UserRole.User),
            "user": ("user", UserRole.User),
        }

    def get_user(self, iserver, username=None, password=None, certificate=None):
        """Authenticate user and return User object or None"""
        log.info(f"Authentication attempt: user='{username}'")

        if username in self.users:
            expected_password, role = self.users[username]
            if password == expected_password:
                log.info(f"Authentication successful: {username} (role={role})")
                return User(role=role, name=username)

        log.warning(f"Authentication failed: {username}")
        return None


async def create_opcua_namespace(server: Server):
    """Create a realistic OPC UA namespace for industrial simulation"""

    # Get objects node
    objects = server.get_objects_node()

    # Create main device folder
    device_folder = await objects.add_folder("ns=2;i=1", "IndustrialDevice")

    # Create sensors folder
    sensors_folder = await device_folder.add_folder("ns=2;i=2", "Sensors")

    # Temperature sensors
    temp1 = await sensors_folder.add_variable(
        "ns=2;i=10", "Temperature1", 25.5, ua.VariantType.Float
    )
    temp2 = await sensors_folder.add_variable(
        "ns=2;i=11", "Temperature2", 30.2, ua.VariantType.Float
    )
    await temp1.set_writable()
    await temp2.set_writable()

    # Pressure sensors
    pressure1 = await sensors_folder.add_variable(
        "ns=2;i=20", "Pressure1", 1013.25, ua.VariantType.Float
    )
    pressure2 = await sensors_folder.add_variable(
        "ns=2;i=21", "Pressure2", 850.0, ua.VariantType.Float
    )

    # Flow rate
    flow_rate = await sensors_folder.add_variable(
        "ns=2;i=30", "FlowRate", 15.7, ua.VariantType.Float
    )

    # Create actuators folder
    actuators_folder = await device_folder.add_folder("ns=2;i=3", "Actuators")

    # Motor control
    motor_speed = await actuators_folder.add_variable(
        "ns=2;i=40", "MotorSpeed", 75, ua.VariantType.Int32
    )
    motor_enabled = await actuators_folder.add_variable(
        "ns=2;i=41", "MotorEnabled", True, ua.VariantType.Boolean
    )
    await motor_speed.set_writable()
    await motor_enabled.set_writable()

    # Valve control
    valve_position = await actuators_folder.add_variable(
        "ns=2;i=50", "ValvePosition", 50, ua.VariantType.Int32
    )
    valve_open = await actuators_folder.add_variable(
        "ns=2;i=51", "ValveOpen", False, ua.VariantType.Boolean
    )
    await valve_position.set_writable()
    await valve_open.set_writable()

    # Pump control
    pump_flow = await actuators_folder.add_variable(
        "ns=2;i=60", "PumpFlow", 12.5, ua.VariantType.Float
    )
    pump_pressure = await actuators_folder.add_variable(
        "ns=2;i=61", "PumpPressure", 5.2, ua.VariantType.Float
    )
    await pump_flow.set_writable()

    # Create alarms folder
    alarms_folder = await device_folder.add_folder("ns=2;i=4", "Alarms")

    # Alarm states
    temp_alarm = await alarms_folder.add_variable(
        "ns=2;i=70", "TemperatureAlarm", False, ua.VariantType.Boolean
    )
    pressure_alarm = await alarms_folder.add_variable(
        "ns=2;i=71", "PressureAlarm", False, ua.VariantType.Boolean
    )
    system_fault = await alarms_folder.add_variable(
        "ns=2;i=72", "SystemFault", False, ua.VariantType.Boolean
    )

    # Create configuration folder
    config_folder = await device_folder.add_folder("ns=2;i=5", "Configuration")

    # Configuration parameters
    temp_setpoint = await config_folder.add_variable(
        "ns=2;i=80", "TemperatureSetpoint", 22.0, ua.VariantType.Float
    )
    pressure_setpoint = await config_folder.add_variable(
        "ns=2;i=81", "PressureSetpoint", 1000.0, ua.VariantType.Float
    )
    max_flow_rate = await config_folder.add_variable(
        "ns=2;i=82", "MaxFlowRate", 20.0, ua.VariantType.Float
    )
    await temp_setpoint.set_writable()
    await pressure_setpoint.set_writable()
    await max_flow_rate.set_writable()

    # Device info
    device_name = await config_folder.add_variable(
        "ns=2;i=90", "DeviceName", "Mock Industrial Controller", ua.VariantType.String
    )
    firmware_version = await config_folder.add_variable(
        "ns=2;i=91", "FirmwareVersion", "v1.2.3", ua.VariantType.String
    )
    serial_number = await config_folder.add_variable(
        "ns=2;i=92", "SerialNumber", "OIDA-001", ua.VariantType.String
    )

    # ========================================================================
    # Create Methods folder with callable methods
    # ========================================================================
    methods_folder = await device_folder.add_folder("ns=2;i=6", "Methods")

    # Helper to create output argument
    def str_output(name="Result"):
        return [ua.Argument(name, ua.NodeId(ua.ObjectIds.String), ua.ValueRank.Scalar)]

    # Add methods to the Methods folder (let asyncua auto-generate NodeIds)
    idx = await server.get_namespace_index("http://oida.mock.server")

    # start_pump - no arguments, returns string
    start_pump_node = await methods_folder.add_method(
        idx, "StartPump", start_pump, [], str_output()
    )

    # stop_pump - no arguments, returns string
    stop_pump_node = await methods_folder.add_method(idx, "StopPump", stop_pump, [], str_output())

    # reset_device - no arguments, returns string (DANGEROUS)
    reset_device_node = await methods_folder.add_method(
        idx, "ResetDevice", reset_device, [], str_output()
    )

    # set_temperature - takes float, returns string
    set_temp_input = [
        ua.Argument("Temperature", ua.NodeId(ua.ObjectIds.Float), ua.ValueRank.Scalar)
    ]
    set_temp_node = await methods_folder.add_method(
        idx, "SetTemperature", set_temperature, set_temp_input, str_output()
    )

    # emergency_stop - no arguments (CRITICAL)
    emergency_stop_node = await methods_folder.add_method(
        idx, "EmergencyStop", emergency_stop, [], str_output()
    )

    # get_diagnostics - no arguments, returns JSON string
    diagnostics_node = await methods_folder.add_method(
        idx, "GetDiagnostics", get_diagnostics, [], str_output("Diagnostics")
    )

    # execute_command - takes string, returns string (VERY DANGEROUS - simulated RCE)
    exec_cmd_input = [ua.Argument("Command", ua.NodeId(ua.ObjectIds.String), ua.ValueRank.Scalar)]
    exec_cmd_node = await methods_folder.add_method(
        idx, "ExecuteCommand", execute_command, exec_cmd_input, str_output()
    )

    log.info("Created Methods folder with 7 callable methods")

    # ========================================================================
    # Enable historizing on some sensor nodes
    # ========================================================================
    for sensor in [temp1, temp2, pressure1]:
        try:
            await sensor.write_attribute(
                ua.AttributeIds.Historizing, ua.DataValue(ua.Variant(True))
            )
            log.info(f"Enabled historizing on {await sensor.read_browse_name()}")
        except Exception as e:
            log.warning(f"Could not enable historizing: {e}")

    # ========================================================================
    # Create Files folder with FileType nodes
    # ========================================================================
    files_folder = await device_folder.add_folder("ns=2;i=7", "Files")

    # Create a simple mock file implementation
    # Note: Full FileType requires implementing Open/Read/Write/Close methods
    # This is a simplified version that exposes file metadata

    # Config file (readable)
    config_file = await files_folder.add_object("ns=2;i=200", "config.ini")
    await config_file.add_variable("ns=2;i=201", "Size", 1024, ua.VariantType.UInt64)
    await config_file.add_variable("ns=2;i=202", "Writable", False, ua.VariantType.Boolean)
    await config_file.add_variable("ns=2;i=203", "OpenCount", 0, ua.VariantType.UInt16)

    # Log file (readable)
    log_file = await files_folder.add_object("ns=2;i=210", "system.log")
    await log_file.add_variable("ns=2;i=211", "Size", 45678, ua.VariantType.UInt64)
    await log_file.add_variable("ns=2;i=212", "Writable", False, ua.VariantType.Boolean)
    await log_file.add_variable("ns=2;i=213", "OpenCount", 0, ua.VariantType.UInt16)

    # Firmware file (writable - dangerous!)
    firmware_file = await files_folder.add_object("ns=2;i=220", "firmware.bin")
    await firmware_file.add_variable("ns=2;i=221", "Size", 2097152, ua.VariantType.UInt64)
    firmware_writable = await firmware_file.add_variable(
        "ns=2;i=222", "Writable", True, ua.VariantType.Boolean
    )
    await firmware_file.add_variable("ns=2;i=223", "OpenCount", 0, ua.VariantType.UInt16)

    # Recipe file (writable)
    recipe_file = await files_folder.add_object("ns=2;i=230", "recipe.xml")
    await recipe_file.add_variable("ns=2;i=231", "Size", 8192, ua.VariantType.UInt64)
    recipe_writable = await recipe_file.add_variable(
        "ns=2;i=232", "Writable", True, ua.VariantType.Boolean
    )
    await recipe_file.add_variable("ns=2;i=233", "OpenCount", 0, ua.VariantType.UInt16)

    log.info("Created Files folder with 4 file nodes (2 writable)")

    return {
        "sensors": [temp1, temp2, pressure1, pressure2, flow_rate],
        "actuators": [motor_speed, motor_enabled, valve_position, valve_open, pump_flow],
        "alarms": [temp_alarm, pressure_alarm, system_fault],
        "config": [temp_setpoint, pressure_setpoint, max_flow_rate],
        "methods": [
            start_pump_node,
            stop_pump_node,
            reset_device_node,
            set_temp_node,
            emergency_stop_node,
            diagnostics_node,
            exec_cmd_node,
        ],
        "files": [config_file, log_file, firmware_file, recipe_file],
    }


async def simulate_values(nodes_dict):
    """Simulate changing values for dynamic behavior"""
    import random
    import math

    counter = 0

    # Helper to write with correct variant type (Float nodes need ua.Variant)
    async def write_float(node, value):
        await node.write_value(ua.Variant(float(value), ua.VariantType.Float))

    while True:
        try:
            counter += 1

            # Simulate temperature fluctuations
            temp1_val = 25.0 + 5.0 * math.sin(counter * 0.1) + random.uniform(-1, 1)
            temp2_val = 30.0 + 3.0 * math.cos(counter * 0.15) + random.uniform(-0.5, 0.5)
            await write_float(nodes_dict["sensors"][0], temp1_val)
            await write_float(nodes_dict["sensors"][1], temp2_val)

            # Simulate pressure changes
            pressure1_val = 1013.25 + 50 * math.sin(counter * 0.05) + random.uniform(-10, 10)
            pressure2_val = 850.0 + 25 * math.cos(counter * 0.08) + random.uniform(-5, 5)
            await write_float(nodes_dict["sensors"][2], pressure1_val)
            await write_float(nodes_dict["sensors"][3], pressure2_val)

            # Simulate flow rate
            flow_val = 15.0 + 5.0 * math.sin(counter * 0.12) + random.uniform(-1, 1)
            await write_float(nodes_dict["sensors"][4], max(0, flow_val))

            # Simulate pump pressure based on flow
            pump_pressure = flow_val * 0.3 + random.uniform(-0.2, 0.2)
            await write_float(nodes_dict["actuators"][4], max(0, pump_pressure))

            # Simulate occasional alarms
            if counter % 100 == 0:
                alarm_state = temp1_val > 28.0
                await nodes_dict["alarms"][0].write_value(alarm_state)

            if counter % 150 == 0:
                alarm_state = pressure1_val > 1050.0
                await nodes_dict["alarms"][1].write_value(alarm_state)

            await asyncio.sleep(2)  # Update every 2 seconds

        except Exception as e:
            log.error(f"Error in simulation: {e}")
            await asyncio.sleep(5)


async def setup_security(server: Server, enable_security: bool = True):
    """Configure server security (certificates and policies)"""
    if not enable_security:
        # Insecure mode - only NoSecurity
        server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
        log.info("Security: NoSecurity only (insecure mode)")
        return

    # Generate self-signed certificates for testing
    try:
        cert_dir = "/tmp/opcua_certs"
        os.makedirs(cert_dir, exist_ok=True)

        cert_path = os.path.join(cert_dir, "server_cert.der")
        key_path = os.path.join(cert_dir, "server_key.pem")

        if not os.path.exists(cert_path):
            log.info("Generating self-signed certificate...")
            # Generate certificate using asyncua's crypto utilities
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from datetime import timedelta

            # Generate key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Generate certificate
            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "Test"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA Mock"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "OIDA Mock OPC UA Server"),
                ]
            )

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=365))
                .add_extension(
                    x509.SubjectAlternativeName(
                        [
                            x509.UniformResourceIdentifier("urn:oida:mock:opcua:server"),
                        ]
                    ),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )

            # Save certificate (DER format)
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.DER))

            # Save key (PEM format)
            with open(key_path, "wb") as f:
                f.write(
                    key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )

            log.info(f"Certificate generated: {cert_path}")

        # Load certificate and key
        await server.load_certificate(cert_path)
        await server.load_private_key(key_path)

        # Enable multiple security policies
        server.set_security_policy(
            [
                ua.SecurityPolicyType.NoSecurity,
                ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
                ua.SecurityPolicyType.Basic256Sha256_Sign,
                ua.SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt,
            ]
        )

        log.info("Security: Multiple policies enabled (NoSecurity + Basic256Sha256 + Aes128)")

    except Exception as e:
        log.warning(f"Could not setup security certificates: {e}")
        log.warning("Falling back to NoSecurity only")
        server.set_security_policy([ua.SecurityPolicyType.NoSecurity])


async def main():
    """Start the mock OPC UA server"""
    port = int(os.environ.get("OPCUA_PORT", "4840"))
    enable_security = os.environ.get("OPCUA_SECURITY", "true").lower() == "true"
    enable_auth = os.environ.get("OPCUA_AUTH", "true").lower() == "true"

    log.info(f"Starting Enhanced Mock OPC UA Server on port {port}")
    log.info(f"Security: {'enabled' if enable_security else 'disabled'}")
    log.info(f"Authentication: {'enabled' if enable_auth else 'disabled (anonymous only)'}")

    # Create server with optional user manager
    if enable_auth:
        user_manager = CustomUserManager()
        server = Server(user_manager=user_manager)
        log.info(
            "User authentication enabled (admin/admin, operator/operator123, readonly/readonly)"
        )
    else:
        server = Server()
        log.info("Anonymous access only")

    await server.init()

    # Configure server
    server.set_endpoint(f"opc.tcp://0.0.0.0:{port}/freeopcua/server/")
    server.set_server_name("OIDA Enhanced Mock OPC UA Server")

    # Setup namespace
    uri = "http://oida.mock.server"
    idx = await server.register_namespace(uri)

    # Create namespace objects (includes methods)
    nodes_dict = await create_opcua_namespace(server)

    # Setup security (certificates and policies)
    await setup_security(server, enable_security)

    log.info("OPC UA Server configured with:")
    log.info("  - Industrial simulation data (sensors, actuators, alarms)")
    log.info(
        "  - 7 callable methods (StartPump, StopPump, ResetDevice, SetTemperature, EmergencyStop, GetDiagnostics, ExecuteCommand)"
    )
    log.info("  - Dynamic value simulation (updates every 2 seconds)")

    async with server:
        log.info(f"OPC UA Server started on opc.tcp://0.0.0.0:{port}/freeopcua/server/")

        # Start simulation task
        simulation_task = asyncio.create_task(simulate_values(nodes_dict))

        try:
            await simulation_task
        except KeyboardInterrupt:
            log.info("Shutting down OPC UA server...")
            simulation_task.cancel()
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    asyncio.run(main())
