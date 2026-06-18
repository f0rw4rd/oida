# Vulture whitelist -- false positives from required API signatures.
# Only add entries here that are genuinely required by external APIs
# (callback signatures, signal handlers, abstract method params, etc.)
# Do NOT whitelist actual dead code.

# paho-mqtt callback signature requires (client, userdata, ...) params
userdata  # unused variable (mqtt callback signature)

# signal.signal() handler requires (signum, frame) params
signum  # unused variable (signal handler signature)

# argparse.Action.__call__ requires option_string param
option_string  # unused variable (argparse Action signature)

# Kept for public API backward compatibility
prefer_native  # unused variable (src/oida/fuzz/core/mutation/__init__.py:31)

# DNP3 callback API signature (OnTaskStart receives task_type, task_id)
task_id  # unused variable (dnp3 callback signature)
task_type  # unused variable (dnp3 callback signature)

# NetBIOS device method parameter for future validation
ip_from_response  # unused variable (network.py _add_netbios_device parameter)

# TASE.2 IEC 60870-6-503 API parameters (not yet used by pyiec61850-ng backend)
originator  # unused variable (tase2 scanner write_information_message parameter)
max_messages  # unused variable (tase2 scanner create_information_message_store parameter)
