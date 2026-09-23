# Vulture whitelist -- false positives from required API signatures.
# Only add entries here that are genuinely required by external APIs
# (callback signatures, signal handlers, abstract method params, etc.)
# Do NOT whitelist actual dead code.

# paho-mqtt callback signature requires (client, userdata, ...) params
userdata  # unused variable (mqtt callback signature)

# pysnmp observer signature requires (engine, execpoint, ctx, cbCtx) params
execpoint  # unused variable (pysnmp observer signature)
cbCtx  # unused variable (pysnmp observer signature)

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

# --- Dynamically dispatched classes (vulture is static and cannot see these) ---

# Protocol fuzzers: resolved from _FUZZER_SPECS strings via getattr() in
# src/oida/fuzz/protocols/__init__.py (tolerant loader, commit 7742565)
ADSFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
ASTMFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
CoAPFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
DaytimeFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
DICOMFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
EchoFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
EtherCATFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
FTPFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
GOOSEFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
HARTIPFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
HL7Fuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
HTTP2Fuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
HTTPFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
ICMPFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
ICMPv6Fuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
IGMPFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
IPv4Fuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
KNXFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
MDNSFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
MMSFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
MQTTFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
MutationFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
NetBIOSFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
NTPFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
OPCUAFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
PPPoEFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
ProfinetDCPFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
S7CommFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
SixLoWPANFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
TASE2Fuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
TCPFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
TFTPFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)
VNCFuzzer  # unused class (fuzz/protocols/_FUZZER_SPECS dynamic dispatch)

# BaseFuzzer.RequestInfo.expects_response: declarative request metadata read
# by protocol fuzzers overriding RequestInfo (dataclass field, not a variable)
expects_response  # unused variable (fuzz/core/base_fuzzer.py RequestInfo dataclass field)

# DiscoveredDevice / listener payload attributes: written by pcap listeners,
# serialized wholesale via vars()/asdict and read back by string key in
# build_device_description() and export paths -- no static .attr reader exists
# by design. Same pattern as the *_data fields already in the baseline.
dhcpv6_data  # unused attribute (discovery DiscoveredDevice / dhcpv6 listener payload)
fins_data  # unused attribute (discovery DiscoveredDevice / fins listener payload)
mdns_data  # unused attribute (discovery DiscoveredDevice / mdns listener payload)
ntp_data  # unused attribute (discovery DiscoveredDevice / ntp listener payload)
vrrp_data  # unused attribute (discovery DiscoveredDevice / vrrp listener payload)
iec104_passive_data  # unused attribute (pcap iec104 listener payload)
irc_passive_data  # unused attribute (pcap irc listener payload)
modbus_passive_data  # unused attribute (pcap modbus listener payload)
stp_data  # unused attribute (pcap stp listener payload)

# boofuzz BaseMonitor protocol hooks: invoked by the boofuzz session loop,
# not by our own code
pre_send  # unused method (boofuzz BaseMonitor.pre_send hook)
post_send  # unused method (boofuzz BaseMonitor.post_send hook)

# COTP connection state-completeness flag: written by _handle_cr, never read
# (the DR-probe alert intentionally keys on "no CC" instead)
cr_seen  # unused variable/attribute (pcap cotp state tracking)

# DiscoveredDevice *_passive_data fields: written by ~50 pcap listeners, read
# back by string key after vars()/asdict serialization in export/description
# paths -- identical pattern to the entries already baselined
arp_data
opcua_data
ethernetip_data
netmanage_data
rdp_passive_data
tacacs_passive_data
socks_passive_data
pap_passive_data
ads_passive_data
c1222_passive_data
can_passive_data
canopen_passive_data
cipsafety_passive_data
coap_passive_data
cotp_passive_data
devicenet_passive_data
dicom_passive_data
dnp3_passive_data
dtp_data
egd_passive_data
enip_passive_data
epl_passive_data
ethercat_passive_data
ff_hse_passive_data
goose_passive_data
hartip_passive_data
hl7_passive_data
hsr_passive_data
ieee1722_passive_data
ipmi_passive_data
j1939_passive_data
knx_passive_data
mqttsn_passive_data
netbios_passive_data
nmea0183_passive_data
ntp_passive_data
opcda_passive_data
opcua_passive_data
opensafety_passive_data
pcom_passive_data
profinet_passive_data
prp_passive_data
ptp_passive_data
rgoose_passive_data
rpcbind_passive_data
rtps_passive_data
selfm_passive_data
sercos_passive_data
smartinstall_data
sv_passive_data
tte_passive_data
vtp_data

# --- Remaining individually-triaged dynamic/external-API findings ---

# Fuzzer TCP connection API: documented contract for the session loop
# (TODO at tcp.py:86 says "consume reset_count/last_recv_was_reset in the
# session loop"); also asserted in tests/unit/fuzz/test_connection_fixes.py
last_recv_was_reset  # unused attribute (fuzz TCP connection RST flag, tested API)

# boofuzz Session.total_num_mutations: set on the external boofuzz session
# before _main_fuzz_loop (which reads it via SessionInfo) -- external contract
total_num_mutations  # unused attribute (boofuzz session attr, set externally)

# CombinedMonitor property asserted by tests/unit/fuzz/test_monitors_loop2.py
health_signal_available  # unused property (monitor API, tested)

# Test-support functions called from tests/, not src/
reset_for_tests  # unused function (test-support, tests/unit/utils/test_crash_report.py)
_resolve_dist_name  # unused function (test-support, tests/unit/test_dist_name_resolution.py)

# Fuzzer registry introspection helper (kept for CLI/SDK diagnostics parity
# with install_hint); tested in tests/unit/fuzz/test_protocol_registry_tolerant.py
import_error_for  # unused function (fuzz protocol-registry API, tested)

# Deprecated backward-compat property asserted by
# tests/unit/fuzz/test_iec104_fuzzer.py (send_seq == 0)
send_seq  # unused property (iec104 fuzzer backward-compat, tested)

# Protocol documentation tables: kept as the authoritative name→value mapping
# so future code/docs/tests have one source; referenced by test docstrings
ADS_DEV_DATA_OFFSETS  # unused variable (ads constants doc-table, test-referenced)

# Passive listeners dispatched via LISTENER_REGISTRY "class" string entries +
# importlib/getattr in create_listeners() (same pattern as the 94 baselined)
EGDPassiveListener  # unused class (listener_registry dynamic dispatch)
IEEE1722PassiveListener  # unused class (listener_registry dynamic dispatch)
MQTTSNPassiveListener  # unused class (listener_registry dynamic dispatch)
RTPSPassiveListener  # unused class (listener_registry dynamic dispatch)
SELFMPassiveListener  # unused class (listener_registry dynamic dispatch)
TTEPassiveListener  # unused class (listener_registry dynamic dispatch)

# pynetdicom AE attributes: set on the external AE object (self.ae.* = ...)
maximum_pdu_size  # unused attribute (pynetdicom AE, set externally)
network_timeout  # unused attribute (pynetdicom AE, set externally)
acse_timeout  # unused attribute (pynetdicom AE, set externally)
dimse_timeout  # unused attribute (pynetdicom AE, set externally)
connection_timeout  # unused attribute (pynetdicom AE, set externally)

# External client attributes set by assignment (asyncua validator)
certificate_validator  # unused attribute (asyncua client, set externally)

# pynetdicom script context also sets timeouts identically (enumeration mixin)
detected_analyzer  # unused attribute (astm cli_runner, read by unit test)

# NXC-style protocol dispatch classes: imported by name in each protocol
# package __init__ and resolved via getattr(protocol_module, protocol_name)
# in loader.py -- static analysis cannot see the dispatch
ethercat  # unused class (protocols/ethercat/cli_runner.py dispatch class)
