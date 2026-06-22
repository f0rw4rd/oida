// slop-full.js — Exhaustive slop-check: EVERY src file, no skips.
// One reviewer per directory-coherent cluster (<=14 files each). Each agent
// runs deterministic checks (ruff F401/F841 + vulture@60) AND LLM judgment
// (API-hallucination verified by import, cargo-cult, dead-write, dead-code)
// over its own files, calibrated to oida CLAUDE.md conventions.

export const meta = {
  name: 'slop-full',
  description: 'Exhaustive AI-slop sweep over every oida src file (no skips), clustered by directory.',
  phases: [
    { title: 'Review', detail: 'one reviewer per cluster: ruff+vulture+LLM judgment' },
    { title: 'Report', detail: 'merge cluster findings into prioritized report' },
  ],
}

const clusters = [{"label":"proto/ads","files":["src/oida/protocols/ads/__init__.py","src/oida/protocols/ads/constants.py","src/oida/protocols/ads/ethercat_ops.py","src/oida/protocols/ads/helpers.py","src/oida/protocols/ads/nxc_connection.py","src/oida/protocols/ads/proto_args.py","src/oida/protocols/ads/scanner.py"]},{"label":"proto/astm","files":["src/oida/protocols/astm/__init__.py","src/oida/protocols/astm/mixins/__init__.py","src/oida/protocols/astm/mixins/enumeration.py","src/oida/protocols/astm/mixins/framing.py","src/oida/protocols/astm/mixins/records.py","src/oida/protocols/astm/mixins/security.py","src/oida/protocols/astm/nxc_connection.py","src/oida/protocols/astm/proto_args.py","src/oida/protocols/astm/records.py"]},{"label":"proto/bacnet-1","files":["src/oida/protocols/bacnet/__init__.py","src/oida/protocols/bacnet/constants.py","src/oida/protocols/bacnet/mixins/__init__.py","src/oida/protocols/bacnet/mixins/connection.py","src/oida/protocols/bacnet/mixins/discovery.py","src/oida/protocols/bacnet/mixins/export.py","src/oida/protocols/bacnet/mixins/files.py","src/oida/protocols/bacnet/mixins/monitoring.py","src/oida/protocols/bacnet/mixins/network.py","src/oida/protocols/bacnet/mixins/objects.py","src/oida/protocols/bacnet/mixins/properties.py","src/oida/protocols/bacnet/mixins/security.py","src/oida/protocols/bacnet/mixins/state.py","src/oida/protocols/bacnet/nxc_connection.py"]},{"label":"proto/bacnet-2","files":["src/oida/protocols/bacnet/proto_args.py"]},{"label":"proto/can","files":["src/oida/protocols/can/__init__.py","src/oida/protocols/can/constants.py","src/oida/protocols/can/mixins/__init__.py","src/oida/protocols/can/mixins/canopen.py","src/oida/protocols/can/mixins/isotp.py","src/oida/protocols/can/mixins/traffic.py","src/oida/protocols/can/mixins/uds.py","src/oida/protocols/can/mixins/xcp.py","src/oida/protocols/can/nxc_connection.py","src/oida/protocols/can/proto_args.py","src/oida/protocols/can/scanner.py"]},{"label":"proto/coap","files":["src/oida/protocols/coap/__init__.py","src/oida/protocols/coap/constants.py","src/oida/protocols/coap/helpers.py","src/oida/protocols/coap/nxc_connection.py","src/oida/protocols/coap/proto_args.py","src/oida/protocols/coap/scanner.py"]},{"label":"proto/dicom","files":["src/oida/protocols/dicom/__init__.py","src/oida/protocols/dicom/mixins/__init__.py","src/oida/protocols/dicom/mixins/cfind.py","src/oida/protocols/dicom/mixins/enumeration.py","src/oida/protocols/dicom/mixins/fuzz.py","src/oida/protocols/dicom/mixins/operations.py","src/oida/protocols/dicom/mixins/reporting.py","src/oida/protocols/dicom/mixins/worklist.py","src/oida/protocols/dicom/nxc_connection.py","src/oida/protocols/dicom/proto_args.py"]},{"label":"proto/discovery-1","files":["src/oida/protocols/discovery/__init__.py","src/oida/protocols/discovery/arp.py","src/oida/protocols/discovery/base.py","src/oida/protocols/discovery/core.py","src/oida/protocols/discovery/dhcp.py","src/oida/protocols/discovery/dhcpv6.py","src/oida/protocols/discovery/eigrp_passive.py","src/oida/protocols/discovery/enrich.py","src/oida/protocols/discovery/file_carving.py","src/oida/protocols/discovery/file_extraction.py","src/oida/protocols/discovery/fins.py","src/oida/protocols/discovery/hsrp.py","src/oida/protocols/discovery/ics.py","src/oida/protocols/discovery/igmp.py"]},{"label":"proto/discovery-2","files":["src/oida/protocols/discovery/infra.py","src/oida/protocols/discovery/ipv4_resolve.py","src/oida/protocols/discovery/ipv6.py","src/oida/protocols/discovery/lldp.py","src/oida/protocols/discovery/mdns.py","src/oida/protocols/discovery/netmanage.py","src/oida/protocols/discovery/network.py","src/oida/protocols/discovery/ntp.py","src/oida/protocols/discovery/ospf_passive.py","src/oida/protocols/discovery/pim_passive.py","src/oida/protocols/discovery/proto_args.py","src/oida/protocols/discovery/rip_passive.py","src/oida/protocols/discovery/scanner.py","src/oida/protocols/discovery/ssdp.py"]},{"label":"proto/discovery-3","files":["src/oida/protocols/discovery/stats.py","src/oida/protocols/discovery/vendor.py","src/oida/protocols/discovery/vrrp.py"]},{"label":"proto/dnp3","files":["src/oida/protocols/dnp3/__init__.py","src/oida/protocols/dnp3/constants.py","src/oida/protocols/dnp3/mixins/__init__.py","src/oida/protocols/dnp3/mixins/control.py","src/oida/protocols/dnp3/mixins/file_transfer.py","src/oida/protocols/dnp3/mixins/polling.py","src/oida/protocols/dnp3/nxc_connection.py","src/oida/protocols/dnp3/proto_args.py","src/oida/protocols/dnp3/scanner.py"]},{"label":"proto/ethercat","files":["src/oida/protocols/ethercat/__init__.py","src/oida/protocols/ethercat/advanced_ops.py","src/oida/protocols/ethercat/coe.py","src/oida/protocols/ethercat/coe_ops.py","src/oida/protocols/ethercat/constants.py","src/oida/protocols/ethercat/eeprom.py","src/oida/protocols/ethercat/eeprom_ops.py","src/oida/protocols/ethercat/foe.py","src/oida/protocols/ethercat/fsoe.py","src/oida/protocols/ethercat/fuzzing_ops.py","src/oida/protocols/ethercat/nxc_connection.py","src/oida/protocols/ethercat/proto_args.py","src/oida/protocols/ethercat/reporting.py","src/oida/protocols/ethercat/soe.py"]},{"label":"proto/ethernetip-1","files":["src/oida/protocols/ethernetip/__init__.py","src/oida/protocols/ethernetip/attacks.py","src/oida/protocols/ethernetip/cip_definitions.py","src/oida/protocols/ethernetip/constants.py","src/oida/protocols/ethernetip/mixins/__init__.py","src/oida/protocols/ethernetip/mixins/advanced_parsers.py","src/oida/protocols/ethernetip/mixins/attacks.py","src/oida/protocols/ethernetip/mixins/cip_objects.py","src/oida/protocols/ethernetip/mixins/cip_security.py","src/oida/protocols/ethernetip/mixins/class_explorer.py","src/oida/protocols/ethernetip/mixins/controller_info.py","src/oida/protocols/ethernetip/mixins/discovery.py","src/oida/protocols/ethernetip/mixins/enip_commands.py","src/oida/protocols/ethernetip/mixins/fuzz.py"]},{"label":"proto/ethernetip-2","files":["src/oida/protocols/ethernetip/mixins/network_parsers.py","src/oida/protocols/ethernetip/mixins/security_analysis.py","src/oida/protocols/ethernetip/mixins/write_test.py","src/oida/protocols/ethernetip/nxc_connection.py","src/oida/protocols/ethernetip/parsers.py","src/oida/protocols/ethernetip/proto_args.py","src/oida/protocols/ethernetip/scanner.py"]},{"label":"proto/fhir","files":["src/oida/protocols/fhir/__init__.py","src/oida/protocols/fhir/helpers.py","src/oida/protocols/fhir/mixins/__init__.py","src/oida/protocols/fhir/mixins/crud.py","src/oida/protocols/fhir/mixins/search.py","src/oida/protocols/fhir/mixins/security.py","src/oida/protocols/fhir/nxc_connection.py","src/oida/protocols/fhir/proto_args.py","src/oida/protocols/fhir/resources.py"]},{"label":"proto/goose","files":["src/oida/protocols/goose/__init__.py","src/oida/protocols/goose/nxc_connection.py","src/oida/protocols/goose/proto_args.py"]},{"label":"proto/hart","files":["src/oida/protocols/hart/__init__.py","src/oida/protocols/hart/hartip.py","src/oida/protocols/hart/mixins/__init__.py","src/oida/protocols/hart/mixins/device_info.py","src/oida/protocols/hart/mixins/enumeration.py","src/oida/protocols/hart/mixins/fuzz.py","src/oida/protocols/hart/mixins/security.py","src/oida/protocols/hart/nxc_connection.py","src/oida/protocols/hart/proto_args.py","src/oida/protocols/hart/scanner.py"]},{"label":"proto/hl7-1","files":["src/oida/protocols/hl7/__init__.py","src/oida/protocols/hl7/mixins/__init__.py","src/oida/protocols/hl7/mixins/_helpers.py","src/oida/protocols/hl7/mixins/continuation.py","src/oida/protocols/hl7/mixins/device.py","src/oida/protocols/hl7/mixins/enum.py","src/oida/protocols/hl7/mixins/financial.py","src/oida/protocols/hl7/mixins/fuzz.py","src/oida/protocols/hl7/mixins/master_file.py","src/oida/protocols/hl7/mixins/message.py","src/oida/protocols/hl7/mixins/pharmacy.py","src/oida/protocols/hl7/mixins/probe.py","src/oida/protocols/hl7/mixins/query.py","src/oida/protocols/hl7/mixins/response.py"]},{"label":"proto/hl7-2","files":["src/oida/protocols/hl7/mixins/security.py","src/oida/protocols/hl7/mixins/special_query.py","src/oida/protocols/hl7/proto_args.py","src/oida/protocols/hl7/segments.py","src/oida/protocols/hl7/utils.py"]},{"label":"proto/iec104","files":["src/oida/protocols/iec104/__init__.py","src/oida/protocols/iec104/_deps.py","src/oida/protocols/iec104/commands.py","src/oida/protocols/iec104/constants.py","src/oida/protocols/iec104/listen.py","src/oida/protocols/iec104/nxc_connection.py","src/oida/protocols/iec104/proto_args.py","src/oida/protocols/iec104/scanner.py","src/oida/protocols/iec104/serial.py"]},{"label":"proto/knx-1","files":["src/oida/protocols/knx/__init__.py","src/oida/protocols/knx/bcu.py","src/oida/protocols/knx/cemi_handler.py","src/oida/protocols/knx/constants.py","src/oida/protocols/knx/data.py","src/oida/protocols/knx/ets.py","src/oida/protocols/knx/helpers.py","src/oida/protocols/knx/mixins/__init__.py","src/oida/protocols/knx/mixins/device_info.py","src/oida/protocols/knx/mixins/discovery.py","src/oida/protocols/knx/mixins/memory.py","src/oida/protocols/knx/mixins/properties.py","src/oida/protocols/knx/mixins/security.py","src/oida/protocols/knx/nxc_connection.py"]},{"label":"proto/knx-2","files":["src/oida/protocols/knx/proto_args.py","src/oida/protocols/knx/scanner.py"]},{"label":"proto/mms","files":["src/oida/protocols/mms/__init__.py","src/oida/protocols/mms/fingerprint.py","src/oida/protocols/mms/nxc_connection.py","src/oida/protocols/mms/proto_args.py"]},{"label":"proto/modbus-1","files":["src/oida/protocols/modbus/__init__.py","src/oida/protocols/modbus/constants.py","src/oida/protocols/modbus/convert_maps.py","src/oida/protocols/modbus/decoder.py","src/oida/protocols/modbus/import_maps.py","src/oida/protocols/modbus/mixins/__init__.py","src/oida/protocols/modbus/mixins/canopen.py","src/oida/protocols/modbus/mixins/diagnostics.py","src/oida/protocols/modbus/mixins/events.py","src/oida/protocols/modbus/mixins/files.py","src/oida/protocols/modbus/mixins/fuzz.py","src/oida/protocols/modbus/mixins/identification.py","src/oida/protocols/modbus/mixins/monitor.py","src/oida/protocols/modbus/mixins/raw_function_codes.py"]},{"label":"proto/modbus-2","files":["src/oida/protocols/modbus/mixins/read_write.py","src/oida/protocols/modbus/mixins/sunspec.py","src/oida/protocols/modbus/mixins/sunspec_constants.py","src/oida/protocols/modbus/mixins/writes.py","src/oida/protocols/modbus/nxc_connection.py","src/oida/protocols/modbus/proto_args.py","src/oida/protocols/modbus/register_io.py","src/oida/protocols/modbus/register_maps/__init__.py","src/oida/protocols/modbus/scanner.py","src/oida/protocols/modbus/scanner_mixins/__init__.py","src/oida/protocols/modbus/scanner_mixins/comm_events.py","src/oida/protocols/modbus/scanner_mixins/custom_fc.py","src/oida/protocols/modbus/scanner_mixins/diagnostics.py","src/oida/protocols/modbus/scanner_mixins/discovery.py"]},{"label":"proto/modbus-3","files":["src/oida/protocols/modbus/scanner_mixins/file_ops.py","src/oida/protocols/modbus/scanner_mixins/identification.py","src/oida/protocols/modbus/scanner_mixins/reporting.py","src/oida/protocols/modbus/scanner_mixins/write_ops.py","src/oida/protocols/modbus/validate_maps.py"]},{"label":"proto/mqtt","files":["src/oida/protocols/mqtt/__init__.py","src/oida/protocols/mqtt/mixins/__init__.py","src/oida/protocols/mqtt/mixins/auth.py","src/oida/protocols/mqtt/mixins/connection.py","src/oida/protocols/mqtt/mixins/messaging.py","src/oida/protocols/mqtt/mixins/security.py","src/oida/protocols/mqtt/mixins/topic_discovery.py","src/oida/protocols/mqtt/nxc_connection.py","src/oida/protocols/mqtt/proto_args.py","src/oida/protocols/mqtt/scanner.py"]},{"label":"proto/ocpp","files":["src/oida/protocols/ocpp/__init__.py","src/oida/protocols/ocpp/constants.py","src/oida/protocols/ocpp/mixins/__init__.py","src/oida/protocols/ocpp/mixins/charging.py","src/oida/protocols/ocpp/mixins/discovery.py","src/oida/protocols/ocpp/mixins/messages.py","src/oida/protocols/ocpp/mixins/security.py","src/oida/protocols/ocpp/proto_args.py","src/oida/protocols/ocpp/scanner.py"]},{"label":"proto/opcua-1","files":["src/oida/protocols/opcua/__init__.py","src/oida/protocols/opcua/handlers.py","src/oida/protocols/opcua/helpers.py","src/oida/protocols/opcua/mixins/__init__.py","src/oida/protocols/opcua/mixins/browse.py","src/oida/protocols/opcua/mixins/credentials.py","src/oida/protocols/opcua/mixins/discovery.py","src/oida/protocols/opcua/mixins/files.py","src/oida/protocols/opcua/mixins/fuzz.py","src/oida/protocols/opcua/mixins/history.py","src/oida/protocols/opcua/mixins/methods.py","src/oida/protocols/opcua/mixins/security.py","src/oida/protocols/opcua/mixins/subscriptions.py","src/oida/protocols/opcua/mixins/writes.py"]},{"label":"proto/opcua-2","files":["src/oida/protocols/opcua/nxc_connection.py","src/oida/protocols/opcua/proto_args.py","src/oida/protocols/opcua/scanner.py"]},{"label":"proto/pcap","files":["src/oida/protocols/pcap/__init__.py","src/oida/protocols/pcap/listener_registry.py","src/oida/protocols/pcap/proto_args.py","src/oida/protocols/pcap/scanner.py"]},{"label":"proto/profinet","files":["src/oida/protocols/profinet/__init__.py","src/oida/protocols/profinet/gsdml_parser.py","src/oida/protocols/profinet/helpers.py","src/oida/protocols/profinet/mixins/__init__.py","src/oida/protocols/profinet/mixins/cyclic.py","src/oida/protocols/profinet/mixins/enumeration.py","src/oida/protocols/profinet/mixins/fuzz.py","src/oida/protocols/profinet/mixins/rpc.py","src/oida/protocols/profinet/models.py","src/oida/protocols/profinet/proto_args.py"]},{"label":"proto/snap7","files":["src/oida/protocols/snap7/__init__.py","src/oida/protocols/snap7/constants.py","src/oida/protocols/snap7/device_lookup.py","src/oida/protocols/snap7/mixins/__init__.py","src/oida/protocols/snap7/mixins/block_operations.py","src/oida/protocols/snap7/mixins/device_info.py","src/oida/protocols/snap7/mixins/memory.py","src/oida/protocols/snap7/mixins/security.py","src/oida/protocols/snap7/mixins/slot_scan.py","src/oida/protocols/snap7/models.py","src/oida/protocols/snap7/nxc_connection.py","src/oida/protocols/snap7/proto_args.py","src/oida/protocols/snap7/scanner.py","src/oida/protocols/snap7/szl_parser.py"]},{"label":"proto/snmp","files":["src/oida/protocols/snmp/__init__.py","src/oida/protocols/snmp/constants.py","src/oida/protocols/snmp/mixins/__init__.py","src/oida/protocols/snmp/mixins/brute_force.py","src/oida/protocols/snmp/mixins/host_enumeration.py","src/oida/protocols/snmp/mixins/raw_queries.py","src/oida/protocols/snmp/mixins/v3_enumeration.py","src/oida/protocols/snmp/mixins/version_detection.py","src/oida/protocols/snmp/mixins/write_access.py","src/oida/protocols/snmp/nxc_connection.py","src/oida/protocols/snmp/proto_args.py","src/oida/protocols/snmp/scanner.py"]},{"label":"proto/tase2","files":["src/oida/protocols/tase2/__init__.py","src/oida/protocols/tase2/mixins/__init__.py","src/oida/protocols/tase2/mixins/control.py","src/oida/protocols/tase2/mixins/discovery.py","src/oida/protocols/tase2/mixins/enumeration.py","src/oida/protocols/tase2/mixins/info_messages.py","src/oida/protocols/tase2/mixins/security.py","src/oida/protocols/tase2/mixins/transfer_sets.py","src/oida/protocols/tase2/nxc_connection.py","src/oida/protocols/tase2/proto_args.py","src/oida/protocols/tase2/scanner.py"]},{"label":"pcap-1","files":["src/oida/pcap/__init__.py","src/oida/pcap/ads.py","src/oida/pcap/ajp.py","src/oida/pcap/amqp.py","src/oida/pcap/bacnet.py","src/oida/pcap/bfd.py","src/oida/pcap/bgp.py","src/oida/pcap/c1222.py","src/oida/pcap/can.py","src/oida/pcap/canopen.py","src/oida/pcap/cdp.py","src/oida/pcap/cipsafety.py","src/oida/pcap/coap.py","src/oida/pcap/cotp.py"]},{"label":"pcap-2","files":["src/oida/pcap/devicenet.py","src/oida/pcap/dhcp.py","src/oida/pcap/dicom.py","src/oida/pcap/dnp3.py","src/oida/pcap/dns.py","src/oida/pcap/dtp.py","src/oida/pcap/eigrp.py","src/oida/pcap/enip.py","src/oida/pcap/epl.py","src/oida/pcap/ethercat.py","src/oida/pcap/ff_hse.py","src/oida/pcap/file_carving.py","src/oida/pcap/fins.py","src/oida/pcap/ftp.py"]},{"label":"pcap-3","files":["src/oida/pcap/glbp.py","src/oida/pcap/goose.py","src/oida/pcap/hartip.py","src/oida/pcap/hl7.py","src/oida/pcap/hsr.py","src/oida/pcap/hsrp.py","src/oida/pcap/http.py","src/oida/pcap/ibmmq.py","src/oida/pcap/iec101.py","src/oida/pcap/iec103.py","src/oida/pcap/iec104.py","src/oida/pcap/igmp.py","src/oida/pcap/imap.py","src/oida/pcap/interactions.py"]},{"label":"pcap-4","files":["src/oida/pcap/ipmi.py","src/oida/pcap/ipp.py","src/oida/pcap/ipsec.py","src/oida/pcap/irc.py","src/oida/pcap/iscsi.py","src/oida/pcap/j1939.py","src/oida/pcap/kerberos.py","src/oida/pcap/knx.py","src/oida/pcap/ldap.py","src/oida/pcap/lldp.py","src/oida/pcap/lontalk.py","src/oida/pcap/mdns.py","src/oida/pcap/memcached.py","src/oida/pcap/mms.py"]},{"label":"pcap-5","files":["src/oida/pcap/modbus.py","src/oida/pcap/mongodb.py","src/oida/pcap/mqtt.py","src/oida/pcap/msrpc.py","src/oida/pcap/mssql.py","src/oida/pcap/mysql.py","src/oida/pcap/netbios.py","src/oida/pcap/nfs.py","src/oida/pcap/nmea0183.py","src/oida/pcap/ntlm.py","src/oida/pcap/ntp.py","src/oida/pcap/opcda.py","src/oida/pcap/opcua.py","src/oida/pcap/opensafety.py"]},{"label":"pcap-6","files":["src/oida/pcap/ospf.py","src/oida/pcap/pap.py","src/oida/pcap/pcom.py","src/oida/pcap/pgsql.py","src/oida/pcap/pim.py","src/oida/pcap/pjl.py","src/oida/pcap/pop3.py","src/oida/pcap/profinet.py","src/oida/pcap/prp.py","src/oida/pcap/ptp.py","src/oida/pcap/pyshark_base.py","src/oida/pcap/radius.py","src/oida/pcap/rdp.py","src/oida/pcap/redis.py"]},{"label":"pcap-7","files":["src/oida/pcap/rgoose.py","src/oida/pcap/rip.py","src/oida/pcap/rmi.py","src/oida/pcap/rpcbind.py","src/oida/pcap/rsync.py","src/oida/pcap/rtsp.py","src/oida/pcap/s7comm.py","src/oida/pcap/sercos.py","src/oida/pcap/sip.py","src/oida/pcap/smartinstall.py","src/oida/pcap/smb.py","src/oida/pcap/smtp.py","src/oida/pcap/snmp.py","src/oida/pcap/socks.py"]},{"label":"pcap-8","files":["src/oida/pcap/ssdp.py","src/oida/pcap/stp.py","src/oida/pcap/sv.py","src/oida/pcap/synchrophasor.py","src/oida/pcap/tacacs.py","src/oida/pcap/telnet.py","src/oida/pcap/tftp.py","src/oida/pcap/tls.py","src/oida/pcap/tns.py","src/oida/pcap/vnc.py","src/oida/pcap/vrrp.py","src/oida/pcap/vtp.py","src/oida/pcap/wsdiscovery.py","src/oida/pcap/x11.py"]},{"label":"fuzz/core-1","files":["src/oida/fuzz/core/__init__.py","src/oida/fuzz/core/application.py","src/oida/fuzz/core/auth.py","src/oida/fuzz/core/base_fuzzer.py","src/oida/fuzz/core/calibration.py","src/oida/fuzz/core/codecs/__init__.py","src/oida/fuzz/core/codecs/asn1.py","src/oida/fuzz/core/codecs/mms.py","src/oida/fuzz/core/codecs/opcua.py","src/oida/fuzz/core/config.py","src/oida/fuzz/core/connections/__init__.py","src/oida/fuzz/core/connections/base.py","src/oida/fuzz/core/connections/raw_socket.py","src/oida/fuzz/core/connections/scapy.py"]},{"label":"fuzz/core-2","files":["src/oida/fuzz/core/connections/serial.py","src/oida/fuzz/core/connections/stateful.py","src/oida/fuzz/core/connections/tcp.py","src/oida/fuzz/core/database/__init__.py","src/oida/fuzz/core/database/interface.py","src/oida/fuzz/core/database/mock.py","src/oida/fuzz/core/database/models.py","src/oida/fuzz/core/database/orm.py","src/oida/fuzz/core/mutation/__init__.py","src/oida/fuzz/core/mutation/config.py","src/oida/fuzz/core/mutation/radamsa.py","src/oida/fuzz/core/mutation/radamsa_native.py","src/oida/fuzz/core/session/__init__.py","src/oida/fuzz/core/session/commands.py"]},{"label":"fuzz/core-3","files":["src/oida/fuzz/core/session/crypto_state.py","src/oida/fuzz/core/session/logging.py","src/oida/fuzz/core/session/manager.py","src/oida/fuzz/core/session/sequence.py","src/oida/fuzz/core/session/state_context.py","src/oida/fuzz/core/session/state_machine.py","src/oida/fuzz/core/session/test_case.py","src/oida/fuzz/core/stateful_fuzzer.py"]},{"label":"fuzz/monitors","files":["src/oida/fuzz/monitors/__init__.py","src/oida/fuzz/monitors/agent.py","src/oida/fuzz/monitors/application.py","src/oida/fuzz/monitors/base.py","src/oida/fuzz/monitors/http2.py","src/oida/fuzz/monitors/industrial.py","src/oida/fuzz/monitors/infrastructure.py","src/oida/fuzz/monitors/medical.py","src/oida/fuzz/monitors/network.py","src/oida/fuzz/monitors/opcua.py","src/oida/fuzz/monitors/registry.py","src/oida/fuzz/monitors/script.py"]},{"label":"fuzz/primitives-1","files":["src/oida/fuzz/primitives/__init__.py","src/oida/fuzz/primitives/asn1.py","src/oida/fuzz/primitives/asn1_blocks.py","src/oida/fuzz/primitives/delimited.py","src/oida/fuzz/primitives/dynamic.py","src/oida/fuzz/primitives/osi.py","src/oida/fuzz/primitives/radamsa_primitives.py","src/oida/fuzz/primitives/reduced_string.py","src/oida/fuzz/primitives/smart_string.py","src/oida/fuzz/primitives/tcp_data_offset.py","src/oida/fuzz/primitives/transformers/__init__.py","src/oida/fuzz/primitives/transformers/authentication.py","src/oida/fuzz/primitives/transformers/base.py","src/oida/fuzz/primitives/transformers/compression.py"]},{"label":"fuzz/primitives-2","files":["src/oida/fuzz/primitives/transformers/encoding.py"]},{"label":"fuzz/protocols-1","files":["src/oida/fuzz/protocols/__init__.py","src/oida/fuzz/protocols/_metadata.py","src/oida/fuzz/protocols/ads.py","src/oida/fuzz/protocols/bacnet.py","src/oida/fuzz/protocols/coap.py","src/oida/fuzz/protocols/daytime.py","src/oida/fuzz/protocols/dhcp.py","src/oida/fuzz/protocols/dnp3.py","src/oida/fuzz/protocols/dns.py","src/oida/fuzz/protocols/echo.py","src/oida/fuzz/protocols/ethernet.py","src/oida/fuzz/protocols/ethernetip.py","src/oida/fuzz/protocols/ftp.py","src/oida/fuzz/protocols/hl7.py"]},{"label":"fuzz/protocols-2","files":["src/oida/fuzz/protocols/http2.py","src/oida/fuzz/protocols/http_protocol.py","src/oida/fuzz/protocols/icmp.py","src/oida/fuzz/protocols/icmpv6.py","src/oida/fuzz/protocols/iec104.py","src/oida/fuzz/protocols/ipv4.py","src/oida/fuzz/protocols/ipv6.py","src/oida/fuzz/protocols/mdns.py","src/oida/fuzz/protocols/mms.py","src/oida/fuzz/protocols/modbus/__init__.py","src/oida/fuzz/protocols/modbus/constants.py","src/oida/fuzz/protocols/modbus/pdu.py","src/oida/fuzz/protocols/modbus/rtu.py","src/oida/fuzz/protocols/modbus/tcp.py"]},{"label":"fuzz/protocols-3","files":["src/oida/fuzz/protocols/mqtt.py","src/oida/fuzz/protocols/mutation.py","src/oida/fuzz/protocols/ntp.py","src/oida/fuzz/protocols/opcua.py","src/oida/fuzz/protocols/opcua_constants.py","src/oida/fuzz/protocols/smtp.py","src/oida/fuzz/protocols/snmp_common.py","src/oida/fuzz/protocols/snmpv1.py","src/oida/fuzz/protocols/snmpv2.py","src/oida/fuzz/protocols/snmpv3.py","src/oida/fuzz/protocols/tcp.py","src/oida/fuzz/protocols/tcp_state_integration.py","src/oida/fuzz/protocols/tftp.py","src/oida/fuzz/protocols/vnc.py"]},{"label":"fuzz/utils","files":["src/oida/fuzz/utils/__init__.py"]},{"label":"fuzz/_top","files":["src/oida/fuzz/__init__.py"]},{"label":"utils-1","files":["src/oida/utils/__init__.py","src/oida/utils/base_scanner.py","src/oida/utils/cli.py","src/oida/utils/common_types.py","src/oida/utils/default_credentials.py","src/oida/utils/exceptions.py","src/oida/utils/export_utils.py","src/oida/utils/fuzzer.py","src/oida/utils/ics_logger.py","src/oida/utils/iface_info.py","src/oida/utils/lazy_import.py","src/oida/utils/login_scanner.py","src/oida/utils/mixin_protocol.py","src/oida/utils/payload.py"]},{"label":"utils-2","files":["src/oida/utils/permissions.py","src/oida/utils/platform_compat.py","src/oida/utils/proto_args_factory.py","src/oida/utils/protocol_helpers.py","src/oida/utils/protocol_registry.py","src/oida/utils/rate_limiter.py","src/oida/utils/security_findings.py","src/oida/utils/serial_detection.py","src/oida/utils/socket_helpers.py","src/oida/utils/vendor_maps.py"]},{"label":"shared","files":["src/oida/shared/__init__.py","src/oida/shared/file_carving_common.py","src/oida/shared/glbp_constants.py","src/oida/shared/hsrp_constants.py","src/oida/shared/igmp_constants.py","src/oida/shared/ospf_constants.py","src/oida/shared/pim_constants.py"]},{"label":"core","files":["src/oida/__init__.py","src/oida/__main__.py","src/oida/cli.py","src/oida/connection.py","src/oida/fuzz_cli.py","src/oida/loader.py","src/oida/protocols/__init__.py","src/oida/serial_cli.py","src/oida/targets.py"]}]

const FINDINGS_SCHEMA = {
  type: 'object',
  required: ['cluster', 'findings'],
  additionalProperties: false,
  properties: {
    cluster: { type: 'string' },
    files_reviewed: { type: 'integer' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['severity', 'category', 'title', 'location', 'description'],
        additionalProperties: false,
        properties: {
          severity: { type: 'string', enum: ['HIGH', 'MEDIUM', 'LOW'] },
          category: {
            type: 'string',
            enum: ['api-hallucination', 'cargo-cult', 'dead-write', 'dead-code',
                   'fluff', 'defensive-slop', 'oversized', 'slopsquat'],
          },
          title: { type: 'string' },
          location: { type: 'string' },
          description: { type: 'string' },
          suggested_fix: { type: 'string' },
        },
      },
    },
    notes: { type: 'string' },
  },
}

const ROOT = '/home/f0rw4rd/pro/oida'

const reviewPrompt = (c) => `
You are doing an EXHAUSTIVE AI-slop review of the cluster "${c.label}" in the
oida repo (cwd = ${ROOT}). Use the venv binaries: ${ROOT}/.venv/bin/python,
${ROOT}/.venv/bin/ruff, ${ROOT}/.venv/bin/vulture.

FILES IN THIS CLUSTER (review EVERY one - no skips):
${c.files.map(f => '  - ' + f).join('\n')}

STEP 1 - Deterministic (run, parse, fold into findings):
  ${ROOT}/.venv/bin/ruff check --select F401,F841 ${c.files.join(' ')} --output-format concise
  ${ROOT}/.venv/bin/vulture --min-confidence 60 ${c.files.join(' ')}

STEP 2 - Read every file. Hunt these slop classes:

(a) api-hallucination - calls to third-party (PyPI) symbols that DO NOT EXIST or
    have wrong signatures in the INSTALLED version. VERIFY each by running:
      ${ROOT}/.venv/bin/python -c "import LIB; print(hasattr(LIB,'NAME'))"
    Also flag getattr/hasattr with a default that silently masks a typo'd attr
    name (MEDIUM). IGNORE first-party imports (oida.*, relative). Do NOT
    speculate - run the check.

(b) cargo-cult / over-engineering - wrapper-around-wrapper, single-call-site
    helpers/factories, abstract base with one subclass, params with defaults no
    caller overrides, dead try/except guarding an impossible path, 3+ duplicated
    near-identical helpers. For each: "what NAMED failure mode does this address?"
    If none and it could be inlined, flag it.

(c) dead-write - self.X / dict["k"]=v / ctx.set("k",..) where NO reader exists
    anywhere. Verify with: grep -rn 'self\.X\b' src/ tests/. Docstrings/comments
    are NOT readers. Reflection consumers (getattr(self,..), vars(self), to_dict,
    asdict, __dict__ scans) DO count - do not flag those.

(d) dead-code - unused functions/methods/classes vulture flags. But CONFIRM by
    grep before flagging; many are dynamically dispatched (see calibration).

(e) fluff - narrating comments ("# This function ...", "# Here's ...",
    "# First, ... Then, ...") that restate the code. LOW only.

CALIBRATION - these are LEGITIMATE here; do NOT flag:
  - src/oida/pcap/*PassiveListener classes: dynamically loaded via the pcap
    registry/__getattr__. vulture calls them "unused" - they are NOT.
  - __getattr__/__dir__ lazy-import shims in __init__.py: intentional.
  - src/oida/fuzz/protocols/* dispatch tables & primitive builders that look
    repetitive - that repetition IS the fuzzer. Flag only vulture-confirmed dead.
  - NXC nxc_connection.py / mixins/*: "log + continue" try/except is the
    documented pattern (except Exception as e: logger.debug(...); logger.fail(...)).
    Flag ONLY a pure swallow: except with NO debug AND NO fail/log.
  - Callback params required by a library signature (userdata, signum, cbCtx,
    frame, option_string) - required, not dead.
  - prefer_native in fuzz mutation: documented kept-for-API-compat. LOW at most.

Severity: HIGH = definite real defect (nonexistent API, vulture-confirmed dead
function with zero callers, large dead-write block). MEDIUM = real over-abstraction
or silent-mask with no failure mode. LOW = fluff / borderline.

Adversarially verify EVERY candidate before flagging. Be terse and specific.
Return findings via schema. cluster = "${c.label}". files_reviewed = ${c.files.length}.
If clean, findings: [].
`.trim()

phase('Review')
const results = await parallel(
  clusters.map(c => () =>
    agent(reviewPrompt(c), {
      label: `rev:${c.label}`,
      phase: 'Review',
      agentType: 'general-purpose',
      schema: FINDINGS_SCHEMA,
    })
  )
)

const ok = results.filter(Boolean)
const failed = clusters.filter((c, i) => !results[i]).map(c => c.label)
const all = ok.flatMap(r => (r.findings || []).map(f => ({ ...f, cluster: r.cluster })))
const sev = { HIGH: 0, MEDIUM: 0, LOW: 0 }
for (const f of all) sev[f.severity] = (sev[f.severity] || 0) + 1
const filesReviewed = ok.reduce((n, r) => n + (r.files_reviewed || 0), 0)
log(`Review: ${ok.length}/${clusters.length} clusters, ${filesReviewed} files, ${all.length} findings (H=${sev.HIGH} M=${sev.MEDIUM} L=${sev.LOW}); failed=[${failed.join(', ')}]`)

phase('Report')
const reportPrompt = `
Synthesize a SLOP-CHECK report. ${filesReviewed} oida src files reviewed across
${ok.length} clusters (failed clusters: ${failed.join(', ') || 'none'}).
Severity totals: HIGH=${sev.HIGH} MEDIUM=${sev.MEDIUM} LOW=${sev.LOW}.

FINDINGS (JSON):
\`\`\`json
${JSON.stringify(all, null, 2).slice(0, 160000)}
\`\`\`

Write the report to ${ROOT}/SLOP_REPORT.md with this structure:

# /slop-check report - full src sweep (${filesReviewed} files, no skips)

<one-line stats: files reviewed, clusters, severity counts.>

## HIGH - likely real defects
For each HIGH finding:
- **\`file:line\`** - title. description. *Fix:* one-line.

## MEDIUM - review and confirm
Same shape.

## LOW - calibration / cleanup
Group by category; for fluff give 1-2 examples per cluster, not every match.

## Coverage & skips
- ${filesReviewed} files reviewed; failed clusters (re-run needed): ${failed.join(', ') || 'none'}.

## Calibration notes
2-4 sentences: which apparent signals were false positives (pcap dynamic
listeners, fuzzer dispatch tables, NXC log+continue) and should be weighted down.

PRINCIPLES: dedup identical defects to highest severity; cite file:line on EVERY
finding (no line -> drop it); no emojis; terse. If nothing found, say so plainly.

After writing the file, return a 5-line plain-text summary (counts + the single
most important HIGH finding if any).
`.trim()

const summary = await agent(reportPrompt, {
  label: 'synthesize',
  phase: 'Report',
  agentType: 'general-purpose',
})

return {
  clusters: clusters.length,
  clusters_ok: ok.length,
  files_reviewed: filesReviewed,
  failed_clusters: failed,
  findings: all.length,
  severity: sev,
  report_path: `${ROOT}/SLOP_REPORT.md`,
  summary,
}
