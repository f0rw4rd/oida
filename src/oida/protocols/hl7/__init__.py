"""
HL7 v2 Protocol Scanner

Scans HL7 v2.x MLLP (Minimal Lower Layer Protocol) endpoints for:
- Connection testing (MLLP handshake)
- Message exchange (ADT, ORM, ORU, SIU, QRY, MDM)
- Version fingerprinting (MSH segment parsing)
- Patient/Order/Observation data interaction
- Security assessment (no native auth = security gap)

CLI examples:
    oida hl7 192.168.1.100              # Basic connection test
    oida hl7 192.168.1.100 --send-adt   # Send ADT test message
    oida hl7 192.168.1.100 --send-orm --patient-id PT001 --order-code CBC  # Order message
    oida hl7 192.168.1.100 --send-qry --patient-id PT001  # Query message
    oida hl7 192.168.1.100 --fuzz       # Message fuzzing
"""

import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from ...connection import NetworkConnection
from ...utils.protocol_helpers import ConnectionHelper
from ...utils.lazy_import import lazy_import
from .segments import HL7SegmentBuilder, HL7SegmentParser
from .utils import MLLP_END, MLLP_START, extract_ack_code, strip_mllp, wrap_mllp  # noqa: F401 (MLLP_START re-exported)

_hl7apy = lazy_import("hl7apy", "HL7", install_hint="pip install oida[hl7]")


__all__ = ["HL7SegmentBuilder", "HL7SegmentParser", "hl7", "HL7APY_AVAILABLE"]

# HL7 Sending Application to Vendor/Product mapping
# Used to identify healthcare IT systems from MSH-3 field
HL7_VENDOR_MAP = {
    # Major EMR/EHR Systems
    "EPIC": ("Epic Systems", "EMR"),
    "EPICCARE": ("Epic Systems", "EpicCare Ambulatory"),
    "BEAKER": ("Epic Systems", "Beaker LIS"),
    "RADIANT": ("Epic Systems", "Radiant RIS"),
    "CUPID": ("Epic Systems", "Cupid Cardiology"),
    "CERNER": ("Cerner Corporation", "Millennium EMR"),
    "POWERCHART": ("Cerner Corporation", "PowerChart"),
    "PATHNET": ("Cerner Corporation", "PathNet LIS"),
    "MEDITECH": ("Meditech", "MAGIC/CS EMR"),
    "EXPANSE": ("Meditech", "Expanse EHR"),
    "ALLSCRIPTS": ("Allscripts", "Sunrise Clinical Manager"),
    "SUNRISE": ("Allscripts", "Sunrise EMR"),
    "PARAGON": ("Allscripts", "Paragon EHR"),
    "ATHENA": ("Athenahealth", "athenaOne"),
    "ATHENAHEALTH": ("Athenahealth", "Cloud EHR"),
    "NEXTGEN": ("NextGen Healthcare", "NextGen EHR"),
    "ECLINICALWORKS": ("eClinicalWorks", "Cloud EHR"),
    "ECW": ("eClinicalWorks", "eClinicalWorks"),
    "GREENWAY": ("Greenway Health", "Intergy"),
    "VERADIGM": ("Veradigm", "Practice Fusion"),
    "MODERNMD": ("ModernMD", "ModernMD EHR"),
    "DRCHRONO": ("DrChrono", "DrChrono EHR"),
    "KAREO": ("Kareo", "Kareo EHR"),
    "ADVANCEDMD": ("AdvancedMD", "AdvancedMD EHR"),
    # Interface Engines / Integration Platforms
    "MIRTH": ("NextGen", "Mirth Connect"),
    "MIRTHCONNECT": ("NextGen", "Mirth Connect"),
    "RHAPSODY": ("Rhapsody", "Rhapsody Integration Engine"),
    "COREPOINT": ("Lyniate", "Corepoint Integration Engine"),
    "CLOVERLEAF": ("Infor", "Cloverleaf"),
    "IGUANA": ("iNTERFACEWARE", "Iguana"),
    "ENSEMBLE": ("InterSystems", "Ensemble/HealthShare"),
    "HEALTHSHARE": ("InterSystems", "HealthShare"),
    "IRIS": ("InterSystems", "IRIS for Health"),
    "ORION": ("Orion Health", "Rhapsody"),
    "BRIDGEIT": ("Optum", "BridgeIT"),
    "BIZTALK": ("Microsoft", "BizTalk Server"),
    "TIBCO": ("TIBCO", "TIBCO BusinessWorks"),
    "JBOSS": ("Red Hat", "JBoss Fuse"),
    "MULESOFT": ("Salesforce", "MuleSoft Anypoint"),
    # Laboratory Information Systems (LIS)
    "SUNQUEST": ("Sunquest", "Sunquest LIS"),
    "SOFTLAB": ("SCC Soft", "SoftLab LIS"),
    "LABDAQ": ("Comp Pro Med", "LabDAQ"),
    "ORCHARD": ("Orchard Software", "Harvest LIS"),
    "PSYCHE": ("PSYCHE Systems", "PSYCHE LIS"),
    "LABCORP": ("LabCorp", "LabCorp LIS"),
    "QUEST": ("Quest Diagnostics", "Quest LIS"),
    "STARLIMS": ("Abbott", "STARLIMS"),
    # Radiology / PACS
    "MCKESSON": ("McKesson", "Radiology PACS"),
    "AGFA": ("Agfa HealthCare", "IMPAX"),
    "IMPAX": ("Agfa HealthCare", "IMPAX PACS"),
    "SECTRA": ("Sectra", "Sectra PACS"),
    "PHILIPS": ("Philips", "IntelliSpace"),
    "INTELLISPACE": ("Philips", "IntelliSpace PACS"),
    "CARESTREAM": ("Carestream", "Vue PACS"),
    "SIEMENS": ("Siemens Healthineers", "syngo"),
    "SYNGO": ("Siemens Healthineers", "syngo.via"),
    "GE": ("GE Healthcare", "Centricity"),
    "CENTRICITY": ("GE Healthcare", "Centricity PACS/RIS"),
    # Pharmacy Systems
    "PYXIS": ("BD", "Pyxis MedStation"),
    "OMNICELL": ("Omnicell", "Omnicell Automation"),
    "BAXTER": ("Baxter", "Pharmacy Systems"),
    "SCRIPTPRO": ("ScriptPro", "SP Central"),
    "MCKESSON_PHARM": ("McKesson", "Pharmacy Automation"),
    # Blood Bank / Transfusion
    "HCLL": ("HCLL", "SafeTrace Tx"),
    "MEDIWARE": ("Haemonetics", "HCLL SafeTrace"),
    "SOFTEK": ("Softek", "Illuminate"),
    # Cardiology / Monitoring
    "MUSE": ("GE Healthcare", "MUSE ECG"),
    "MORTARA": ("Philips", "Mortara ECG"),
    "SPACELABS": ("Spacelabs", "Patient Monitoring"),
    "DRAEGER": ("Dräger", "Patient Monitoring"),
    "PHILIPS_MON": ("Philips", "IntelliVue"),
    # Scheduling / ADT
    "AMION": ("Amion", "Physician Scheduling"),
    "QGENDA": ("QGenda", "Provider Scheduling"),
    "CENTRALSCHED": ("API Healthcare", "Central Scheduling"),
    # Revenue Cycle / Billing
    "OPTUM": ("Optum", "Revenue Cycle"),
    "WAYSTAR": ("Waystar", "Revenue Cycle"),
    "AVAILITY": ("Availity", "Revenue Cycle"),
    "CHANGE": ("Change Healthcare", "Claims Management"),
    "CHANGEHC": ("Change Healthcare", "Assurance Platform"),
    # Generic / Test
    "TEST": ("Test System", "Development/Test"),
    "DEV": ("Development", "Development System"),
    "TRAINING": ("Training", "Training System"),
    "LAB": ("Laboratory", "Lab Test System"),
    "HOSPITAL": ("Hospital", "Generic Hospital System"),
    "CLINIC": ("Clinic", "Generic Clinic System"),
    "OIDA": ("OIDA", "Security Scanner"),
}

# IEEE 11073-10101 MDC Codes for IHE PCD (Patient Care Device) profiles
# Used in ORU^R01 (PCD-01), RGV^O15 (PCD-03), ORU^R40/R42 (PCD-04/10)
# Reference: NIST RTMMS (https://rtmms.nist.gov), IEEE 11073-10101:2019
MDC_CODES = {
    # Device Types - MDS (Medical Device System) level
    "DEV_MON_PHYSIO_MULTI_PARAM_MDS": (69965, "MDC_DEV_MON_PHYSIO_MULTI_PARAM_MDS"),
    "DEV_ANALY_SAT_O2_MDS": (69801, "MDC_DEV_ANALY_SAT_O2_MDS"),
    "DEV_PUMP_INFUS_MDS": (69985, "MDC_DEV_PUMP_INFUS_MDS"),
    "DEV_VENT_MDS": (70667, "MDC_DEV_VENT_MDS"),
    # Device Types - VMD (Virtual Medical Device) level
    "DEV_PUMP_INFUS": (69981, "MDC_DEV_PUMP_INFUS_VMD"),
    "DEV_PUMP_INFUS_SYRINGE": (69985, "MDC_DEV_PUMP_INFUS_SYRINGE_VMD"),
    "DEV_PUMP_INFUS_PCA": (69989, "MDC_DEV_PUMP_INFUS_PCA_VMD"),
    "DEV_PUMP_INFUS_CHAN": (69977, "MDC_DEV_PUMP_INFUS_CHAN"),
    "DEV_PULSEOX": (69877, "MDC_DEV_ANALY_SAT_O2_VMD"),
    "DEV_MONITOR": (69965, "MDC_DEV_METER_PHYSIO_MULTI_PARAM_VMD"),
    "DEV_VENT": (70057, "MDC_DEV_VENT_VMD"),
    # Infusion Pump Parameters (Partition 2 - SCADA/Metric)
    "FLOW_FLUID_PUMP": (157985, "MDC_FLOW_FLUID_PUMP"),
    "CONC_DRUG": (157986, "MDC_CONC_DRUG"),
    "RATE_DOSE": (157924, "MDC_RATE_DOSE"),
    "VOL_FLUID_TBI": (157993, "MDC_VOL_FLUID_TBI"),
    "VOL_FLUID_TBI_REMAIN": (157872, "MDC_VOL_FLUID_TBI_REMAIN"),
    "VOL_FLUID_DELIV": (157994, "MDC_VOL_FLUID_DELIV"),
    "TIME_PD_REMAIN": (157997, "MDC_TIME_PD_REMAIN"),
    # Vital Signs / Physiological (Partition 2)
    "ECG_HEART_RATE": (147842, "MDC_ECG_HEART_RATE"),
    "SAT_O2": (150456, "MDC_PULS_OXIM_SAT_O2"),
    "PULS_RATE": (149530, "MDC_PULS_RATE"),
    "RESP_RATE": (151562, "MDC_RESP_RATE"),
    "PRESS_BLD_NONINV_SYS": (150020, "MDC_PRESS_BLD_NONINV_SYS"),
    "PRESS_BLD_NONINV_DIA": (150021, "MDC_PRESS_BLD_NONINV_DIA"),
    "PRESS_BLD_NONINV_MEAN": (150022, "MDC_PRESS_BLD_NONINV_MEAN"),
    "PRESS_BLD_ART_SYS": (150016, "MDC_PRESS_BLD_ART_SYS"),
    "PRESS_BLD_ART_DIA": (150017, "MDC_PRESS_BLD_ART_DIA"),
    "PRESS_BLD_ART_MEAN": (150018, "MDC_PRESS_BLD_ART_MEAN"),
    "TEMP": (188740, "MDC_TEMP"),
    "TEMP_CORE": (188420, "MDC_TEMP_CORE"),
    "TEMP_SKIN": (188424, "MDC_TEMP_SKIN"),
    "AWAY_CO2_ET": (151708, "MDC_AWAY_CO2_ET"),
    # Ventilator Parameters
    "VOL_AWAY_TIDAL": (151708, "MDC_VOL_AWAY_TIDAL"),
    "VENT_PRESS_AWAY_INSP_PEAK": (151973, "MDC_VENT_PRESS_AWAY_INSP_PEAK"),
    "VENT_RESP_RATE_SETTING": (151586, "MDC_VENT_RESP_RATE_SETTING"),
    "VENT_VOL_MINUTE": (152004, "MDC_VENT_VOL_MINUTE"),
    "VENT_CONC_AWAY_O2": (152016, "MDC_VENT_CONC_AWAY_O2"),
    # Alarm/Event Codes (Partition 3 - Events)
    "EVT_ALARM": (68480, "MDC_EVT_ALARM"),
    "EVT_OCCLUSION": (196616, "MDC_EVT_OCCLUSION"),
    "EVT_AIR_IN_LINE": (196614, "MDC_EVT_AIR_IN_LINE"),
    "EVT_EMPTY": (196618, "MDC_EVT_EMPTY"),
    "EVT_BATTERY_LOW": (196620, "MDC_EVT_BATTERY_LOW"),
    "EVT_PUMP_DOOR_OPEN": (196620, "MDC_EVT_DOOR_OPEN"),
    "EVT_HI_CRIT": (196608, "MDC_EVT_HI_CRIT"),
    "EVT_LO_CRIT": (196609, "MDC_EVT_LO_CRIT"),
    "EVT_PUMP": (68484, "MDC_EVT_PUMP"),
    "EVT_INFUSION_START": (196650, "MDC_EVT_INFUSION_START"),
    "EVT_INFUSION_STOP": (196651, "MDC_EVT_INFUSION_STOP"),
    "EVT_INFUSION_PAUSE": (196652, "MDC_EVT_INFUSION_PAUSE"),
    # Alarm Attributes
    "ATTR_EVT_COND": (68481, "MDC_ATTR_EVT_COND"),
    "ATTR_ALERT_PRIORITY": (68481, "MDC_ATTR_ALERT_PRIORITY"),
    "ATTR_ALERT_STATE": (68482, "MDC_ATTR_ALERT_STATE"),
    "ATTR_ALERT_SOURCE": (68483, "MDC_ATTR_ALERT_SOURCE"),
    "ATTR_EVT_SOURCE": (68485, "MDC_ATTR_EVT_SOURCE"),
    "ATTR_DRUG_NAME": (68486, "MDC_ATTR_DRUG_NAME"),
    # Units of Measurement (Partition 4 - Dimensions)
    "DIM_ML_PER_HR": (265266, "MDC_DIM_MILLI_L_PER_HR"),
    "DIM_ML": (263762, "MDC_DIM_MILLI_L"),
    "DIM_UG_KG_MIN": (264352, "MDC_DIM_MICRO_G_PER_KG_PER_MIN"),
    "DIM_MG_PER_HR": (264320, "MDC_DIM_MILLI_G_PER_HR"),
    "DIM_MG_PER_ML": (264736, "MDC_DIM_MILLI_G_PER_ML"),
    "DIM_PERCENT": (262688, "MDC_DIM_PERCENT"),
    "DIM_BEAT_PER_MIN": (264864, "MDC_DIM_BEAT_PER_MIN"),
    "DIM_RESP_PER_MIN": (264928, "MDC_DIM_RESP_PER_MIN"),
    "DIM_MMHG": (266016, "MDC_DIM_MMHG"),
    "DIM_KILO_PASCAL": (266560, "MDC_DIM_KILO_PASCAL"),
    "DIM_DEGC": (266112, "MDC_DIM_DEGC"),
    "DIM_FAHR": (266272, "MDC_DIM_FAHR"),
    "DIM_CM_H2O": (266048, "MDC_DIM_CM_H2O"),
    "DIM_MIN": (264320, "MDC_DIM_MIN"),
}

# Device type to MDC code mapping (VMD level for OBR-4)
PCD_DEVICE_TYPES = {
    "lvp": MDC_CODES["DEV_PUMP_INFUS"],
    "syringe": MDC_CODES["DEV_PUMP_INFUS_SYRINGE"],
    "pca": MDC_CODES["DEV_PUMP_INFUS_PCA"],
    "monitor": MDC_CODES["DEV_MON_PHYSIO_MULTI_PARAM_MDS"],
    "ventilator": MDC_CODES["DEV_VENT_MDS"],
    "pulseox": MDC_CODES["DEV_ANALY_SAT_O2_MDS"],
}

# Alarm type to MDC code mapping
PCD_ALARM_TYPES = {
    "occlusion": MDC_CODES["EVT_OCCLUSION"],
    "air": MDC_CODES["EVT_AIR_IN_LINE"],
    "empty": MDC_CODES["EVT_EMPTY"],
    "battery": MDC_CODES["EVT_BATTERY_LOW"],
    "generic": MDC_CODES["EVT_ALARM"],
}


# hl7apy availability check (actual import deferred until use)
HL7APY_AVAILABLE = _hl7apy.is_available

# Import all mixins (these also require hl7apy)
if HL7APY_AVAILABLE:
    from .mixins import (
        MessageMixin,
        QueryMixin,
        PharmacyMixin,
        ResponseMixin,
        EnumMixin,
        ProbeMixin,
        MasterFileMixin,
        SpecialQueryMixin,
        FinancialMixin,
        DeviceMixin,
        FuzzMixin,
        SecurityMixin,
        ContinuationMixin,
    )
else:
    # Mixins require hl7apy - create stubs so the module can still be imported
    class _MixinStub:
        pass

    MessageMixin = _MixinStub
    QueryMixin = _MixinStub
    PharmacyMixin = _MixinStub
    ResponseMixin = _MixinStub
    EnumMixin = _MixinStub
    ProbeMixin = _MixinStub
    MasterFileMixin = _MixinStub
    SpecialQueryMixin = _MixinStub
    FinancialMixin = _MixinStub
    DeviceMixin = _MixinStub
    FuzzMixin = _MixinStub
    SecurityMixin = _MixinStub
    ContinuationMixin = _MixinStub


class hl7(
    MessageMixin,
    QueryMixin,
    PharmacyMixin,
    ResponseMixin,
    EnumMixin,
    ProbeMixin,
    MasterFileMixin,
    SpecialQueryMixin,
    FinancialMixin,
    DeviceMixin,
    FuzzMixin,
    SecurityMixin,
    ContinuationMixin,
    NetworkConnection,
):
    """HL7 v2 MLLP Scanner (NXC-style)"""

    def __init__(self, args: Any, db: Optional[Any], host: str):
        self.protocol_name = "hl7"
        self.default_port = 2575
        self.segment_builder = None
        self.all_responses = []  # Track all responses for export
        self.detected_version = None  # Auto-detected from server response
        super().__init__(args, db, host)

    def _get_version(self) -> str:
        """Get HL7 version - explicit user override wins, then auto-detected, then default"""
        # An explicit --hl7-version always wins (default is None = not specified)
        user_version = getattr(self.args, "hl7_version", None)
        if user_version:
            return user_version
        # Use auto-detected version from server
        if self.detected_version:
            return self.detected_version
        # Fallback to default
        return "2.5"

    def proto_flow(self):
        """Main HL7 scanning workflow"""

        if not HL7APY_AVAILABLE:
            self.logger.fail(
                "hl7apy library required for HL7 protocol. Install with: pip install oida[hl7]"
            )
            self.results["success"] = False
            self.results["error"] = "hl7apy dependency not available"
            return

        # Initialize segment builder (uses default version, will be updated after server response)
        self.segment_builder = HL7SegmentBuilder(version=self._get_version())

        # Handle --enum-all as alias for all enumeration options
        if getattr(self.args, "enum_all", False):
            self.args.enum_providers = True
            self.args.enum_apps = True
            self.args.enum_locations = True
            self.args.enum_patients = True  # Query for patients
            self.args.query_obs = True  # Query for observations/lab results
            self.args.query_rx = True  # Query for medications
            self.args.query_orders = True  # Query for orders
            self.args.extract_response = True  # Extract extended data

        # Create connection
        if not self.create_conn_obj():
            return

        # Probe operations if requested (runs before other operations)
        if getattr(self.args, "probe_ops", False):
            self._probe_operations()
            self._analyze_security()
            self._export_results()
            self._disconnect()
            return

        # Enumerate host info
        self.enum_host_info()
        self.print_host_info()

        # Send test messages based on args
        if getattr(self.args, "send_adt", False):
            self._send_adt_message()

        if getattr(self.args, "send_oru", False):
            self._send_oru_message()

        if getattr(self.args, "send_orm", False):
            self._send_orm_message()

        if getattr(self.args, "send_rx", False):
            self._send_rx_message()

        if getattr(self.args, "send_ras", False):
            self._send_ras_message()

        if getattr(self.args, "send_rgv", False):
            self._send_rgv_message()

        if getattr(self.args, "send_rds", False):
            self._send_rds_message()

        if getattr(self.args, "send_siu", False):
            self._send_siu_message()

        if getattr(self.args, "send_qry", False) or getattr(self.args, "enum_patients", False):
            self._send_qry_message()

        if getattr(self.args, "query_obs", False):
            self._send_qry_obs_message()

        if getattr(self.args, "query_rx", False):
            self._send_qry_rx_message()

        if getattr(self.args, "query_orders", False):
            self._send_qry_orders_message()

        if getattr(self.args, "send_mdm", False):
            self._send_mdm_message()

        # MFN (Master File) operations
        if getattr(self.args, "send_mfn", False):
            self._send_mfn_message()

        if getattr(self.args, "query_mfn", False):
            self._send_mfq_message()

        # QBP Special queries
        if getattr(self.args, "query_whoami", False):
            self._send_qbp_q40_message()

        if getattr(self.args, "query_tabular", False):
            self._send_qbp_q13_message()

        if getattr(self.args, "query_imm", False):
            self._send_qbp_z34_message()

        if getattr(self.args, "query_imm_forecast", False):
            self._send_qbp_z44_message()

        # BAR/DFT Financial operations
        if getattr(self.args, "send_bar", False):
            self._send_bar_message()

        if getattr(self.args, "send_dft", False):
            self._send_dft_message()

        # IHE PCD (Patient Care Device) operations
        if getattr(self.args, "pcd_01", False):
            self._send_pcd01_message()

        if getattr(self.args, "pcd_03", False):
            self._send_pcd03_message()

        if getattr(self.args, "pcd_alarm", False):
            self._send_pcd_alarm_message()

        if getattr(self.args, "message_type", None):
            self._send_custom_message(self.args.message_type)

        if getattr(self.args, "fuzz", False):
            self._fuzz_messages()

        # Enumeration features
        if getattr(self.args, "enum_providers", False):
            self._enum_providers()

        if getattr(self.args, "enum_apps", False):
            self._enum_apps()

        if getattr(self.args, "enum_locations", False):
            self._enum_locations()

        # Analyze security
        self._analyze_security()

        # Export results if requested
        self._export_results()

        # Cleanup
        self._disconnect()

    def create_conn_obj(self) -> bool:
        """Establish MLLP TCP connection (optionally with TLS)"""
        port = getattr(self.args, "port", self.default_port)
        timeout = getattr(self.args, "timeout", 10)
        use_tls = getattr(self.args, "tls", False)

        try:
            self.conn = ConnectionHelper.create_tls_tcp_connection(
                self.ip,
                port,
                timeout=timeout,
                use_tls=use_tls,
                tls_cert=getattr(self.args, "tls_cert", None),
                tls_key=getattr(self.args, "tls_key", None),
                tls_ca=getattr(self.args, "tls_ca", None),
                tls_insecure=getattr(self.args, "tls_insecure", False),
                # Verify the cert against the original hostname (not the resolved
                # IP) so DNS-SAN certs match when --tls-ca is supplied.
                server_hostname=getattr(self, "host", None) or self.ip,
                protocol="hl7",
                endpoint_label="MLLP endpoint",
                logger=self.logger,
            )

            # Display client identity
            client_app = getattr(self.args, "sending_app", "OIDA")
            client_facility = getattr(self.args, "sending_facility", "SECURITY")
            self.logger.display(f"  Client: {client_app}@{client_facility}")

            self.results["data"]["connected"] = True
            self.results["data"]["tls_enabled"] = use_tls
            return True
        except TimeoutError as e:
            self.logger.debug(f"create conn obj failed: {e}")
            self.logger.fail("Connection timed out")
            self.results["data"]["connected"] = False
            return False
        except ConnectionRefusedError as e:
            self.logger.debug(f"create conn obj failed: {e}")
            self.logger.fail("Connection refused")
            self.results["data"]["connected"] = False
            return False
        except Exception as e:
            self.logger.debug(f"create conn obj failed: {e}")
            self.logger.fail(f"Connection failed: {e}")
            self.results["data"]["connected"] = False
            return False

    def enum_host_info(self):
        """Test MLLP connection with a read-only query.

        Sends QBP^Q11 (Display-Based Response, read-only) rather than
        the legacy ADT^A01 admission write. ADT^A01 created a fake
        patient admission on the target on every scan — every operator
        running ``oida hl7 <ip>`` was silently writing to the target's
        EMR / clinical interface. Use a read query for fingerprinting.

        QBP^Q11 still surfaces vendor / sending-app / HL7 version in
        the MSA/MSH echo without any server-side data change.
        """
        test_msg = self._create_test_message("QBP", "Q11")

        if test_msg:
            response = self._send_mllp_message(test_msg)
            if response:
                self._parse_response(response)

                # Confirmed successful MLLP exchange. MLLP is TLS-optional;
                # without TLS, PHI is transmitted in cleartext on the wire.
                if not getattr(self.args, "tls", False):
                    self.results["data"].setdefault("security_findings", []).append(
                        {
                            "operation": "MLLP",
                            "issue": "No encryption",
                            "description": ("HL7 MLLP without TLS -- PHI transmitted in cleartext"),
                        }
                    )

    def print_host_info(self):
        """Display discovered HL7 endpoint info"""
        data = self.results.get("data", {})

        if data.get("server_info"):
            info = data["server_info"]
            sending_app = info.get("sending_app", "Unknown")
            vendor = info.get("vendor")
            product_type = info.get("product_type")

            # Display server identity with vendor identification
            if vendor:
                self.logger.display(
                    f"  Server: {sending_app}@{info.get('sending_facility', 'Unknown')} ({vendor} - {product_type})"
                )
            else:
                self.logger.display(
                    f"  Server: {sending_app}@{info.get('sending_facility', 'Unknown')}"
                )
            self.logger.display(f"  HL7 Version: {info.get('version', 'Unknown')}")

        if data.get("ack_code"):
            ack = data["ack_code"]
            if ack == "AA":
                self.logger.success("  ACK: Application Accept (AA)")
            elif ack == "AE":
                self.logger.warning("  ACK: Application Error (AE)")
            elif ack == "AR":
                self.logger.fail("  ACK: Application Reject (AR)")
            else:
                self.logger.display(f"  ACK: {ack}")

    def _get_fuzz_message_types(self) -> list:
        """Get message types for fuzzing - shared with _probe_operations"""
        return [
            # ADT - Admission/Discharge/Transfer
            ("ADT", "A01", "Admission", "Low"),
            ("ADT", "A04", "Patient Registration", "Low"),
            ("ADT", "A05", "Pre-Admit", "Low"),
            ("ADT", "A08", "Patient Update", "Medium"),
            ("ADT", "A03", "Discharge", "Medium"),
            ("ADT", "A12", "Cancel Transfer", "Low"),
            ("ADT", "A28", "Add Person", "Medium"),
            ("ADT", "A40", "Patient Merge", "HIGH"),
            # Orders and Results
            ("ORM", "O01", "Lab/Procedure Order", "HIGH"),
            ("ORU", "R01", "Observation Result", "Medium"),
            # Queries
            ("QRY", "Q01", "Patient Query", "Medium"),
            ("QBP", "Q13", "Tabular Query", "Low"),
            ("QBP", "Q40", "WhoAmI Query", "Low"),
            ("QBP", "Z34", "Immunization History", "Medium"),
            # Scheduling and Documents
            ("SIU", "S12", "Scheduling", "Low"),
            ("MDM", "T02", "Document Notification", "Medium"),
            # Pharmacy
            ("RDE", "O11", "Pharmacy Order", "HIGH"),
            ("RAS", "O17", "Pharmacy Administration", "HIGH"),
            ("RGV", "O15", "Pharmacy Give", "HIGH"),
            ("RDS", "O13", "Pharmacy Dispense", "HIGH"),
            ("VXU", "V04", "Vaccination Update", "Medium"),
            # Financial/Billing
            ("BAR", "P01", "Add Billing Account", "HIGH"),
            ("DFT", "P03", "Financial Transaction", "HIGH"),
            # Master Files
            ("MFN", "M01", "Master File General", "Medium"),
            ("MFN", "M02", "Master File Staff", "HIGH"),
            ("MFN", "M04", "Master File Charges", "HIGH"),
            ("MFQ", "M01", "Master File Query", "Low"),
        ]

    def _inject_fuzz_segment(self, message: str, segment_name: str) -> str:
        """Inject fuzz-friendly content into a specific segment for targeted fuzzing"""
        segment_name = segment_name.upper()

        # Segment-specific fuzz payloads (oversized, special chars, boundaries)
        fuzz_content = {
            "PID": f"PID|1||{'X' * 500}^^^MRN||{'Y' * 200}^{'Z' * 200}||19800101|U",
            "PV1": f"PV1|1|I|{'LOC' * 100}^^^HOSPITAL|||{'DOC' * 50}^ATTENDING",
            "OBX": f"OBX|1|ST|{'TEST' * 100}||{'VALUE' * 500}|{'UNIT' * 50}",
            "ORC": f"ORC|NW|{'ORD' * 200}|{'FILL' * 200}",
            "RXA": f"RXA|0|1|20240101||{'DRUG' * 100}^{'NAME' * 100}|{'9' * 20}|mg",
            "RXD": f"RXD|1|{'DRUG' * 100}|20240101|{'9' * 20}|TAB",
            "DG1": f"DG1|1|ICD10|{'CODE' * 50}^{'DESC' * 200}",
            "FT1": f"FT1|1|{'TXN' * 100}||20240101||CG|{'CODE' * 100}||{'9' * 20}",
        }

        # If segment exists in message, replace it; otherwise append
        if f"{segment_name}|" in message:
            lines = message.split("\r")
            for i, line in enumerate(lines):
                if line.startswith(f"{segment_name}|"):
                    if segment_name in fuzz_content:
                        lines[i] = fuzz_content[segment_name]
                    break
            return "\r".join(lines)
        elif segment_name in fuzz_content:
            return message + "\r" + fuzz_content[segment_name]

        return message

    def _create_test_message(self, msg_type: str, trigger_event: str) -> Optional[str]:
        """Create an HL7 test message"""
        version = self._get_version()
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        msg_id = f"MSG{int(time.time())}"

        # Try hl7apy first for supported message types
        try:
            from hl7apy.core import Message

            msg = Message(f"{msg_type}_{trigger_event}", version=version)
            msh = msg.msh
            msh.msh_3 = "OIDA"
            msh.msh_4 = "SECURITY"
            msh.msh_5 = "TARGET"
            msh.msh_6 = "FACILITY"
            msh.msh_7 = timestamp
            msh.msh_9 = f"{msg_type}^{trigger_event}"
            msh.msh_10 = msg_id
            msh.msh_11 = "P"
            msh.msh_12 = version
            return msg.to_er7()
        except Exception as e:
            self.logger.debug("create test message failed: %s", e)

        # Fallback: create raw HL7 message for unsupported types
        msh = f"MSH|^~\\&|OIDA|SECURITY|TARGET|FACILITY|{timestamp}||{msg_type}^{trigger_event}|{msg_id}|P|{version}"

        # Add required segments based on message type
        segments = [msh]
        if msg_type == "ADT":
            segments.append("EVN|" + trigger_event + "|" + timestamp)
            segments.append("PID|1||12345^^^MRN||DOE^JOHN||19800115|M")
            segments.append("PV1|1|I|ICU^101^A|||||||||||||||V12345")
        elif msg_type == "QBP":
            segments.append("QPD|" + trigger_event + "|Q001|12345^^^MRN")
            segments.append("RCP|I|10^RD")
        else:
            # Generic fallback with minimal segments
            segments.append("PID|1||12345^^^MRN||DOE^JOHN||19800115|M")

        return "\r".join(segments)

    def _send_mllp_message(self, message: str) -> Optional[bytes]:
        """Send message with MLLP framing and receive response"""
        if not self.conn:
            return None

        try:
            self.conn.sendall(wrap_mllp(message))

            # Receive response with a hard cap so a hostile peer can't drive
            # the scanner to OOM by streaming endless bytes without MLLP_END.
            MAX_HL7_RESPONSE = 16 * 1024 * 1024  # 16 MiB
            response = b""
            while True:
                chunk = self.conn.recv(4096)
                if not chunk:
                    break
                response += chunk
                if MLLP_END in response:
                    break
                if len(response) > MAX_HL7_RESPONSE:
                    self.logger.warning(
                        "HL7 response exceeded %d bytes without MLLP_END; aborting",
                        MAX_HL7_RESPONSE,
                    )
                    return None

            stripped = strip_mllp(response)
            self._handle_response_options(stripped)
            return stripped
        except TimeoutError:
            self.logger.debug("Response timeout")
            return None
        except Exception as e:
            self.logger.debug(f"Send/receive error: {e}")
            return None

    def _handle_response_options(self, response: bytes) -> None:
        """Apply --save-response / --parse-segments to a received response."""
        if not response:
            return

        save_path = getattr(self.args, "save_response", None)
        if save_path:
            try:
                with open(save_path, "ab") as fh:
                    fh.write(response)
                    fh.write(b"\n")
                self.logger.display(f"Saved raw response to {save_path}")
            except OSError as e:
                self.logger.warning(f"Could not save response to {save_path}: {e}")

        if getattr(self.args, "parse_segments", False):
            text = response.decode("utf-8", errors="ignore")
            segments = [s for s in text.replace("\r\n", "\r").replace("\n", "\r").split("\r") if s]
            self.logger.display(f"Response segments ({len(segments)}):")
            for segment in segments:
                seg_id = segment.split("|", 1)[0]
                self.logger.display(f"  [{seg_id}] {segment}")

    def _get_field_value(self, segment, field_name: str) -> str:
        """Extract value from HL7 field, handling hl7apy object types"""
        try:
            if not hasattr(segment, field_name):
                return ""
            field = getattr(segment, field_name)
            # Handle different hl7apy object types
            if hasattr(field, "value"):
                return str(field.value) if field.value else ""
            elif hasattr(field, "to_er7"):
                return field.to_er7()
            else:
                return str(field) if field else ""
        except Exception as e:
            self.logger.debug(f"Field extraction failed for {field_name}: {e}")
            return ""

    def _display_results_table(
        self,
        items: List[Dict],
        column_defs: List[tuple],
        result_key: str,
        result_label: str,
        security_finding: Optional[Dict] = None,
    ) -> None:
        """Display extracted results in a table with dynamic columns.

        Args:
            items: List of dictionaries containing the data to display
            column_defs: List of (key, display_name) tuples defining columns
            result_key: Key to store results under in self.results["data"]
            result_label: Human-readable label for the result type (e.g., "patient(s)")
            security_finding: Optional security finding dict to add if items found
        """
        from ...utils.export_utils import print_table

        if not items:
            self.logger.display(f"  No {result_label} found in response")
            return

        # Store results
        self.results["data"][result_key] = {
            "count": len(items),
            result_label[:-3] if result_label.endswith("(s)") else result_label: items,
        }

        # Build table with only non-empty columns
        active_columns = [(k, d) for k, d in column_defs if any(item.get(k) for item in items)]
        rows = [[item.get(k, "") for k, _ in active_columns] for item in items]
        headers = [d for _, d in active_columns]
        print_table(rows, headers, logger=self.logger)

        self.logger.success(f"Total: {len(items)} {result_label} found")

        if security_finding:
            self.results["data"].setdefault("security_findings", []).append(security_finding)

    def _identify_vendor(self, sending_app: str) -> tuple:
        """
        Identify vendor/product from HL7 Sending Application (MSH-3).

        Args:
            sending_app: The Sending Application value from MSH-3

        Returns:
            Tuple of (vendor_name, product_type) or (None, None) if not found
        """
        if not sending_app:
            return (None, None)

        # Normalize: uppercase and strip whitespace
        app_upper = sending_app.upper().strip()

        # Direct match
        if app_upper in HL7_VENDOR_MAP:
            return HL7_VENDOR_MAP[app_upper]

        # Check if any key is a substring (for compound names like "EPIC_LAB")
        for key, (vendor, product) in HL7_VENDOR_MAP.items():
            if key in app_upper or app_upper.startswith(key):
                return (vendor, product)

        # Try to identify by common patterns
        patterns = [
            ("EPIC", ("Epic Systems", "EMR")),
            ("CERNER", ("Cerner Corporation", "EMR")),
            ("MEDITECH", ("Meditech", "EMR")),
            ("ALLSCRIPTS", ("Allscripts", "EMR")),
            ("MIRTH", ("NextGen", "Mirth Connect")),
            ("RHAPSODY", ("Rhapsody", "Integration Engine")),
            ("GE_", ("GE Healthcare", "Healthcare IT")),
            ("PHILIPS", ("Philips", "Healthcare IT")),
            ("SIEMENS", ("Siemens Healthineers", "Healthcare IT")),
        ]
        for pattern, result in patterns:
            if pattern in app_upper:
                return result

        return (None, None)

    def _parse_response(self, response: bytes):
        """Parse HL7 response message"""
        if not response:
            return

        try:
            msg_str = response.decode("utf-8", errors="ignore")
            from hl7apy.parser import parse_message

            msg = parse_message(msg_str)

            # Extract MSH info
            if hasattr(msg, "msh"):
                msh = msg.msh
                sending_app = self._get_field_value(msh, "msh_3")
                server_version = self._get_field_value(msh, "msh_12")

                # Auto-detect server version for subsequent messages
                if server_version and not self.detected_version:
                    self.detected_version = server_version

                # Identify vendor from sending application
                vendor_name, product_type = self._identify_vendor(sending_app)

                self.results["data"]["server_info"] = {
                    "sending_app": sending_app,
                    "sending_facility": self._get_field_value(msh, "msh_4"),
                    "version": server_version,
                    "message_type": self._get_field_value(msh, "msh_9"),
                    "vendor": vendor_name,
                    "product_type": product_type,
                }

            # Extract MSA (acknowledgment) info. Only ack_code is surfaced
            # (print_host_info); msa_3 ack_text had no reader.
            if hasattr(msg, "msa"):
                msa = msg.msa
                self.results["data"]["ack_code"] = self._get_field_value(msa, "msa_1")

        except Exception as e:
            self.logger.debug(f"Failed to parse response: {e}")
            self.logger.debug(f"Raw response: {response.decode('utf-8', errors='ignore')}")

    def _extract_ack_code(self, response: Optional[bytes]) -> Optional[str]:
        """Extract ACK code from HL7 response.

        Delegates to utils.extract_ack_code(); accepts already-stripped bytes
        (strip_mllp is a no-op when framing is absent).
        """
        if not response:
            return None
        return extract_ack_code(response)

    def _export_results(self):
        """Export collected data using central export_data() utility"""
        from ...utils.export_utils import export_data

        output_dir = getattr(self.args, "output", None)
        if not output_dir:
            return  # No export requested

        fmt = getattr(self.args, "format", "json")
        # Don't print tables to console - data already shown during scan
        file_fmt = fmt.replace("console", "").replace("all", "csv,json").strip(",") or "json"

        data = self.results.get("data", {})
        port = getattr(self.args, "port", self.default_port)

        # Export patient query results - dynamically include all extracted fields
        # _display_results_table stores the list under the singularized label
        # ("patient(s)" -> "patient"), so read that key.
        patients = data.get("query_results", {}).get("patient", [])
        if patients:
            # Find all keys that have data across all patients
            all_keys = set()
            for p in patients:
                all_keys.update(k for k, v in p.items() if v)

            # Order keys sensibly (core fields first, then alphabetical)
            core_order = ["PatientID", "PatientName", "DOB", "Sex", "Phone", "Address", "Account"]
            ordered_keys = [k for k in core_order if k in all_keys]
            ordered_keys.extend(sorted(k for k in all_keys if k not in core_order))

            headers = ["Host", "Port"] + ordered_keys
            rows = [[self.ip, port] + [p.get(k, "") for k in ordered_keys] for p in patients]
            export_data(rows, headers, file_fmt, output_dir, "hl7_patients", logger=self.logger)

        # Export server info
        server_info = data.get("server_info", {})
        if server_info:
            headers = ["Host", "Port", "SendingApp", "Facility", "Version", "Vendor", "ProductType"]
            rows = [
                [
                    self.ip,
                    port,
                    server_info.get("sending_app", ""),
                    server_info.get("sending_facility", ""),
                    server_info.get("version", ""),
                    server_info.get("vendor", ""),
                    server_info.get("product_type", ""),
                ]
            ]
            export_data(rows, headers, file_fmt, output_dir, "hl7_server", logger=self.logger)

        # Export security findings
        findings = data.get("security_findings", [])
        if findings:
            headers = ["Host", "Port", "Operation", "Issue", "Description"]
            rows = [
                [
                    self.ip,
                    port,
                    f.get("operation", ""),
                    f.get("issue", ""),
                    f.get("description", ""),
                ]
                for f in findings
            ]
            export_data(rows, headers, file_fmt, output_dir, "hl7_security", logger=self.logger)

        # Export enumerated providers (--enum-providers)
        providers = data.get("providers", {})
        if providers and any(providers.values()):
            headers = ["Host", "Port", "Category", "Provider"]
            rows = [
                [self.ip, port, category, name]
                for category, names in providers.items()
                for name in names
            ]
            if rows:
                export_data(
                    rows, headers, file_fmt, output_dir, "hl7_providers", logger=self.logger
                )

        # Export interface topology (--enum-apps)
        topology = data.get("interface_topology", {})
        if topology:
            headers = ["Host", "Port", "Application", "Vendor", "Product", "Facility"]
            rows = []
            for app_name, info in topology.get("applications", {}).items():
                facs = info.get("facilities") or [""]
                for fac in facs:
                    rows.append(
                        [
                            self.ip,
                            port,
                            app_name,
                            info.get("vendor", "") or "",
                            info.get("product", "") or "",
                            fac,
                        ]
                    )
            if rows:
                export_data(rows, headers, file_fmt, output_dir, "hl7_apps", logger=self.logger)

        # Export enumerated locations (--enum-locations)
        loc_data = data.get("locations", {})
        if loc_data:
            headers = ["Host", "Port", "Type", "Location"]
            rows = []
            for loc_type, key in (
                ("Nursing Unit", "nursing_units"),
                ("Room", "rooms"),
                ("Bed", "beds"),
                ("Full Location", "full_locations"),
            ):
                rows.extend([self.ip, port, loc_type, v] for v in loc_data.get(key, []))
            if rows:
                export_data(
                    rows, headers, file_fmt, output_dir, "hl7_locations", logger=self.logger
                )

        # Export master file results (--master-file)
        mf_data = data.get("master_file_results", {})
        if mf_data:
            staff = mf_data.get("staff_entries", [])
            if staff:
                keys = ["StaffID", "StaffName", "StaffType", "Department", "ActiveStatus"]
                headers = ["Host", "Port"] + keys
                rows = [[self.ip, port] + [s.get(k, "") for k in keys] for s in staff]
                export_data(rows, headers, file_fmt, output_dir, "hl7_staff", logger=self.logger)
            charges = mf_data.get("charge_entries", [])
            if charges:
                keys = [
                    "PrimaryKeyValue",
                    "Price",
                    "Department",
                    "EffectiveStartDate",
                    "EffectiveEndDate",
                ]
                headers = ["Host", "Port"] + keys
                rows = [[self.ip, port] + [c.get(k, "") for k in keys] for c in charges]
                export_data(rows, headers, file_fmt, output_dir, "hl7_charges", logger=self.logger)

        # Export WhoAmI server identity (--whoami)
        whoami = data.get("whoami_results", {})
        if whoami and any(whoami.values()):
            headers = ["Host", "Port", "ServerApp", "ServerFacility", "Version"]
            rows = [
                [
                    self.ip,
                    port,
                    whoami.get("server_app", ""),
                    whoami.get("server_facility", ""),
                    whoami.get("version", ""),
                ]
            ]
            export_data(rows, headers, file_fmt, output_dir, "hl7_whoami", logger=self.logger)

        # Export tabular (RTB) results (--rtb)
        tabular = data.get("tabular_results", {})
        if tabular and tabular.get("rows"):
            columns = tabular.get("columns") or [
                f"Col{i + 1}" for i in range(len(tabular["rows"][0]))
            ]
            headers = ["Host", "Port"] + columns
            rows = [[self.ip, port] + list(r) for r in tabular["rows"]]
            export_data(rows, headers, file_fmt, output_dir, "hl7_tabular", logger=self.logger)

    def _disconnect(self):
        """Close MLLP connection"""
        if self.conn:
            try:
                self.conn.close()
            except Exception as e:
                self.logger.debug(f"Connection close failed: {e}")
            self.conn = None

    @staticmethod
    def check_dependencies() -> bool:
        """Check if HL7 dependencies are available."""
        return HL7APY_AVAILABLE
