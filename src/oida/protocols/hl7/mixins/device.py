"""
HL7 Device Mixin

Handles IHE PCD (Patient Care Device) messages:
- PCD-01 Device Observation (ORU^R01 with MDC codes)
- PCD-03 Infusion Order (RGV^O15 to pump)
- PCD-04/10 Device Alarm (ORU^R40/R42)
"""

import time
from datetime import datetime
from typing import Optional

from hl7apy.core import Message, Segment

from .. import MDC_CODES, PCD_DEVICE_TYPES, PCD_ALARM_TYPES
from ._helpers import populate_msh


class DeviceMixin:
    """Mixin providing IHE PCD Patient Care Device message operations."""

    def _add_pcd_patient_segments(self, msg: Message):
        """Add PID and PV1 segments common to PCD messages.

        Args:
            msg: HL7 Message to add segments to.
        """
        patient_id = getattr(self.args, "patient_id", None)
        patient_name = getattr(self.args, "patient_name", None)
        pid = self.segment_builder.build_pid(
            patient_id=patient_id or "PCD_TEST001",
            patient_name=patient_name or "DOE^JOHN",
        )
        if pid:
            msg.add(pid)

    def _send_pcd01_message(self):
        """Send PCD-01 Device Observation (ORU^R01 with MDC codes)"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail(
                "PCD-01 (Device Observation) is a write operation. Use --confirm to proceed."
            )
            return

        self.logger.display("Sending PCD-01 Device Observation (ORU^R01)...")

        msg = self._create_pcd01_message()
        if not msg:
            self.logger.fail("PCD-01 message creation failed")
            return

        response = self._send_mllp_message(msg)
        if response:
            self.logger.success("Received PCD-01 response")
            self._parse_response(response)
            self._extract_detailed_response(response, "ORU^R01 (PCD-01)")

            # Security finding if accepted
            ack = self.results["data"].get("ack_code", "")
            if ack == "AA":
                device_type = getattr(self.args, "device_type", "lvp")
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": "PCD-01",
                        "issue": "Device Observation Accepted",
                        "description": f"Server accepted device observation from {device_type} - could inject false readings",
                    }
                )
        else:
            self.logger.warning("No response to PCD-01 message")

    def _create_pcd01_message(self) -> Optional[str]:
        """Create PCD-01 ORU^R01 with device observations using MDC codes.

        Implements IHE DEC (Device Enterprise Communication) profile.
        OBX-4 uses IEEE 11073 hierarchy: MDS.VMD.Channel.Metric
        """
        try:
            version = self._get_version()
            msg = Message("ORU_R01", version=version)

            # MSH segment - identify as device type
            device_type = getattr(self.args, "device_type", "lvp")
            device_mdc = PCD_DEVICE_TYPES.get(device_type, MDC_CODES["DEV_PUMP_INFUS"])
            device_id = getattr(self.args, "device_id", None) or f"DEV_{int(time.time())}"
            obs_time = datetime.now().strftime("%Y%m%d%H%M%S")

            # Device type specific sending application names
            device_apps = {
                "lvp": "INFUSION_PUMP",
                "syringe": "SYRINGE_PUMP",
                "pca": "PCA_PUMP",
                "monitor": "BEDSIDE_MONITOR",
                "ventilator": "VENTILATOR",
                "pulseox": "PULSE_OXIMETER",
            }
            sending_app = f"{device_apps.get(device_type, 'DEVICE')}_{device_id}"

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="ORU^R01^ORU_R01",
                control_prefix="PCD",
                receiving_app="EMR",
                receiving_facility="HOSPITAL",
                sending_app=sending_app,
                sending_facility=getattr(self.args, "sending_facility", "ICU"),
            )

            # PID segment
            self._add_pcd_patient_segments(msg)

            # PV1 segment
            pv1 = self.segment_builder.build_pv1(
                patient_class="I",
                location=getattr(self.args, "location", "ICU^101^A"),
            )
            if pv1:
                msg.add(pv1)

            # OBR segment - device type identifier (Universal Service ID)
            obr = Segment("OBR", version=version)
            obr.obr_1 = "1"
            obr.obr_4 = f"{device_mdc[0]}^{device_mdc[1]}^MDC"
            obr.obr_7 = obs_time  # Observation Date/Time
            msg.add(obr)

            # OBX segments for device observations
            # OBX-4 Sub-ID format: MDS.VMD.Channel.Metric (1.0.0.N)
            obx_seq = 1
            metric_num = 1

            # Helper to create PCD OBX segment
            def add_obx(mdc_code, mdc_unit, value, seq, metric):
                obx = Segment("OBX", version=version)
                obx.obx_1 = str(seq)
                obx.obx_2 = "NM"
                obx.obx_3 = f"{mdc_code[0]}^{mdc_code[1]}^MDC"
                obx.obx_4 = f"1.0.0.{metric}"  # MDS.VMD.Channel.Metric hierarchy
                obx.obx_5 = str(value)
                obx.obx_6 = f"{mdc_unit[0]}^{mdc_unit[1]}^MDC"
                obx.obx_11 = "F"  # Observation Result Status: Final
                obx.obx_14 = obs_time  # Date/Time of Observation
                msg.add(obx)

            # Flow rate (if provided)
            flow_rate = getattr(self.args, "flow_rate", None)
            if flow_rate is not None:
                add_obx(
                    MDC_CODES["FLOW_FLUID_PUMP"],
                    MDC_CODES["DIM_ML_PER_HR"],
                    flow_rate,
                    obx_seq,
                    metric_num,
                )
                obx_seq += 1
                metric_num += 1

            # VTBI (Volume To Be Infused)
            vtbi = getattr(self.args, "vtbi", None)
            if vtbi is not None:
                add_obx(MDC_CODES["VOL_FLUID_TBI"], MDC_CODES["DIM_ML"], vtbi, obx_seq, metric_num)
                obx_seq += 1
                metric_num += 1

            # Volume delivered
            vol_delivered = getattr(self.args, "volume_delivered", None)
            if vol_delivered is not None:
                add_obx(
                    MDC_CODES["VOL_FLUID_DELIV"],
                    MDC_CODES["DIM_ML"],
                    vol_delivered,
                    obx_seq,
                    metric_num,
                )
                obx_seq += 1
                metric_num += 1

            # Drug concentration
            drug_conc = getattr(self.args, "drug_concentration", None)
            if drug_conc is not None:
                add_obx(
                    MDC_CODES["CONC_DRUG"],
                    MDC_CODES["DIM_MG_PER_ML"],
                    drug_conc,
                    obx_seq,
                    metric_num,
                )
                obx_seq += 1
                metric_num += 1

            # Dose rate (ug/kg/min)
            dose_rate = getattr(self.args, "dose_rate", None)
            if dose_rate is not None:
                add_obx(
                    MDC_CODES["RATE_DOSE"],
                    MDC_CODES["DIM_UG_KG_MIN"],
                    dose_rate,
                    obx_seq,
                    metric_num,
                )
                obx_seq += 1
                metric_num += 1

            # Add default observation if none provided
            if obx_seq == 1:
                # Default: flow rate 125 mL/hr for infusion pump
                add_obx(
                    MDC_CODES["FLOW_FLUID_PUMP"],
                    MDC_CODES["DIM_ML_PER_HR"],
                    125,
                    obx_seq,
                    metric_num,
                )

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create PCD-01 message: {e}")
            return self._create_test_message("ORU", "R01")

    def _send_pcd03_message(self):
        """Send PCD-03 Infusion Order (RGV^O15 to pump)"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail(
                "PCD-03 (Infusion Order) is a dangerous operation. Use --confirm to proceed."
            )
            return

        self.logger.display("Sending PCD-03 Infusion Order (RGV^O15)...")

        msg = self._create_pcd03_message()
        if not msg:
            self.logger.fail("PCD-03 message creation failed")
            return

        response = self._send_mllp_message(msg)
        if response:
            self.logger.success("Received PCD-03 response")
            self._parse_response(response)
            self._extract_detailed_response(response, "RGV^O15 (PCD-03)")

            # Security finding if accepted
            ack = self.results["data"].get("ack_code", "")
            if ack == "AA":
                drug = getattr(self.args, "drug_name", "Unknown")
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": "PCD-03",
                        "issue": "Infusion Order Accepted",
                        "description": f"Server accepted infusion order for {drug} - could control pump parameters",
                    }
                )
        else:
            self.logger.warning("No response to PCD-03 message")

    def _create_pcd03_message(self) -> Optional[str]:
        """Create PCD-03 RGV^O15 with infusion parameters"""
        try:
            version = self._get_version()
            msg = Message("RGV_O15", version=version)

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="RGV^O15^RGV_O15",
                control_prefix="PCD3",
                receiving_app="INFUSION_PUMP",
                receiving_facility="ICU",
                sending_app=getattr(self.args, "sending_app", "BCMA"),
                sending_facility=getattr(self.args, "sending_facility", "PHARMACY"),
            )

            # PID segment
            self._add_pcd_patient_segments(msg)

            # ORC segment
            orc = self.segment_builder.build_orc(
                order_control="NW",
                placer_order=f"ORD{int(time.time())}",
                order_status="IP",
            )
            if orc:
                msg.add(orc)

            # RXG segment (Give)
            drug_name = getattr(self.args, "drug_name", None) or getattr(
                self.args, "rx_drug", "Morphine"
            )
            flow_rate = getattr(self.args, "flow_rate", None) or getattr(self.args, "rx_dose", "10")
            vtbi = getattr(self.args, "vtbi", None)
            drug_conc = getattr(self.args, "drug_concentration", None)

            rxg = Segment("RXG", version=version)
            rxg.rxg_1 = "1"  # Give sub-ID
            rxg.rxg_2 = "1"  # Dispense sub-ID
            rxg.rxg_4 = f"^{drug_name}^NDC"  # Give code
            rxg.rxg_5 = str(flow_rate)  # Give amount
            rxg.rxg_7 = getattr(self.args, "rx_units", "mg")  # Give units

            # Include concentration if provided
            if drug_conc:
                rxg.rxg_17 = str(drug_conc)  # Give strength
                rxg.rxg_18 = "mg/mL"  # Give strength units

            msg.add(rxg)

            # TQ1 segment (Timing/Quantity) - for infusion duration
            tq1 = Segment("TQ1", version=version)
            tq1.tq1_1 = "1"  # Set ID
            if vtbi:
                # Calculate duration based on VTBI and flow rate
                tq1.tq1_6 = f"{vtbi}^mL"  # Service duration (as volume)
            else:
                tq1.tq1_6 = "120^min"  # Default 2 hour infusion

            msg.add(tq1)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create PCD-03 message: {e}")
            return self._create_test_message("RGV", "O15")

    def _send_pcd_alarm_message(self):
        """Send PCD-04/10 Device Alarm (ORU^R40/R42)"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail("PCD Alarm message is a write operation. Use --confirm to proceed.")
            return

        alarm_type = getattr(self.args, "alarm_type", "generic")
        self.logger.display(f"Sending PCD-10 Device Alarm ({alarm_type})...")

        msg = self._create_pcd_alarm_message()
        if not msg:
            self.logger.fail("PCD alarm message creation failed")
            return

        response = self._send_mllp_message(msg)
        if response:
            self.logger.success("Received PCD alarm response")
            self._parse_response(response)
            self._extract_detailed_response(response, "ORU^R42 (PCD-10)")

            # Security finding if accepted
            ack = self.results["data"].get("ack_code", "")
            if ack == "AA":
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": "PCD-10",
                        "issue": "Device Alarm Accepted",
                        "description": f"Server accepted {alarm_type} alarm - could inject false alarms",
                    }
                )
        else:
            self.logger.warning("No response to PCD alarm message")

    def _create_pcd_alarm_message(self) -> Optional[str]:
        """Create device alarm message (ORU^R42 / PCD-10)"""
        try:
            version = self._get_version()
            msg = Message("ORU_R01", version=version)  # ORU_R42 may not be in all implementations

            # MSH segment
            device_type = getattr(self.args, "device_type", "lvp")
            device_id = getattr(self.args, "device_id", None) or f"PUMP_{int(time.time())}"

            populate_msh(
                msg,
                self.args,
                version=version,
                msg_type="ORU^R42^ORU_R01",
                control_prefix="EVT",
                receiving_app="EMR",
                receiving_facility="HOSPITAL",
                sending_app=f"PUMP_{device_id}",
                sending_facility=getattr(self.args, "sending_facility", "ICU"),
            )

            # PID segment (optional for device alarms, but useful for context)
            patient_id = getattr(self.args, "patient_id", None)
            if patient_id:
                pid = self.segment_builder.build_pid(
                    patient_id=patient_id,
                    patient_name=getattr(self.args, "patient_name", None) or "DOE^JOHN",
                )
                if pid:
                    msg.add(pid)

            # OBR segment - device type
            device_mdc = PCD_DEVICE_TYPES.get(device_type, MDC_CODES["DEV_PUMP_INFUS"])
            obr = Segment("OBR", version=version)
            obr.obr_1 = "1"
            obr.obr_4 = f"{device_mdc[0]}^{device_mdc[1]}^MDC"
            msg.add(obr)

            # OBX-1: Generic alarm event
            alarm_event = MDC_CODES["EVT_ALARM"]
            obx1 = Segment("OBX", version=version)
            obx1.obx_1 = "1"
            obx1.obx_2 = "CWE"  # Coded with exceptions
            obx1.obx_3 = f"{alarm_event[0]}^{alarm_event[1]}^MDC"

            # Get specific alarm type
            alarm_type = getattr(self.args, "alarm_type", "generic")
            alarm_mdc = PCD_ALARM_TYPES.get(alarm_type, MDC_CODES["EVT_ALARM"])
            obx1.obx_5 = f"{alarm_mdc[0]}^{alarm_mdc[1]}^MDC"
            obx1.obx_11 = "F"
            msg.add(obx1)

            # OBX-2: Alarm description/condition
            alarm_descriptions = {
                "occlusion": "Line Occluded - Check tubing",
                "air": "Air Detected in Line - Prime required",
                "empty": "Container Empty - Replace bag",
                "battery": "Low Battery - Connect to power",
                "generic": "Device Alarm - Check device",
            }
            desc = alarm_descriptions.get(alarm_type, "Device Alarm")

            attr_mdc = MDC_CODES["ATTR_EVT_COND"]
            obx2 = Segment("OBX", version=version)
            obx2.obx_1 = "2"
            obx2.obx_2 = "ST"  # String
            obx2.obx_3 = f"{attr_mdc[0]}^{attr_mdc[1]}^MDC"
            obx2.obx_5 = desc
            obx2.obx_11 = "F"
            msg.add(obx2)

            # OBX-3: Alarm priority (optional)
            priority_mdc = MDC_CODES["ATTR_ALERT_PRIORITY"]
            obx3 = Segment("OBX", version=version)
            obx3.obx_1 = "3"
            obx3.obx_2 = "ST"
            obx3.obx_3 = f"{priority_mdc[0]}^{priority_mdc[1]}^MDC"
            obx3.obx_5 = "HIGH" if alarm_type in ["occlusion", "air"] else "MEDIUM"
            obx3.obx_11 = "F"
            msg.add(obx3)

            return msg.to_er7()

        except Exception as e:
            self.logger.debug(f"Failed to create PCD alarm message: {e}")
            return self._create_test_message("ORU", "R42")
