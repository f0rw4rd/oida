"""
HL7 Segment Builder

Helper class for building HL7 v2 message segments with proper field population.
Supports PID, PV1, OBX, OBR, ORC, SCH, TXA segments.
"""

from datetime import datetime
from typing import Any, Optional

import logging

logger = logging.getLogger(__name__)


# Import hl7apy at module load. Availability is gated by HL7APY_AVAILABLE in
# __init__.py (which prints a friendly "pip install oida[hl7]" hint); this local
# import just makes hl7apy.core.Segment available to the builder methods. If the
# dep is missing, Segment stays None and builder calls raise inside their own
# try/except.
try:
    from hl7apy.core import Segment
except ImportError as _hl7_err:  # pragma: no cover — release-checked dep
    Segment = None  # type: ignore[assignment]
    logger.debug("hl7apy not installed; HL7 segment building disabled: %s", _hl7_err)


class HL7SegmentBuilder:
    """Build HL7 v2 message segments with proper field population"""

    def __init__(self, version: str = "2.5"):
        self.version = version

    def build_pid(
        self,
        patient_id: str = "",
        patient_name: str = "",
        dob: str = "",
        sex: str = "",
        address: str = "",
        phone: str = "",
        ssn: str = "",
        set_id: int = 1,
    ) -> Optional[Any]:
        """
        Build PID (Patient Identification) segment

        Args:
            patient_id: Patient ID (PID-3)
            patient_name: Patient name in LAST^FIRST^MIDDLE format (PID-5)
            dob: Date of birth YYYYMMDD (PID-7)
            sex: Sex M/F/O/U (PID-8)
            address: Patient address (PID-11)
            phone: Phone number (PID-13)
            ssn: SSN (PID-19)
            set_id: Set ID (PID-1)

        Returns:
            PID segment or None
        """
        try:
            pid = Segment("PID", version=self.version)
            pid.pid_1 = str(set_id)

            if patient_id:
                # PID-3: Patient ID (CX type)
                pid.pid_3 = f"{patient_id}^^^HOSPITAL^MR"

            if patient_name:
                # PID-5: Patient Name (XPN type) - LAST^FIRST^MIDDLE
                pid.pid_5 = patient_name

            if dob:
                # PID-7: Date of Birth
                pid.pid_7 = dob

            if sex:
                # PID-8: Administrative Sex
                pid.pid_8 = sex

            if address:
                # PID-11: Patient Address (XAD type)
                pid.pid_11 = address

            if phone:
                # PID-13: Phone Number - Home (XTN type)
                pid.pid_13 = phone

            if ssn:
                # PID-19: SSN Number
                pid.pid_19 = ssn

            return pid

        except Exception as e:
            logger.debug(f"Operation failed: {e}")
            return None

    def build_pv1(
        self,
        patient_class: str = "I",
        visit_number: str = "",
        admit_date: str = "",
        attending_doctor: str = "",
        location: str = "",
        set_id: int = 1,
    ) -> Optional[Any]:
        """
        Build PV1 (Patient Visit) segment

        Args:
            patient_class: Patient class I/O/E/P (PV1-2)
            visit_number: Visit number (PV1-19)
            admit_date: Admit date YYYYMMDD (PV1-44)
            attending_doctor: Attending doctor (PV1-7)
            location: Assigned patient location (PV1-3)
            set_id: Set ID (PV1-1)

        Returns:
            PV1 segment or None
        """
        try:
            pv1 = Segment("PV1", version=self.version)
            pv1.pv1_1 = str(set_id)

            # PV1-2: Patient Class (I=Inpatient, O=Outpatient, E=Emergency, P=Preadmit)
            pv1.pv1_2 = patient_class

            if location:
                # PV1-3: Assigned Patient Location (PL type)
                pv1.pv1_3 = location

            if attending_doctor:
                # PV1-7: Attending Doctor (XCN type)
                pv1.pv1_7 = attending_doctor

            if visit_number:
                # PV1-19: Visit Number (CX type)
                pv1.pv1_19 = visit_number

            if admit_date:
                # PV1-44: Admit Date/Time
                pv1.pv1_44 = admit_date

            return pv1

        except Exception as e:
            logger.debug(f"Failed to get pv1: {e}")
            return None

    def build_obx(
        self,
        value_type: str = "NM",
        observation_id: str = "",
        observation_value: str = "",
        units: str = "",
        reference_range: str = "",
        abnormal_flag: str = "",
        set_id: int = 1,
    ) -> Optional[Any]:
        """
        Build OBX (Observation/Result) segment

        Args:
            value_type: Value type NM/ST/TX/CE (OBX-2)
            observation_id: Observation identifier (OBX-3)
            observation_value: Observation value (OBX-5)
            units: Units (OBX-6)
            reference_range: Reference range (OBX-7)
            abnormal_flag: Abnormal flag (OBX-8)
            set_id: Set ID (OBX-1)

        Returns:
            OBX segment or None
        """
        try:
            obx = Segment("OBX", version=self.version)
            obx.obx_1 = str(set_id)

            # OBX-2: Value Type (NM=Numeric, ST=String, TX=Text, CE=Coded)
            obx.obx_2 = value_type

            if observation_id:
                # OBX-3: Observation Identifier (CE type)
                obx.obx_3 = observation_id

            if observation_value:
                # OBX-5: Observation Value
                obx.obx_5 = observation_value

            if units:
                # OBX-6: Units (CE type)
                obx.obx_6 = units

            if reference_range:
                # OBX-7: Reference Range
                obx.obx_7 = reference_range

            if abnormal_flag:
                # OBX-8: Abnormal Flags
                obx.obx_8 = abnormal_flag

            # OBX-11: Observation Result Status (F=Final, P=Preliminary)
            obx.obx_11 = "F"

            return obx

        except Exception as e:
            logger.debug(f"Operation failed: {e}")
            return None

    def build_obr(
        self,
        order_id: str = "",
        filler_order: str = "",
        service_id: str = "",
        priority: str = "R",
        requested_datetime: str = "",
        set_id: int = 1,
    ) -> Optional[Any]:
        """
        Build OBR (Observation Request) segment

        Args:
            order_id: Placer order number (OBR-2)
            filler_order: Filler order number (OBR-3)
            service_id: Universal service ID (OBR-4)
            priority: Priority S/A/R/P (OBR-5)
            requested_datetime: Requested datetime (OBR-6)
            set_id: Set ID (OBR-1)

        Returns:
            OBR segment or None
        """
        try:
            obr = Segment("OBR", version=self.version)
            obr.obr_1 = str(set_id)

            if order_id:
                # OBR-2: Placer Order Number (EI type)
                obr.obr_2 = order_id

            if filler_order:
                # OBR-3: Filler Order Number (EI type)
                obr.obr_3 = filler_order

            if service_id:
                # OBR-4: Universal Service ID (CE type)
                obr.obr_4 = service_id

            if priority:
                # OBR-5: Priority (S=Stat, A=ASAP, R=Routine, P=Preop)
                obr.obr_5 = priority

            if requested_datetime:
                # OBR-6: Requested Date/Time
                obr.obr_6 = requested_datetime

            return obr

        except Exception as e:
            logger.debug(f"HL7: build_obr segment construction failed: {e}")
            return None

    def build_orc(
        self,
        order_control: str = "NW",
        placer_order: str = "",
        filler_order: str = "",
        order_status: str = "",
        set_id: int = 1,
    ) -> Optional[Any]:
        """
        Build ORC (Common Order) segment

        Args:
            order_control: Order control NW/CA/SC/DC (ORC-1)
            placer_order: Placer order number (ORC-2)
            filler_order: Filler order number (ORC-3)
            order_status: Order status (ORC-5)
            set_id: Set ID

        Returns:
            ORC segment or None
        """
        try:
            orc = Segment("ORC", version=self.version)

            # ORC-1: Order Control (NW=New, CA=Cancel, SC=Status Changed, DC=Discontinue)
            orc.orc_1 = order_control

            if placer_order:
                # ORC-2: Placer Order Number (EI type)
                orc.orc_2 = placer_order

            if filler_order:
                # ORC-3: Filler Order Number (EI type)
                orc.orc_3 = filler_order

            if order_status:
                # ORC-5: Order Status
                orc.orc_5 = order_status

            return orc

        except Exception as e:
            logger.debug(f"HL7: build_orc segment construction failed: {e}")
            return None

    def build_sch(
        self,
        placer_appointment_id: str = "",
        filler_appointment_id: str = "",
        event_reason: str = "",
        appointment_type: str = "",
        start_datetime: str = "",
        duration: str = "",
    ) -> Optional[Any]:
        """
        Build SCH (Scheduling Activity Information) segment

        Args:
            placer_appointment_id: Placer appointment ID (SCH-1)
            filler_appointment_id: Filler appointment ID (SCH-2)
            event_reason: Event reason (SCH-6)
            appointment_type: Appointment type (SCH-8)
            start_datetime: Start date/time (SCH-11)
            duration: Duration (SCH-9)

        Returns:
            SCH segment or None
        """
        try:
            sch = Segment("SCH", version=self.version)

            if placer_appointment_id:
                # SCH-1: Placer Appointment ID (EI type)
                sch.sch_1 = placer_appointment_id

            if filler_appointment_id:
                # SCH-2: Filler Appointment ID (EI type)
                sch.sch_2 = filler_appointment_id

            if event_reason:
                # SCH-6: Event Reason (CE type)
                sch.sch_6 = event_reason

            if appointment_type:
                # SCH-8: Appointment Type (CE type)
                sch.sch_8 = appointment_type

            if duration:
                # SCH-9: Appointment Duration
                sch.sch_9 = duration

            if start_datetime:
                # SCH-11: Appointment Timing Quantity (TQ type)
                sch.sch_11 = start_datetime

            return sch

        except Exception as e:
            logger.debug(f"HL7: build_sch segment construction failed: {e}")
            return None

    def build_txa(
        self,
        document_type: str = "",
        document_content_presentation: str = "TX",
        activity_datetime: str = "",
        primary_activity_provider: str = "",
        unique_document_number: str = "",
        document_completion_status: str = "AU",
    ) -> Optional[Any]:
        """
        Build TXA (Transcription Document Header) segment

        Args:
            document_type: Document type (TXA-2)
            document_content_presentation: Content presentation TX/FT/RP (TXA-3)
            activity_datetime: Activity date/time (TXA-4)
            primary_activity_provider: Primary provider (TXA-5)
            unique_document_number: Unique document number (TXA-12)
            document_completion_status: Completion status (TXA-17)

        Returns:
            TXA segment or None
        """
        try:
            txa = Segment("TXA", version=self.version)

            # TXA-1: Set ID
            txa.txa_1 = "1"

            if document_type:
                # TXA-2: Document Type
                txa.txa_2 = document_type

            if document_content_presentation:
                # TXA-3: Document Content Presentation (TX=Text, FT=Formatted, RP=Reference)
                txa.txa_3 = document_content_presentation

            if activity_datetime:
                # TXA-4: Activity Date/Time
                txa.txa_4 = activity_datetime
            else:
                txa.txa_4 = datetime.now().strftime("%Y%m%d%H%M%S")

            if primary_activity_provider:
                # TXA-5: Primary Activity Provider (XCN type)
                txa.txa_5 = primary_activity_provider

            if unique_document_number:
                # TXA-12: Unique Document Number (EI type)
                txa.txa_12 = unique_document_number

            if document_completion_status:
                # TXA-17: Document Completion Status (AU=Authenticated, DI=Dictated)
                txa.txa_17 = document_completion_status

            return txa

        except Exception as e:
            logger.debug(f"Operation failed: {e}")
            return None

    def build_rxo(
        self,
        drug_code: str = "",
        drug_name: str = "",
        requested_dose: str = "",
        requested_units: str = "",
        requested_route: str = "",
        admin_instructions: str = "",
        dispense_amount: str = "",
        dispense_units: str = "",
        refills: str = "",
        ordering_provider: str = "",
    ) -> Optional[Any]:
        """
        Build RXO (Pharmacy/Treatment Order) segment

        Used for prescription/medication order attacks.

        Args:
            drug_code: Drug identifier code (RXO-1)
            drug_name: Drug name (RXO-1 component 2)
            requested_dose: Requested give amount (RXO-2)
            requested_units: Requested give units (RXO-4)
            requested_route: Requested route (RXO-5)
            admin_instructions: Provider's administration instructions (RXO-6)
            dispense_amount: Requested dispense amount (RXO-10)
            dispense_units: Requested dispense units (RXO-11)
            refills: Number of refills (RXO-12)
            ordering_provider: Ordering provider (RXO-14)

        Returns:
            RXO segment or None
        """
        try:
            rxo = Segment("RXO", version=self.version)

            # RXO-1: Requested Give Code (CE type) - drug_code^drug_name^coding_system
            if drug_code or drug_name:
                rxo.rxo_1 = f"{drug_code}^{drug_name}^NDC"

            if requested_dose:
                # RXO-2: Requested Give Amount - Minimum
                rxo.rxo_2 = requested_dose

            if requested_units:
                # RXO-4: Requested Give Units (CE type)
                rxo.rxo_4 = requested_units

            if requested_route:
                # RXO-5: Requested Dosage Form (CE type) - route of administration
                rxo.rxo_5 = requested_route

            if admin_instructions:
                # RXO-6: Provider's Pharmacy/Treatment Instructions
                rxo.rxo_6 = admin_instructions

            if dispense_amount:
                # RXO-10: Requested Dispense Amount
                rxo.rxo_10 = dispense_amount

            if dispense_units:
                # RXO-11: Requested Dispense Units (CE type)
                rxo.rxo_11 = dispense_units

            if refills:
                # RXO-12: Number of Refills
                rxo.rxo_12 = refills

            if ordering_provider:
                # RXO-14: Ordering Provider's DEA Number (XCN type)
                rxo.rxo_14 = ordering_provider

            return rxo

        except Exception as e:
            logger.debug(f"Operation failed: {e}")
            return None

    def build_rxe(
        self,
        drug_code: str = "",
        drug_name: str = "",
        give_amount: str = "",
        give_units: str = "",
        give_dosage_form: str = "",
        dispense_amount: str = "",
        dispense_units: str = "",
        refills_remaining: str = "",
        prescription_number: str = "",
        pharmacy: str = "",
    ) -> Optional[Any]:
        """
        Build RXE (Pharmacy/Treatment Encoded Order) segment

        More detailed pharmacy order for prescription manipulation.

        Args:
            drug_code: Drug code (RXE-2)
            drug_name: Drug name (RXE-2 component 2)
            give_amount: Give amount (RXE-3)
            give_units: Give units (RXE-5)
            give_dosage_form: Dosage form (RXE-6)
            dispense_amount: Dispense amount (RXE-10)
            dispense_units: Dispense units (RXE-11)
            refills_remaining: Refills remaining (RXE-16)
            prescription_number: Prescription number (RXE-15)
            pharmacy: Dispensing pharmacy (RXE-40)

        Returns:
            RXE segment or None
        """
        try:
            rxe = Segment("RXE", version=self.version)

            # RXE-1: Quantity/Timing (TQ type) - deprecated but may be required
            rxe.rxe_1 = "1"

            # RXE-2: Give Code (CE type)
            if drug_code or drug_name:
                rxe.rxe_2 = f"{drug_code}^{drug_name}^NDC"

            if give_amount:
                # RXE-3: Give Amount - Minimum
                rxe.rxe_3 = give_amount

            if give_units:
                # RXE-5: Give Units (CE type)
                rxe.rxe_5 = give_units

            if give_dosage_form:
                # RXE-6: Give Dosage Form (CE type)
                rxe.rxe_6 = give_dosage_form

            if dispense_amount:
                # RXE-10: Dispense Amount
                rxe.rxe_10 = dispense_amount

            if dispense_units:
                # RXE-11: Dispense Units (CE type)
                rxe.rxe_11 = dispense_units

            if prescription_number:
                # RXE-15: Prescription Number
                rxe.rxe_15 = prescription_number

            if refills_remaining:
                # RXE-16: Number of Refills Remaining
                rxe.rxe_16 = refills_remaining

            return rxe

        except Exception as e:
            logger.debug(f"Operation failed: {e}")
            return None

    def build_rxa(
        self,
        admin_sub_id: str = "0",
        admin_code: str = "",
        admin_name: str = "",
        admin_start_datetime: str = "",
        admin_end_datetime: str = "",
        admin_amount: str = "",
        admin_units: str = "",
        admin_route: str = "",
        admin_site: str = "",
        lot_number: str = "",
        expiration_date: str = "",
        manufacturer: str = "",
        set_id: int = 1,
        completion_status: str = "CP",
        # Caller-name aliases (tests + downstream pharmacy mixins use
        # these shorter spellings):
        give_sub_id: str = "",
        start_datetime: str = "",
        end_datetime: str = "",
        admin_notes: str = "",
        admin_provider: str = "",
    ) -> Optional[Any]:
        """
        Build RXA (Pharmacy/Treatment Administration) segment

        Records medication administration events.

        Args:
            admin_sub_id: Administration sub-ID counter (RXA-1)
            admin_code: Administered code (RXA-5)
            admin_name: Administered drug name (RXA-5 component 2)
            admin_start_datetime: Admin start date/time (RXA-3)
            admin_end_datetime: Admin end date/time (RXA-4)
            admin_amount: Administered amount (RXA-6)
            admin_units: Administered units (RXA-7)
            admin_route: Administration route (RXA-9)
            admin_site: Administration site (RXA-10)
            lot_number: Substance lot number (RXA-15)
            expiration_date: Substance expiration date (RXA-16)
            manufacturer: Substance manufacturer (RXA-17)
            set_id: Give sub-ID counter (RXA-2)

        Returns:
            RXA segment or None
        """
        try:
            # Resolve caller-name aliases first so the rest of the
            # function can use the canonical names.
            admin_sub_id = admin_sub_id or give_sub_id or "0"
            admin_start_datetime = admin_start_datetime or start_datetime
            admin_end_datetime = admin_end_datetime or end_datetime
            admin_route = admin_route or admin_notes
            admin_site = admin_site or admin_provider

            rxa = Segment("RXA", version=self.version)

            # RXA-1: Give Sub-ID Counter
            rxa.rxa_1 = admin_sub_id

            # RXA-2: Administration Sub-ID Counter
            rxa.rxa_2 = str(set_id)

            # RXA-3: Date/Time Start of Administration
            if admin_start_datetime:
                rxa.rxa_3 = admin_start_datetime
            else:
                rxa.rxa_3 = datetime.now().strftime("%Y%m%d%H%M%S")

            # RXA-4: Date/Time End of Administration
            if admin_end_datetime:
                rxa.rxa_4 = admin_end_datetime

            # RXA-5: Administered Code (CE type)
            if admin_code or admin_name:
                rxa.rxa_5 = f"{admin_code}^{admin_name}^NDC"

            if admin_amount:
                # RXA-6: Administered Amount
                rxa.rxa_6 = admin_amount

            if admin_units:
                # RXA-7: Administered Units (CE type)
                rxa.rxa_7 = admin_units

            if admin_route:
                # RXA-9: Administration Notes (CE type) - often used for route
                rxa.rxa_9 = admin_route

            if admin_site:
                # RXA-10: Administering Provider
                rxa.rxa_10 = admin_site

            if lot_number:
                # RXA-15: Substance Lot Number
                rxa.rxa_15 = lot_number

            if expiration_date:
                # RXA-16: Substance Expiration Date
                rxa.rxa_16 = expiration_date

            if manufacturer:
                # RXA-17: Substance Manufacturer Name (CE type)
                rxa.rxa_17 = manufacturer

            # RXA-20: Completion Status (CP=Complete, RE=Refused, PA=Partially
            # Administered, NA=Not Administered)
            rxa.rxa_20 = completion_status or "CP"

            return rxa

        except Exception as e:
            logger.debug(f"Operation failed: {e}")
            return None

    def build_rxd(
        self,
        dispense_sub_id: str = "1",
        drug_code: str = "",
        drug_name: str = "",
        dispense_datetime: str = "",
        actual_dispense_amount: str = "",
        actual_dispense_units: str = "",
        prescription_number: str = "",
        dispense_notes: str = "",
        dispensing_provider: str = "",
        lot_number: str = "",
        expiration_date: str = "",
        # Caller-name aliases used by mixins/pharmacy.py — keep these
        # accepting both spellings so the mixin's dispense_code= /
        # actual_amount= / actual_units= / refills_remaining= /
        # datetime_dispensed= calls don't TypeError into silent fallback.
        dispense_code: str = "",
        actual_amount: str = "",
        actual_units: str = "",
        refills_remaining: str = "",
        datetime_dispensed: str = "",
    ) -> Optional[Any]:
        """
        Build RXD (Pharmacy/Treatment Dispense) segment

        Records medication dispensing events.

        Args:
            dispense_sub_id: Dispense sub-ID counter (RXD-1)
            drug_code: Dispense/give code (RXD-2)
            drug_name: Drug name (RXD-2 component 2)
            dispense_datetime: Date/time dispensed (RXD-3)
            actual_dispense_amount: Actual dispense amount (RXD-4)
            actual_dispense_units: Actual dispense units (RXD-5)
            prescription_number: Prescription number (RXD-7)
            dispense_notes: Dispense notes (RXD-9)
            dispensing_provider: Dispensing provider (RXD-10)
            lot_number: Substance lot number (RXD-18)
            expiration_date: Substance expiration date (RXD-19)

        Returns:
            RXD segment or None
        """
        try:
            # Resolve alias kwargs (caller-friendly names from mixins/pharmacy.py
            # and the test suite).
            drug_code = drug_code or dispense_code
            actual_dispense_amount = actual_dispense_amount or actual_amount
            actual_dispense_units = actual_dispense_units or actual_units
            dispense_datetime = dispense_datetime or datetime_dispensed

            rxd = Segment("RXD", version=self.version)

            # RXD-1: Dispense Sub-ID Counter
            rxd.rxd_1 = dispense_sub_id

            # RXD-2: Dispense/Give Code (CE type)
            if drug_code or drug_name:
                rxd.rxd_2 = f"{drug_code}^{drug_name}^NDC"

            # RXD-3: Date/Time Dispensed
            if dispense_datetime:
                rxd.rxd_3 = dispense_datetime
            else:
                rxd.rxd_3 = datetime.now().strftime("%Y%m%d%H%M%S")

            if actual_dispense_amount:
                # RXD-4: Actual Dispense Amount
                rxd.rxd_4 = actual_dispense_amount

            if actual_dispense_units:
                # RXD-5: Actual Dispense Units (CE type)
                rxd.rxd_5 = actual_dispense_units

            if prescription_number:
                # RXD-7: Prescription Number
                rxd.rxd_7 = prescription_number

            if dispense_notes:
                # RXD-9: Dispense Notes
                rxd.rxd_9 = dispense_notes

            if dispensing_provider:
                # RXD-10: Dispensing Provider (XCN type)
                rxd.rxd_10 = dispensing_provider

            if lot_number:
                # RXD-18: Substance Lot Number
                rxd.rxd_18 = lot_number

            if expiration_date:
                # RXD-19: Substance Expiration Date
                rxd.rxd_19 = expiration_date

            if refills_remaining:
                # RXD-8: Refills Remaining
                try:
                    rxd.rxd_8 = refills_remaining
                except Exception as e:
                    logger.debug(f"HL7: RXD-8 not in schema, skipping refills: {e}")

            return rxd

        except Exception as e:
            logger.debug(f"Operation failed: {e}")
            return None

    def build_rxg(
        self,
        give_sub_id: str = "1",
        drug_code: str = "",
        drug_name: str = "",
        give_amount: str = "",
        give_units: str = "",
        give_dosage_form: str = "",
        give_rate_amount: str = "",
        give_rate_units: str = "",
        give_strength: str = "",
        give_strength_units: str = "",
        dispense_sub_id: str = "1",
        # Caller-name aliases (mixins/pharmacy.py + tests).
        give_code: str = "",
        quantity_timing: str = "",
        admin_notes: str = "",
        substitution_status: str = "",
    ) -> Optional[Any]:
        """
        Build RXG (Pharmacy/Treatment Give) segment

        Records medication give events (what was actually given to patient).

        Args:
            give_sub_id: Give sub-ID counter (RXG-1)
            drug_code: Give code (RXG-4)
            drug_name: Drug name (RXG-4 component 2)
            give_amount: Give amount - minimum (RXG-5)
            give_units: Give units (RXG-7)
            give_dosage_form: Give dosage form (RXG-8)
            give_rate_amount: Give rate amount (RXG-15)
            give_rate_units: Give rate units (RXG-16)
            give_strength: Give strength (RXG-17)
            give_strength_units: Give strength units (RXG-18)
            dispense_sub_id: Dispense sub-ID counter (RXG-2)

        Returns:
            RXG segment or None
        """
        try:
            # Resolve alias (caller-friendly name from mixins/pharmacy.py).
            drug_code = drug_code or give_code

            rxg = Segment("RXG", version=self.version)

            # RXG-1: Give Sub-ID Counter
            rxg.rxg_1 = give_sub_id

            # RXG-2: Dispense Sub-ID Counter
            rxg.rxg_2 = dispense_sub_id

            # RXG-3: Quantity/Timing (deprecated, often empty — but
            # callers can override).
            rxg.rxg_3 = quantity_timing or ""

            # RXG-4: Give Code (CE type)
            if drug_code or drug_name:
                rxg.rxg_4 = f"{drug_code}^{drug_name}^NDC"

            if give_amount:
                # RXG-5: Give Amount - Minimum
                rxg.rxg_5 = give_amount

            if give_units:
                # RXG-7: Give Units (CE type)
                rxg.rxg_7 = give_units

            if give_dosage_form:
                # RXG-8: Give Dosage Form (CE type)
                rxg.rxg_8 = give_dosage_form

            if give_rate_amount:
                # RXG-15: Give Rate Amount
                rxg.rxg_15 = give_rate_amount

            if give_rate_units:
                # RXG-16: Give Rate Units (CE type)
                rxg.rxg_16 = give_rate_units

            if give_strength:
                # RXG-17: Give Strength
                rxg.rxg_17 = give_strength

            if give_strength_units:
                # RXG-18: Give Strength Units (CE type)
                rxg.rxg_18 = give_strength_units

            # RXG-10: Administration Notes (TX type — caller alias)
            if admin_notes:
                try:
                    rxg.rxg_10 = admin_notes
                except Exception as e:
                    logger.debug(f"HL7: RXG-10 not in schema, skipping notes: {e}")

            # RXG-11: Substitution Status (ID type — N=No, G=Generic, T=Therapeutic)
            if substitution_status:
                try:
                    rxg.rxg_11 = substitution_status
                except Exception as e:
                    logger.debug(f"HL7: RXG-11 not in schema, skipping substitution_status: {e}")

            return rxg

        except Exception as e:
            logger.debug(f"Operation failed: {e}")
            return None

    def build_dg1(
        self,
        diagnosis_code: str = "",
        diagnosis_description: str = "",
        diagnosis_type: str = "A",
        diagnosis_datetime: str = "",
        diagnosing_clinician: str = "",
        coding_method: str = "ICD10",
        diagnosis_priority: str = "",
        set_id: int = 1,
    ) -> Optional[Any]:
        """
        Build DG1 (Diagnosis) segment

        Used for diagnosis code manipulation/injection.

        Args:
            diagnosis_code: Diagnosis code ICD-10/ICD-9 (DG1-3)
            diagnosis_description: Diagnosis description (DG1-4)
            diagnosis_type: Diagnosis type A=Admitting, W=Working, F=Final (DG1-6)
            diagnosis_datetime: Diagnosis date/time (DG1-5)
            diagnosing_clinician: Diagnosing clinician (DG1-16)
            coding_method: Coding method ICD10/ICD9 (DG1-2)
            diagnosis_priority: Diagnosis priority 1=Primary, 2+=Secondary (DG1-15)
            set_id: Set ID (DG1-1)

        Returns:
            DG1 segment or None
        """
        try:
            dg1 = Segment("DG1", version=self.version)

            # DG1-1: Set ID
            dg1.dg1_1 = str(set_id)

            # DG1-2: Diagnosis Coding Method
            dg1.dg1_2 = coding_method

            # DG1-3: Diagnosis Code (CE type) - code^description^coding_system
            if diagnosis_code or diagnosis_description:
                dg1.dg1_3 = f"{diagnosis_code}^{diagnosis_description}^{coding_method}"

            if diagnosis_description:
                # DG1-4: Diagnosis Description
                dg1.dg1_4 = diagnosis_description

            if diagnosis_datetime:
                # DG1-5: Diagnosis Date/Time
                dg1.dg1_5 = diagnosis_datetime
            else:
                dg1.dg1_5 = datetime.now().strftime("%Y%m%d%H%M%S")

            if diagnosis_type:
                # DG1-6: Diagnosis Type (A=Admitting, W=Working, F=Final)
                dg1.dg1_6 = diagnosis_type

            if diagnosis_priority:
                # DG1-15: Diagnosis Priority
                dg1.dg1_15 = diagnosis_priority

            if diagnosing_clinician:
                # DG1-16: Diagnosing Clinician (XCN type)
                dg1.dg1_16 = diagnosing_clinician

            return dg1

        except Exception as e:
            logger.debug(f"Operation failed: {e}")
            return None

    def build_pr1(
        self,
        procedure_code: str = "",
        procedure_description: str = "",
        procedure_datetime: str = "",
        procedure_type: str = "",
        procedure_practitioner: str = "",
        coding_method: str = "CPT",
        set_id: int = 1,
    ) -> Optional[Any]:
        """
        Build PR1 (Procedure) segment

        Used for procedure code manipulation/billing attacks.

        Args:
            procedure_code: Procedure code CPT/HCPCS (PR1-3)
            procedure_description: Procedure description (PR1-4)
            procedure_datetime: Procedure date/time (PR1-5)
            procedure_type: Procedure type (PR1-6)
            procedure_practitioner: Procedure practitioner (PR1-8)
            coding_method: Coding method CPT/HCPCS (PR1-2)
            set_id: Set ID (PR1-1)

        Returns:
            PR1 segment or None
        """
        try:
            pr1 = Segment("PR1", version=self.version)

            # PR1-1: Set ID
            pr1.pr1_1 = str(set_id)

            # PR1-2: Procedure Coding Method
            pr1.pr1_2 = coding_method

            # PR1-3: Procedure Code (CE type) - code^description^coding_system
            if procedure_code or procedure_description:
                pr1.pr1_3 = f"{procedure_code}^{procedure_description}^{coding_method}"

            if procedure_description:
                # PR1-4: Procedure Description
                pr1.pr1_4 = procedure_description

            if procedure_datetime:
                # PR1-5: Procedure Date/Time
                pr1.pr1_5 = procedure_datetime
            else:
                pr1.pr1_5 = datetime.now().strftime("%Y%m%d%H%M%S")

            if procedure_type:
                # PR1-6: Procedure Functional Type
                pr1.pr1_6 = procedure_type

            if procedure_practitioner:
                # PR1-8: Anesthesiologist / Surgeon (XCN type)
                pr1.pr1_8 = procedure_practitioner

            return pr1

        except Exception as e:
            logger.debug(f"Operation failed: {e}")
            return None

    def build_mrg(
        self,
        prior_patient_id: str = "",
        prior_patient_name: str = "",
        prior_visit_number: str = "",
        prior_account_number: str = "",
    ) -> Optional[Any]:
        """
        Build MRG (Merge Patient Information) segment

        Used for patient merge attacks (ADT^A40) - can merge patient records.

        Args:
            prior_patient_id: Prior patient ID to merge FROM (MRG-1)
            prior_patient_name: Prior patient name (MRG-7)
            prior_visit_number: Prior visit number (MRG-3)
            prior_account_number: Prior account number (MRG-3)

        Returns:
            MRG segment or None
        """
        try:
            mrg = Segment("MRG", version=self.version)

            if prior_patient_id:
                # MRG-1: Prior Patient Identifier List (CX type)
                mrg.mrg_1 = f"{prior_patient_id}^^^HOSPITAL^MR"

            if prior_visit_number:
                # MRG-3: Prior Patient Account Number (CX type)
                mrg.mrg_3 = prior_visit_number

            if prior_account_number:
                # MRG-3 can also be account number
                mrg.mrg_3 = prior_account_number

            if prior_patient_name:
                # MRG-7: Prior Patient Name (XPN type)
                mrg.mrg_7 = prior_patient_name

            return mrg

        except Exception as e:
            logger.debug(f"HL7: build_mrg segment construction failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Master File segments (MFI, MFE, STF, PRA, PRC)
    # Called by mixins/master_file.py — without these, MFN^M01/M02/M04
    # silently fall back to generic test messages (CRITICAL).
    # ------------------------------------------------------------------

    def build_mfi(
        self,
        master_file_id: str = "ZZZ^General",
        file_level_event_code: str = "UPD",
        response_level_code: str = "AL",
    ) -> Optional[Any]:
        """Build MFI (Master File Identification) segment."""
        try:
            mfi = Segment("MFI", version=self.version)
            mfi.mfi_1 = master_file_id
            mfi.mfi_3 = file_level_event_code
            mfi.mfi_6 = response_level_code
            return mfi
        except Exception as e:
            logger.debug(f"HL7: build_mfi segment construction failed: {e}")
            return None

    def build_mfe(
        self,
        record_level_event_code: str = "MAD",
        mfn_control_id: str = "",
        primary_key_value: str = "",
    ) -> Optional[Any]:
        """Build MFE (Master File Entry) segment."""
        try:
            mfe = Segment("MFE", version=self.version)
            mfe.mfe_1 = record_level_event_code
            if mfn_control_id:
                mfe.mfe_2 = mfn_control_id
            if primary_key_value:
                mfe.mfe_4 = primary_key_value
            return mfe
        except Exception as e:
            logger.debug(f"HL7: build_mfe segment construction failed: {e}")
            return None

    def build_stf(
        self,
        staff_id: str = "",
        staff_name: str = "",
        staff_type: str = "",
        department: str = "",
        active_inactive: str = "A",
    ) -> Optional[Any]:
        """Build STF (Staff Identification) segment."""
        try:
            stf = Segment("STF", version=self.version)
            if staff_id:
                stf.stf_1 = staff_id
                stf.stf_2 = staff_id
            if staff_name:
                stf.stf_3 = staff_name
            if staff_type:
                stf.stf_4 = staff_type
            if department:
                stf.stf_11 = department
            stf.stf_7 = active_inactive
            return stf
        except Exception as e:
            logger.debug(f"HL7: build_stf segment construction failed: {e}")
            return None

    def build_pra(
        self,
        practitioner_id: str = "",
        practitioner_category: str = "",
        specialty: str = "",
        institution: str = "",
    ) -> Optional[Any]:
        """Build PRA (Practitioner Detail) segment.

        Per HL7 v2.5 §15.4.1:
          PRA-1: Primary Key Value (practitioner ID)
          PRA-5: Practitioner Category
          PRA-9: Specialty (CE type — code^description^coding-system)
          PRA-10: Practitioner ID Numbers (institution affiliation)
        """
        try:
            pra = Segment("PRA", version=self.version)
            if practitioner_id:
                pra.pra_1 = practitioner_id
            if practitioner_category:
                pra.pra_5 = practitioner_category
            if specialty:
                try:
                    pra.pra_9 = specialty
                except Exception as e:
                    logger.debug(f"HL7: PRA-9 not in schema, skipping specialty: {e}")
            if institution:
                try:
                    pra.pra_10 = institution
                except Exception as e:
                    logger.debug(f"HL7: PRA-10 not in schema, skipping institution: {e}")
            return pra
        except Exception as e:
            logger.debug(f"HL7: build_pra segment construction failed: {e}")
            return None

    def build_prc(
        self,
        charge_code: str = "",
        price: str = "",
        active_inactive: str = "A",
        department: str = "",
    ) -> Optional[Any]:
        """Build PRC (Pricing/Charge Description) segment.

        The HL7 v2.5 PRC field count varies between hl7apy schema files;
        any unsupported field is set defensively so we still emit the
        primary fields the caller cares about.
        """
        try:
            prc = Segment("PRC", version=self.version)
            if charge_code:
                prc.prc_1 = charge_code
            if department:
                try:
                    prc.prc_3 = department
                except Exception as e:
                    logger.debug(f"HL7: PRC-3 not in schema, skipping department: {e}")
            if price:
                # PRC-10 = Facility ID in some schemas, Price in others; set
                # defensively. Drop silently if the field name resolves to
                # 'None' in the active hl7apy schema rather than blowing
                # up the whole segment.
                try:
                    prc.prc_10 = price
                except Exception as e:
                    logger.debug(f"HL7: PRC-10 not in schema, skipping price field: {e}")
            try:
                prc.prc_19 = active_inactive
            except Exception as e:
                logger.debug(f"HL7: PRC-19 not in schema, skipping active flag: {e}")
            return prc
        except Exception as e:
            logger.debug(f"HL7: build_prc segment construction failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Financial segments (GT1, IN1, FT1)
    # Called by mixins/financial.py — without these, BAR^P01 / DFT^P03
    # silently fall back to generic test messages (CRITICAL).
    # ------------------------------------------------------------------

    def build_gt1(
        self,
        guarantor_number: str = "",
        guarantor_name: str = "",
        guarantor_phone: str = "",
        set_id: int = 1,
        guarantor_relationship: str = "",
    ) -> Optional[Any]:
        """Build GT1 (Guarantor) segment.

        Per HL7 v2.5 §6.5.4:
          GT1-1: Set ID
          GT1-2: Guarantor Number (CX)
          GT1-3: Guarantor Name (XPN)
          GT1-6: Guarantor Phone Number (XTN)
          GT1-11: Guarantor Relationship to Patient (CE; SEL=Self, SPO=Spouse, ...)
        """
        try:
            gt1 = Segment("GT1", version=self.version)
            gt1.gt1_1 = str(set_id)
            if guarantor_number:
                gt1.gt1_2 = guarantor_number
            if guarantor_name:
                gt1.gt1_3 = guarantor_name
            if guarantor_phone:
                gt1.gt1_6 = guarantor_phone
            if guarantor_relationship:
                try:
                    gt1.gt1_11 = guarantor_relationship
                except Exception as e:
                    logger.debug(f"HL7: GT1-11 not in schema, skipping relationship: {e}")
            return gt1
        except Exception as e:
            logger.debug(f"HL7: build_gt1 segment construction failed: {e}")
            return None

    def build_in1(
        self,
        insurance_company_name: str = "",
        group_number: str = "",
        policy_number: str = "",
        set_id: int = 1,
        insurance_plan_id: str = "",
    ) -> Optional[Any]:
        """Build IN1 (Insurance) segment.

        Per HL7 v2.5 §6.5.6:
          IN1-1: Set ID
          IN1-2: Insurance Plan ID (CE)
          IN1-4: Insurance Company Name (XON)
          IN1-8: Group Number
          IN1-36: Policy Number
        """
        try:
            in1 = Segment("IN1", version=self.version)
            in1.in1_1 = str(set_id)
            if insurance_plan_id:
                try:
                    in1.in1_2 = insurance_plan_id
                except Exception as e:
                    logger.debug(f"HL7: IN1-2 not in schema, skipping plan id: {e}")
            if insurance_company_name:
                in1.in1_4 = insurance_company_name
            if group_number:
                in1.in1_8 = group_number
            if policy_number:
                in1.in1_36 = policy_number
            return in1
        except Exception as e:
            logger.debug(f"HL7: build_in1 segment construction failed: {e}")
            return None

    def build_ft1(
        self,
        transaction_id: str = "",
        transaction_type: str = "CG",
        transaction_code: str = "",
        transaction_description: str = "",
        transaction_amount: str = "",
        patient_id: str = "",
        diagnosis_code: str = "",
        procedure_code: str = "",
        set_id: int = 1,
    ) -> Optional[Any]:
        """Build FT1 (Financial Transaction) segment."""
        try:
            ft1 = Segment("FT1", version=self.version)
            ft1.ft1_1 = str(set_id)
            if transaction_id:
                ft1.ft1_2 = transaction_id
            ft1.ft1_6 = transaction_type
            if transaction_code:
                ft1.ft1_7 = transaction_code
            if transaction_description:
                ft1.ft1_8 = transaction_description
            if transaction_amount:
                ft1.ft1_10 = transaction_amount
            if patient_id:
                ft1.ft1_13 = patient_id
            if diagnosis_code:
                ft1.ft1_19 = diagnosis_code
            if procedure_code:
                ft1.ft1_25 = procedure_code
            return ft1
        except Exception as e:
            logger.debug(f"HL7: build_ft1 segment construction failed: {e}")
            return None


class HL7SegmentParser:
    """Parse HL7 v2 message segments using hl7apy library"""

    # ────────────────────────────────────────────────────────────────────
    @staticmethod
    def _normalize_message(message: Any) -> str:
        """Normalize message to string with proper HL7 line endings"""
        if isinstance(message, bytes):
            message = message.decode("utf-8", errors="replace")
        # Normalize line endings to CR (HL7 standard)
        return message.replace("\r\n", "\r").replace("\n", "\r")

    @staticmethod
    def _get_field_value(segment: Any, field_name: str, default: str = "") -> str:
        """Safely get field value from hl7apy segment"""
        try:
            field = getattr(segment, field_name, None)
            if field is not None:
                return str(field.value) if field.value else default
        except Exception as e:
            logger.debug(f"Failed to get field: {e}")
        return default

    @staticmethod
    def _get_component(field_value: str, index: int, default: str = "") -> str:
        """Get component from field value (0-indexed)"""
        if not field_value:
            return default
        parts = field_value.split("^")
        return parts[index] if index < len(parts) and parts[index] else default

    @staticmethod
    def split_message(message: Any) -> list:
        """Split HL7 message into segment strings"""
        from hl7apy.parser import parse_message

        normalized = HL7SegmentParser._normalize_message(message)
        msg = parse_message(normalized)
        return [str(child.to_er7()) for child in msg.children]

    @staticmethod
    def get_field(fields: list, index: int, default: str = "") -> str:
        """Get field by index from pipe-delimited list (1-based HL7 indexing)"""
        try:
            if 0 < index <= len(fields):
                return fields[index - 1] if fields[index - 1] else default
        except (IndexError, TypeError) as e:
            logger.debug(f"if 0  index  len(fields):: {e}")
        return default

    @staticmethod
    def format_address(addr_field: str) -> str:
        """Format HL7 XAD address field into readable string"""
        if not addr_field:
            return ""
        parts = addr_field.split("^")
        # XAD: street^other^city^state^zip^country
        components = []
        if len(parts) > 0 and parts[0]:
            components.append(parts[0])
        if len(parts) > 2 and parts[2]:
            components.append(parts[2])
        if len(parts) > 3 and parts[3]:
            components.append(parts[3])
        if len(parts) > 4 and parts[4]:
            components.append(parts[4])
        return ", ".join(components) if components else addr_field

    @staticmethod
    def _iter_segments(element: Any):
        """Yield every Segment in document order, descending into Groups.

        hl7apy nests segments inside message Groups for standard structures
        (e.g. an ORU^R01's PID/OBR/OBX live under an ORU_R01_PATIENT_RESULT
        group, not at the top level). Walking only ``message.children`` would
        therefore see just MSH + the group container and miss every clinical
        segment. This flattens the tree so the parser sees PID/ORC/OBR/OBX/
        RXE/RXD/RXA regardless of grouping.

        hl7apy is the module-level optional dependency; the only caller
        (``parse_message``) has already imported it, so the import here is just
        deferring an internal class reference, not guarding an optional dep.
        """
        from hl7apy.core import Group, Segment

        for child in element.children:
            if isinstance(child, Segment):
                yield child
            elif isinstance(child, Group):
                yield from HL7SegmentParser._iter_segments(child)
            # else: Field/Component/unknown — not a segment, skip

    @staticmethod
    def parse_message(message: Any, extended: bool = False) -> dict:
        """Parse full HL7 message using hl7apy"""
        from hl7apy.parser import parse_message

        # 'orders' was missing from this dict — response.py:_extract_order_status
        # read parsed["orders"] and crashed with KeyError, silently swallowed
        # by its outer try/except. Now we collect ORC + the most recent OBR
        # under "orders" so OSR^Q06 response handling actually surfaces
        # something to the operator.
        result = {
            "patients": [],
            "observations": [],
            "medications": [],
            "orders": [],
            "segments": {},
        }
        normalized = HL7SegmentParser._normalize_message(message)
        msg = parse_message(normalized)
        current_patient = {}
        current_order: dict = {}

        for child in HL7SegmentParser._iter_segments(msg):
            seg_name = child.name
            result["segments"][seg_name] = str(child.to_er7())

            if seg_name == "PID":
                current_patient = HL7SegmentParser._parse_pid_segment(child, extended)
                result["patients"].append(current_patient)

            elif seg_name == "OBX":
                obs = HL7SegmentParser._parse_obx_segment(child)
                if current_patient:
                    obs["PatientID"] = current_patient.get("PatientID", "")
                result["observations"].append(obs)

            elif seg_name == "RXE":
                med = HL7SegmentParser._parse_rxe_segment(child)
                if current_patient:
                    med["PatientID"] = current_patient.get("PatientID", "")
                result["medications"].append(med)

            elif seg_name == "RXD":
                med = HL7SegmentParser._parse_rxd_segment(child)
                if current_patient:
                    med["PatientID"] = current_patient.get("PatientID", "")
                result["medications"].append(med)

            elif seg_name == "RXA":
                med = HL7SegmentParser._parse_rxa_segment(child)
                if current_patient:
                    med["PatientID"] = current_patient.get("PatientID", "")
                result["medications"].append(med)

            elif seg_name == "ORC":
                try:
                    orc = HL7SegmentParser.parse_orc(child)
                except Exception:  # noqa: BLE001 — best-effort tolerant parse
                    orc = {}
                current_order = dict(orc)
                if current_patient:
                    current_order["PatientID"] = current_patient.get("PatientID", "")
                result["orders"].append(current_order)

            elif seg_name == "OBR":
                try:
                    obr = HL7SegmentParser.parse_obr(child)
                except Exception:  # noqa: BLE001
                    obr = {}
                if current_order:
                    # OBR follows the ORC for the same order — fold its
                    # fields into the in-flight order dict so the order
                    # row carries OrderCode/OrderName/Priority/etc.
                    for k, v in obr.items():
                        current_order.setdefault(k, v)
                else:
                    standalone = dict(obr)
                    if current_patient:
                        standalone["PatientID"] = current_patient.get("PatientID", "")
                    result["orders"].append(standalone)

        return result

    @staticmethod
    def _parse_pid_segment(seg: Any, extended: bool = False) -> dict:
        """Parse PID segment using hl7apy"""
        get = HL7SegmentParser._get_field_value
        comp = HL7SegmentParser._get_component
        pid_3 = get(seg, "pid_3")
        pid_5 = get(seg, "pid_5")
        patient = {
            "PatientID": comp(pid_3, 0),
            "PatientName": pid_5.replace("^", " "),
            "DOB": get(seg, "pid_7"),
            "Sex": get(seg, "pid_8"),
            "Address": HL7SegmentParser.format_address(get(seg, "pid_11")),
            "Phone": comp(get(seg, "pid_13"), 0),
            "Account": get(seg, "pid_18"),
        }
        if extended:
            patient.update(
                {
                    "AltID": get(seg, "pid_4"),
                    "MaidenName": get(seg, "pid_6"),
                    "Alias": get(seg, "pid_9"),
                    "Race": get(seg, "pid_10"),
                    "County": get(seg, "pid_12"),
                    "BusinessPhone": get(seg, "pid_14"),
                    "Language": get(seg, "pid_15"),
                    "MaritalStatus": get(seg, "pid_16"),
                    "Religion": get(seg, "pid_17"),
                    "SSN": get(seg, "pid_19"),
                    "DriversLicense": get(seg, "pid_20"),
                    "EthnicGroup": get(seg, "pid_22"),
                }
            )
        return patient

    @staticmethod
    def _parse_obx_segment(seg: Any) -> dict:
        """Parse OBX segment using hl7apy"""
        get = HL7SegmentParser._get_field_value
        comp = HL7SegmentParser._get_component
        obx_3 = get(seg, "obx_3")
        return {
            "ObservationID": comp(obx_3, 0),
            "ObservationName": comp(obx_3, 1),
            "Value": get(seg, "obx_5"),
            "Units": comp(get(seg, "obx_6"), 0),
            "RefRange": get(seg, "obx_7"),
            "AbnormalFlag": get(seg, "obx_8"),
            "Status": get(seg, "obx_11"),
        }

    @staticmethod
    def _parse_rxe_segment(seg: Any) -> dict:
        """Parse RXE segment using hl7apy"""
        get = HL7SegmentParser._get_field_value
        comp = HL7SegmentParser._get_component
        rxe_2 = get(seg, "rxe_2")
        return {
            "DrugCode": comp(rxe_2, 0),
            "DrugName": comp(rxe_2, 1),
            "Dose": get(seg, "rxe_3"),
            "Units": get(seg, "rxe_5"),
            "Route": get(seg, "rxe_6"),
            "Quantity": get(seg, "rxe_10"),
            "Refills": get(seg, "rxe_12"),
            "PrescriptionNumber": get(seg, "rxe_15"),
            "RefillsRemaining": get(seg, "rxe_16"),
            "DispensingPharmacy": get(seg, "rxe_40"),
            "Status": "Ordered",
        }

    @staticmethod
    def _parse_rxd_segment(seg: Any) -> dict:
        """Parse RXD segment using hl7apy"""
        get = HL7SegmentParser._get_field_value
        comp = HL7SegmentParser._get_component
        rxd_2 = get(seg, "rxd_2")
        return {
            "DrugCode": comp(rxd_2, 0),
            "DrugName": comp(rxd_2, 1),
            "DispenseDate": get(seg, "rxd_3"),
            "Quantity": get(seg, "rxd_4"),
            "Units": get(seg, "rxd_5"),
            "LotNumber": get(seg, "rxd_18"),
            "Status": "Dispensed",
        }

    @staticmethod
    def _parse_rxa_segment(seg: Any) -> dict:
        """Parse RXA segment using hl7apy"""
        get = HL7SegmentParser._get_field_value
        comp = HL7SegmentParser._get_component
        rxa_5 = get(seg, "rxa_5")
        return {
            "DrugCode": comp(rxa_5, 0),
            "DrugName": comp(rxa_5, 1),
            "AdminDate": get(seg, "rxa_3"),
            "Dose": get(seg, "rxa_6"),
            "Units": get(seg, "rxa_7"),
            "Route": get(seg, "rxa_9"),
            "LotNumber": get(seg, "rxa_15"),
            "Manufacturer": get(seg, "rxa_17"),
            "Status": "Administered",
        }

    @staticmethod
    def parse_pv1(segment: str) -> dict:
        """Parse PV1 patient visit segment"""
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        return {
            "PatientClass": get(seg, "pv1_2"),
            "Location": get(seg, "pv1_3"),
            "AdmissionType": get(seg, "pv1_4"),
            "AttendingDoctor": get(seg, "pv1_7").replace("^", " "),
            "ReferringDoctor": get(seg, "pv1_8").replace("^", " "),
            "VisitNumber": get(seg, "pv1_19"),
            "FinancialClass": get(seg, "pv1_20"),
            "AdmitDate": get(seg, "pv1_44"),
            "DischargeDate": get(seg, "pv1_45"),
        }

    @staticmethod
    def parse_obr(segment: str) -> dict:
        """Parse OBR observation request segment"""
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        comp = HL7SegmentParser._get_component
        obr_4 = get(seg, "obr_4")
        return {
            "PlacerOrderNumber": get(seg, "obr_2"),
            "FillerOrderNumber": get(seg, "obr_3"),
            "ServiceID": comp(obr_4, 0),
            "ServiceName": comp(obr_4, 1),
            "Priority": get(seg, "obr_5"),
            "RequestedDateTime": get(seg, "obr_6"),
            "ObservationDateTime": get(seg, "obr_7"),
            "OrderingProvider": get(seg, "obr_16").replace("^", " "),
            "ResultStatus": get(seg, "obr_25"),
        }

    @staticmethod
    def parse_orc(segment: str) -> dict:
        """Parse ORC common order segment"""
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        return {
            "OrderControl": get(seg, "orc_1"),
            "PlacerOrderNumber": get(seg, "orc_2"),
            "FillerOrderNumber": get(seg, "orc_3"),
            "OrderStatus": get(seg, "orc_5"),
            "ResponseFlag": get(seg, "orc_6"),
            "TransactionDateTime": get(seg, "orc_9"),
            "EnteredBy": get(seg, "orc_10").replace("^", " "),
            "OrderingProvider": get(seg, "orc_12").replace("^", " "),
            "EnteringOrganization": get(seg, "orc_17"),
            "OrderFacility": get(seg, "orc_21"),
        }

    @staticmethod
    def parse_mfi(segment: str) -> dict:
        """Parse MFI master file identification segment.

        MFI-1 is a CE (code^description^coding-system). Tests/operators
        usually want just the code; expose both forms — `MasterFileID`
        (code only) and `MasterFileIdentifier` (raw CE) — for backward
        compatibility.
        """
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        raw_mfi1 = get(seg, "mfi_1")
        code_mfi1 = raw_mfi1.split("^", 1)[0] if raw_mfi1 else ""
        return {
            "MasterFileID": code_mfi1,
            "MasterFileIdentifier": raw_mfi1,
            "MasterFileApplicationID": get(seg, "mfi_2"),
            "FileLevelEventCode": get(seg, "mfi_3"),
            "EnteredDateTime": get(seg, "mfi_4"),
            "EffectiveDateTime": get(seg, "mfi_5"),
            "ResponseLevelCode": get(seg, "mfi_6"),
        }

    @staticmethod
    def parse_mfe(segment: str) -> dict:
        """Parse MFE master file entry segment (per HL7 v2.5 §8.5.2)."""
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        return {
            "RecordLevelEventCode": get(seg, "mfe_1"),
            "MFNControlID": get(seg, "mfe_2"),
            "EffectiveDateTime": get(seg, "mfe_3"),
            "PrimaryKeyValue": get(seg, "mfe_4"),
            "PrimaryKeyValueType": get(seg, "mfe_5"),
        }

    @staticmethod
    def parse_stf(segment: str) -> dict:
        """Parse STF staff identification segment.

        Exposes both the canonical `PrimaryKeyValue` (per HL7 spec
        naming for STF-1) and the legacy `StaffID` alias used by
        master_file.py and the existing test_misc_fix_verifications
        contract.
        """
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        stf_1 = get(seg, "stf_1")
        return {
            "PrimaryKeyValue": stf_1,
            "StaffID": stf_1,  # legacy alias — keep until master_file.py migrates
            "StaffName": get(seg, "stf_3").replace("^", " "),
            "StaffType": get(seg, "stf_4"),
            "Department": get(seg, "stf_8"),
            "Phone": get(seg, "stf_10"),
            "Email": get(seg, "stf_15"),
            "ActiveStatus": get(seg, "stf_7"),
        }

    @staticmethod
    def parse_pra(segment: str) -> dict:
        """Parse PRA practitioner detail segment (per HL7 v2.5 §15.4.1).

        Wire format: PRA|PRA001|GROUP1|MD||Cardiology|||20200101|...
        Fields:
          PRA-1: Primary Key Value (practitioner ID)
          PRA-2: Practitioner Group
          PRA-3: Practitioner Category
          PRA-5: Specialty (CE — but the test uses the simple "MD" form
                 and expects 'PractitionerCategory' to be the code)
          PRA-9: Effective Start Date
        Note: HL7 v2.5 PRA-3 is the Practitioner Category and PRA-5 is
        Specialty. Earlier oida code uses PRA-5 for category for
        consistency with our test fixtures — preserved here.
        """
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        return {
            "PrimaryKeyValue": get(seg, "pra_1"),
            "PractitionerGroup": get(seg, "pra_2"),
            "PractitionerCategory": get(seg, "pra_3"),
            "Specialty": get(seg, "pra_5"),
            "EffectiveStartDate": get(seg, "pra_8"),
        }

    @staticmethod
    def parse_prc(segment: str) -> dict:
        """Parse PRC pricing segment"""
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        return {
            "PrimaryKeyValue": get(seg, "prc_1"),
            "FacilityID": get(seg, "prc_2"),
            "Department": get(seg, "prc_3"),
            "Price": get(seg, "prc_5"),
            "Formula": get(seg, "prc_6"),
            "EffectiveStartDate": get(seg, "prc_11"),
            "EffectiveEndDate": get(seg, "prc_12"),
        }

    @staticmethod
    def parse_ft1(segment: str) -> dict:
        """Parse FT1 financial transaction segment (per HL7 v2.5 §6.5.5).

        Per spec FT1-1 IS the Set ID and FT1-2 is the Transaction ID;
        the old code labelled them swapped. Tests + downstream code
        compatibility: expose BOTH names (`SetID` for the spec-correct
        name AND keep `TransactionID` as a back-compat alias for
        ft1_2/transaction-id).
        """
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        tx_code_raw = get(seg, "ft1_7")
        tx_code = tx_code_raw.split("^", 1)[0] if tx_code_raw else ""
        return {
            "SetID": get(seg, "ft1_1"),
            "TransactionID": get(seg, "ft1_2"),
            "TransactionBatchID": get(seg, "ft1_3"),
            "TransactionDate": get(seg, "ft1_4"),
            "TransactionPostingDate": get(seg, "ft1_5"),
            "TransactionType": get(seg, "ft1_6"),
            "TransactionCode": tx_code,
            "TransactionDescription": get(seg, "ft1_8"),
            "TransactionQuantity": get(seg, "ft1_10"),
            "TransactionAmount": get(seg, "ft1_11"),
            "InsurancePlanID": get(seg, "ft1_14"),
        }

    @staticmethod
    def parse_gt1(segment: str) -> dict:
        """Parse GT1 guarantor segment"""
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        guarantor_num_raw = get(seg, "gt1_2")
        guarantor_num = guarantor_num_raw.split("^", 1)[0] if guarantor_num_raw else ""
        return {
            "SetID": get(seg, "gt1_1"),
            "GuarantorNumber": guarantor_num,
            "GuarantorName": get(seg, "gt1_3").replace("^", " "),
            "GuarantorAddress": HL7SegmentParser.format_address(get(seg, "gt1_5")),
            "GuarantorPhone": get(seg, "gt1_6"),
            "GuarantorSSN": get(seg, "gt1_12"),
            "GuarantorEmployer": get(seg, "gt1_16"),
            "GuarantorRelationship": get(seg, "gt1_11"),
        }

    @staticmethod
    def parse_in1(segment: str) -> dict:
        """Parse IN1 insurance segment"""
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        return {
            "SetID": get(seg, "in1_1"),
            "InsurancePlanID": get(seg, "in1_2"),
            "InsuranceCompanyID": get(seg, "in1_3"),
            "InsuranceCompanyName": get(seg, "in1_4"),
            "InsuranceCompanyAddress": HL7SegmentParser.format_address(get(seg, "in1_5")),
            "GroupNumber": get(seg, "in1_8"),
            "InsuredName": get(seg, "in1_16").replace("^", " "),
            "InsuredAddress": HL7SegmentParser.format_address(get(seg, "in1_19")),
            "PolicyNumber": get(seg, "in1_36"),
        }

    @staticmethod
    def parse_rxa(segment: str) -> dict:
        """Parse RXA pharmacy administration segment (per HL7 v2.5 §4.4.4).

        Returns the most operationally useful subset. `DrugCode` is the
        first ^-component of RXA-5 (the code itself, not the full
        code^name^system triple).
        """
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        admin_code_raw = get(seg, "rxa_5")
        drug_code = admin_code_raw.split("^", 1)[0] if admin_code_raw else ""
        return {
            "GiveSubIDCounter": get(seg, "rxa_1"),
            "AdministrationSubIDCounter": get(seg, "rxa_2"),
            "AdminDate": get(seg, "rxa_3"),
            "AdminEndDate": get(seg, "rxa_4"),
            "AdminCode": admin_code_raw,
            "DrugCode": drug_code,
            "AdminAmount": get(seg, "rxa_6"),
            "AdminUnits": get(seg, "rxa_7"),
            "AdministrationNotes": get(seg, "rxa_9"),
            "AdministeringProvider": get(seg, "rxa_10"),
            "SubstanceLotNumber": get(seg, "rxa_15"),
            "CompletionStatus": get(seg, "rxa_20"),
        }

    @staticmethod
    def parse_rxd(segment: str) -> dict:
        """Parse RXD pharmacy dispense segment (per HL7 v2.5 §4.4.6)."""
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        dispense_code_raw = get(seg, "rxd_2")
        drug_code = dispense_code_raw.split("^", 1)[0] if dispense_code_raw else ""
        return {
            "DispenseSubIDCounter": get(seg, "rxd_1"),
            "DispenseGiveCode": dispense_code_raw,
            "DrugCode": drug_code,
            "DispenseDate": get(seg, "rxd_3"),
            "ActualDispenseAmount": get(seg, "rxd_4"),
            "ActualDispenseUnits": get(seg, "rxd_5"),
            "PrescriptionNumber": get(seg, "rxd_7"),
            "NumberOfRefillsRemaining": get(seg, "rxd_8"),
            "DispenseNotes": get(seg, "rxd_9"),
            "DispensingProvider": get(seg, "rxd_10"),
        }

    @staticmethod
    def parse_dsc(segment: str) -> dict:
        """Parse DSC continuation pointer segment"""
        from hl7apy.parser import parse_segment

        seg = parse_segment(segment) if isinstance(segment, str) else segment
        get = HL7SegmentParser._get_field_value
        return {
            "ContinuationPointer": get(seg, "dsc_1"),
            "ContinuationStyle": get(seg, "dsc_2"),
        }


# Module exports
__all__ = ["HL7SegmentBuilder", "HL7SegmentParser"]
