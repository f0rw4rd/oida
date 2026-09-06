"""
DICOM Protocol Scanner

Scans DICOM (Digital Imaging and Communications in Medicine) endpoints for:
- C-ECHO (DICOM ping/verification)
- C-FIND (query patients, studies, series, images)
- C-GET (retrieve images)
- C-STORE (upload images)
- C-MOVE (transfer images to destination)
- AE Title enumeration and brute force
- TLS/security assessment
- Wildcard search capability testing

CLI examples:
    oida dicom 192.168.1.100              # C-ECHO discovery
    oida dicom 192.168.1.100 --aet PACS   # Specify calling AE Title
    oida dicom 192.168.1.100 --aet-brute  # Brute force AE Titles
    oida dicom 192.168.1.100 --find       # C-FIND enumeration
    oida dicom 192.168.1.100 --find --patient-name "*"  # Wildcard search
    oida dicom 192.168.1.100 --find --query-level STUDY  # Study-level query
    oida dicom 192.168.1.100 --get --study-uid 1.2.3.4  # Retrieve images
    oida dicom 192.168.1.100 --store --store-file img.dcm  # Upload image
    oida dicom 192.168.1.100 --move --study-uid 1.2.3 --dest-aet OTHER  # Transfer
"""

from pathlib import Path
from typing import Any, Optional

from ...connection import NetworkConnection
from ...utils.lazy_import import lazy_import

# Lazy imports for DICOM libraries
_pynetdicom = lazy_import("pynetdicom", "DICOM")
_pydicom = lazy_import("pydicom", "DICOM")

# Check availability without loading
PYNETDICOM_AVAILABLE = _pynetdicom.is_available


def _get_ae():
    """Get pynetdicom AE class.

    Looks up via the parent package so unit tests that
    `@patch('oida.protocols.dicom.AE')` can substitute it.
    """
    from oida.protocols import dicom as _pkg

    if _pkg.AE is not None:
        return _pkg.AE
    return _pynetdicom.AE


def _get_sop_classes():
    """Get commonly used SOP classes from pynetdicom."""
    sop = _pynetdicom.sop_class
    return {
        "Verification": sop.Verification,
        "PatientRootQueryRetrieveInformationModelFind": sop.PatientRootQueryRetrieveInformationModelFind,
        "StudyRootQueryRetrieveInformationModelFind": sop.StudyRootQueryRetrieveInformationModelFind,
        "PatientRootQueryRetrieveInformationModelGet": sop.PatientRootQueryRetrieveInformationModelGet,
        "StudyRootQueryRetrieveInformationModelGet": sop.StudyRootQueryRetrieveInformationModelGet,
        "PatientRootQueryRetrieveInformationModelMove": sop.PatientRootQueryRetrieveInformationModelMove,
        "StudyRootQueryRetrieveInformationModelMove": sop.StudyRootQueryRetrieveInformationModelMove,
        "ModalityWorklistInformationFind": sop.ModalityWorklistInformationFind,
        "ModalityPerformedProcedureStep": sop.ModalityPerformedProcedureStep,
        "StorageCommitmentPushModel": sop.StorageCommitmentPushModel,
        "BasicGrayscalePrintManagementMeta": sop.BasicGrayscalePrintManagementMeta,
        "BasicColorPrintManagementMeta": sop.BasicColorPrintManagementMeta,
        "Printer": sop.Printer,
        "PrinterConfigurationRetrieval": sop.PrinterConfigurationRetrieval,
        "PatientStudyOnlyQueryRetrieveInformationModelFind": sop.PatientStudyOnlyQueryRetrieveInformationModelFind,
        "CompositeInstanceRootRetrieveMove": sop.CompositeInstanceRootRetrieveMove,
        "CompositeInstanceRootRetrieveGet": sop.CompositeInstanceRootRetrieveGet,
        "CompositeInstanceRetrieveWithoutBulkDataGet": sop.CompositeInstanceRetrieveWithoutBulkDataGet,
        "UnifiedProcedureStepPush": sop.UnifiedProcedureStepPush,
        "UnifiedProcedureStepWatch": sop.UnifiedProcedureStepWatch,
        "UnifiedProcedureStepPull": sop.UnifiedProcedureStepPull,
        "UnifiedProcedureStepQuery": sop.UnifiedProcedureStepQuery,
        "InstanceAvailabilityNotification": sop.InstanceAvailabilityNotification,
        "HangingProtocolStorage": sop.HangingProtocolStorage,
        "HangingProtocolInformationModelFind": sop.HangingProtocolInformationModelFind,
        "HangingProtocolInformationModelMove": sop.HangingProtocolInformationModelMove,
        "HangingProtocolInformationModelGet": sop.HangingProtocolInformationModelGet,
        "ColorPaletteStorage": sop.ColorPaletteStorage,
        "ColorPaletteInformationModelFind": sop.ColorPaletteInformationModelFind,
        "ColorPaletteInformationModelMove": sop.ColorPaletteInformationModelMove,
        "ColorPaletteInformationModelGet": sop.ColorPaletteInformationModelGet,
        "DisplaySystem": sop.DisplaySystem,
        "DefinedProcedureProtocolInformationModelFind": sop.DefinedProcedureProtocolInformationModelFind,
        "DefinedProcedureProtocolInformationModelMove": sop.DefinedProcedureProtocolInformationModelMove,
        "DefinedProcedureProtocolInformationModelGet": sop.DefinedProcedureProtocolInformationModelGet,
        "ProtocolApprovalStorage": sop.ProtocolApprovalStorage,
        "ProtocolApprovalInformationModelFind": sop.ProtocolApprovalInformationModelFind,
        "ProtocolApprovalInformationModelMove": sop.ProtocolApprovalInformationModelMove,
        "ProtocolApprovalInformationModelGet": sop.ProtocolApprovalInformationModelGet,
        "GenericImplantTemplateStorage": sop.GenericImplantTemplateStorage,
        "GenericImplantTemplateInformationModelFind": sop.GenericImplantTemplateInformationModelFind,
        "GenericImplantTemplateInformationModelMove": sop.GenericImplantTemplateInformationModelMove,
        "GenericImplantTemplateInformationModelGet": sop.GenericImplantTemplateInformationModelGet,
        "InventoryStorage": sop.InventoryStorage,
        "InventoryFind": sop.InventoryFind,
        "InventoryMove": sop.InventoryMove,
        "InventoryGet": sop.InventoryGet,
        "InventoryCreation": sop.InventoryCreation,
        "GeneralRelevantPatientInformationQuery": sop.GeneralRelevantPatientInformationQuery,
        "BreastImagingRelevantPatientInformationQuery": sop.BreastImagingRelevantPatientInformationQuery,
        "CardiacRelevantPatientInformationQuery": sop.CardiacRelevantPatientInformationQuery,
        "MediaCreationManagement": sop.MediaCreationManagement,
        "SubstanceApprovalQuery": sop.SubstanceApprovalQuery,
    }


def _get_dcmread():
    """Get pydicom dcmread function."""
    return _pydicom.dcmread


# Cached SOP classes for module-level use
_sop_cache = {}


def _sop(name: str):
    """Get a SOP class by name, caching for efficiency."""
    if not _sop_cache:
        _sop_cache.update(_get_sop_classes())
    return _sop_cache[name]


def _new_dataset():
    """Create a new pydicom Dataset instance.

    Looks up the class via the parent package so unit tests that
    `@patch('oida.protocols.dicom.Dataset')` can substitute it.
    """
    from oida.protocols import dicom as _pkg

    Dataset = _pkg.Dataset if _pkg.Dataset is not None else _pydicom.Dataset
    return Dataset()


# Default AE Titles to test
# PHI-containing DICOM tags (for --phi-only filtering)
PHI_TAGS = [
    "PatientName",
    "PatientID",
    "PatientBirthDate",
    "PatientSex",
    "PatientAge",
    "PatientAddress",
    "PatientTelephoneNumbers",
    "PatientMotherBirthName",
    "OtherPatientIDs",
    "OtherPatientNames",
    "PatientBirthName",
    "PatientSize",
    "PatientWeight",
    "EthnicGroup",
    "Occupation",
    "AdditionalPatientHistory",
    "PatientComments",
    "PatientReligiousPreference",
    "PatientSpeciesDescription",
    "ResponsiblePerson",
    "ResponsiblePersonRole",
    "ResponsibleOrganization",
    "ReferringPhysicianName",
    "ReferringPhysicianAddress",
    "ReferringPhysicianTelephoneNumbers",
    "PhysiciansOfRecord",
    "PerformingPhysicianName",
    "NameOfPhysiciansReadingStudy",
    "OperatorsName",
    "AdmittingDiagnosesDescription",
    "RequestingPhysician",
    "InstitutionName",
    "InstitutionAddress",
    "InstitutionalDepartmentName",
    "StationName",
    "StudyDescription",
    "SeriesDescription",
    "StudyID",
    "AccessionNumber",
    "FillerOrderNumberImagingServiceRequest",
    "PlacerOrderNumberImagingServiceRequest",
    "PatientInsurancePlanCodeSequence",
    "PatientPrimaryLanguageCodeSequence",
    "PatientBirthTime",
    "MedicalRecordLocator",
    "ReferencedPatientPhotoSequence",
    "MilitaryRank",
    "BranchOfService",
    "ScheduledPatientInstitutionResidence",
    "RegionOfResidence",
    "PatientsSexNeutered",
    "ContentCreatorName",
    "VerifyingObserverName",
    "PersonName",
]

DEFAULT_AET_WORDLIST = [
    # Generic
    "ANY",
    "ANYSCP",
    "ANYSCU",
    "*",
    # Common software
    "PACS",
    "WORKSTATION",
    "STORESCU",
    "FINDSCU",
    "MOVESCU",
    "GETSCU",
    "ORTHANC",
    "DCMTK",
    "OSIRIX",
    "HOROS",
    "RADIANT",
    "CONQUEST",
    "CLEARCANVAS",
    "K-PACS",
    "MIPACS",
    # Modalities
    "CT_SCANNER",
    "MR_SCANNER",
    "CR_SCANNER",
    "DR_SCANNER",
    "US_SCANNER",
    "CT",
    "MR",
    "CR",
    "DR",
    "US",
    "NM",
    "PT",
    "XA",
    "RF",
    "DX",
    # Vendor prefixes
    "GE_PACS",
    "GE_CT",
    "GE_MR",
    "GE_AW",
    "SIEMENS_PACS",
    "SIEMENS_CT",
    "SIEMENS_MR",
    "SIEMENS_SYNGO",
    "PHILIPS_PACS",
    "PHILIPS_CT",
    "PHILIPS_MR",
    "TOSHIBA_CT",
    "TOSHIBA_MR",
    "AGFA_PACS",
    "AGFA_IMPAX",
    "FUJI_PACS",
    "FUJI_SYNAPSE",
    "CARESTREAM",
    "SECTRA",
    "MCKESSON",
    # Default/test
    "DEFAULT",
    "TEST",
    "DICOM",
    "VIEWER",
    "ARCHIVE",
]

# DICOM Implementation Class UID to Vendor/Product mapping
DICOM_VENDOR_MAP = {
    # Open source / common tools
    "1.2.276.0.7230010.3": ("DCMTK", "OFFIS DICOM Toolkit"),
    "1.2.276.0.7230010.3.0.3": ("DCMTK dcmodify", "OFFIS dcmodify tool"),
    "1.2.276.0.7230010.3.1": ("DCMTK storescp", "OFFIS storage SCP"),
    "1.2.826.0.1.3680043.2.135": ("Orthanc", "Open Source PACS"),
    "1.2.40.0.13.1.3": ("pynetdicom", "Python DICOM Network Library"),
    "1.2.826.0.1.3680043.9.3811.3": ("pynetdicom", "Python DICOM networking"),
    "1.2.276.0.20": ("GDCM", "Grassroots DICOM"),
    "1.3.6.1.4.1.30071": ("ClearCanvas", "ClearCanvas Workstation"),
    "1.2.826.0.1.3680043.8.498": ("pydicom", "Python DICOM Library"),
    # Major vendors - GE Healthcare
    "1.2.840.113619": ("GE Healthcare", "GE Medical Systems"),
    "1.2.840.113619.2.5": ("GE Signa", "GE MR Systems"),
    "1.2.840.113619.6": ("GE Centricity", "GE Centricity PACS/RIS"),
    "1.2.840.113619.21": ("GE Centricity EMR", "GE Electronic Medical Records"),
    "1.2.528.1.1001": ("GE Collage", "GE specialized storage"),
    "1.2.276.0.26": ("GE Voluson", "Kretztechnik/GE Ultrasound"),
    # Major vendors - Philips
    "1.3.46.670589": ("Philips", "Philips Healthcare"),
    "1.3.46.670589.11": ("Philips MR", "Philips MR Systems"),
    "1.3.46.670589.11.5406": ("Philips ACS/NT", "Philips MR 6.x"),
    "1.3.46.670589.11.5702": ("Philips Achieva", "Philips Achieva MR"),
    "1.3.46.670589.16": ("Philips Xcelera", "Philips Cardio Workstation"),
    # Major vendors - Siemens
    "2.16.840.1.113662": ("Siemens", "Siemens Healthineers"),
    "1.3.12.2.1107.5": ("Siemens syngo", "Siemens syngo Platform"),
    "1.3.12.2.1107.5.2": ("Siemens Magnetom", "Siemens MR Systems"),
    # Major vendors - Other
    "1.2.392.200036.9116": ("Canon/Toshiba", "Canon Medical Systems"),
    "1.2.840.113704": ("Carestream", "Carestream Health"),
    "1.2.840.113704.7": ("Carestream Vue", "Carestream Vue PACS"),
    "1.2.124.113532": ("Agfa", "Agfa HealthCare"),
    "1.2.840.113564": ("Fujifilm", "Fujifilm Medical Systems"),
    "1.2.840.113564.3": ("Fujifilm Synapse", "Fujifilm Synapse PACS"),
    "1.2.752.24": ("Sectra", "Sectra Medical Systems"),
    "1.2.840.114257": ("Hologic", "Hologic Inc"),
    "1.2.840.113654": ("Merge", "Merge Healthcare (IBM Watson)"),
    "1.2.124.113532.3320": ("Merge PACS", "Merge PACS Broker"),
    "1.2.392.200046": ("Hitachi", "Hitachi Medical Systems"),
    # Note: 2.16.840.1.113662 was historically Picker/Marconi, now Siemens (above)
    # Workstations / Viewers
    "1.2.826.0.1.3680043.2.1143": ("HOROS", "Horos DICOM Viewer (macOS)"),
    "1.2.826.0.1.3680043.9.3811": ("OsiriX", "OsiriX DICOM Viewer"),
    "1.2.276.0.7238010.5": ("Horos/OsiriX", "macOS DICOM Viewer"),
    "1.2.826.0.1.3680043.2.60": ("Conquest", "Conquest DICOM Server"),
    "1.2.250.1.59": ("3Dnet", "3Dnet Medical"),
    "1.2.804.114202.5": ("Intelerad", "InteleViewer PACS"),
    # Cloud/VNA/EHR
    "1.2.840.114350": ("Epic", "Epic Systems"),
    "1.2.840.114358": ("Cerner", "Cerner Corporation"),
    "1.2.250.1.213": ("Medasys/DMS", "French Healthcare IT"),
}


from .mixins import (
    CFindMixin,
    OperationsMixin,
    EnumerationMixin,
    ReportingMixin,
    WorklistMixin,
    FuzzMixin,
)


class dicom(
    CFindMixin,
    OperationsMixin,
    EnumerationMixin,
    ReportingMixin,
    WorklistMixin,
    FuzzMixin,
    NetworkConnection,
):
    """DICOM Scanner (NXC-style)"""

    name = "DICOM"

    def __init__(self, args: Any, db: Optional[Any], host: str):
        self.protocol_name = "dicom"
        # IANA-assigned DICOM port is 104, but the de-facto default for
        # every major PACS implementation (Orthanc, dcm4chee, ConQuest,
        # OFFIS DICOMscope) is 11112. The test suite and our scanner
        # docstring assume 11112, so use that as the default and let
        # operators pass --port 104 if they're scanning a strict IANA
        # deployment.
        self.default_port = 11112
        self.ae = None
        self.assoc = None
        # C-GET state tracking
        self._cget_output_path = None
        self._cget_received_files = []
        super().__init__(args, db, host)

    def _handle_store_for_cget(self, event):
        """Handle incoming C-STORE sub-operations from C-GET"""
        try:
            ds = event.dataset
            ds.file_meta = event.file_meta

            if self._cget_output_path:
                sop_uid = getattr(ds, "SOPInstanceUID", "unknown")

                # Sanitize UIDs for safe filesystem paths. A hostile DICOM
                # responder controls every UID returned in a C-STORE
                # sub-operation; setting PatientID='..' and
                # StudyInstanceUID='..' makes the handler write a .dcm two
                # directories ABOVE _cget_output_path. The old sanitizer
                # only replaced '/' and '\\' but Path('..').name == '..'
                # left the traversal intact.
                def _safe_name(raw: str) -> str:
                    # Drop separators, NUL, control chars, leading dots.
                    cleaned = str(raw).replace("/", "_").replace("\\", "_").replace("\x00", "_")
                    cleaned = "".join(c if c.isprintable() else "_" for c in cleaned)
                    cleaned = cleaned.lstrip(".")  # kills '..', '.', '....', etc.
                    cleaned = Path(cleaned).name
                    return cleaned or "unknown"

                # Resolve filenames and assert they stay inside the
                # configured output directory (belt-and-braces against
                # any sanitizer regression).
                base = self._cget_output_path.resolve()

                def _resolve_inside(p: Path) -> Path:
                    resolved = p.resolve()
                    try:
                        resolved.relative_to(base)
                    except ValueError:
                        raise PermissionError(
                            f"C-STORE write outside output dir blocked: {resolved}"
                        )
                    return resolved

                # Check if we're doing bulk export with subdirectory structure
                if getattr(self, "_cget_use_subdirs", False):
                    # Create patient/study subdirectory structure
                    patient_id = _safe_name(str(getattr(ds, "PatientID", "unknown")))
                    study_uid = _safe_name(str(getattr(ds, "StudyInstanceUID", "unknown"))[-20:])
                    patient_dir = _resolve_inside(self._cget_output_path / patient_id)
                    study_dir = _resolve_inside(patient_dir / study_uid)
                    study_dir.mkdir(parents=True, exist_ok=True)
                    filename = _resolve_inside(study_dir / f"{_safe_name(str(sop_uid))}.dcm")
                else:
                    # Simple flat directory structure
                    filename = _resolve_inside(
                        self._cget_output_path / f"{_safe_name(str(sop_uid))}.dcm"
                    )

                ds.save_as(filename, enforce_file_format=True)
                self._cget_received_files.append(str(filename))

            return 0x0000  # Success
        except Exception as e:
            self.logger.debug(f"C-STORE handler error: {e}")
            return 0xC211  # Failure

    def proto_flow(self):
        """Main DICOM scanning workflow"""

        # Get calling AE Title
        self.calling_aet = getattr(self.args, "aet", "OIDA")
        self.called_aet = getattr(self.args, "called_aet", "ANY-SCP")

        # AET brute force mode
        if getattr(self.args, "aet_brute", None) is not None or getattr(
            self.args, "common_ae", False
        ):
            self._aet_brute_force()
            return

        # Create connection
        if not self.create_conn_obj():
            return

        # Enumerate host info (C-ECHO)
        self.enum_host_info()
        self.print_host_info()

        # C-FIND operations
        if getattr(self.args, "find", False):
            self._cfind_query()

        # Enumeration features
        if getattr(self.args, "enum_operators", False):
            self._enum_operators()

        if getattr(self.args, "enum_devices", False):
            self._enum_devices()

        if getattr(self.args, "time_analysis", False):
            self._time_analysis()

        # Modality Worklist query
        if getattr(self.args, "worklist", False):
            self._worklist_query()

        # Recursive bulk export (--dump-all)
        if getattr(self.args, "dump_all", False):
            if not getattr(self.args, "confirm", False):
                self.logger.fail(
                    "--dump-all performs recursive bulk C-GET of every patient/study "
                    "(mass PHI exfiltration) — requires --confirm"
                )
            else:
                self._recursive_bulk_export()

        # C-GET operations (retrieve images)
        if getattr(self.args, "get", False):
            self._cget_retrieve()

        # C-STORE operations (upload images) — writes an object to the PACS
        if getattr(self.args, "store", False):
            if not getattr(self.args, "confirm", False):
                self.logger.fail(
                    "--store uploads a DICOM object to the PACS (state-changing) — requires --confirm"
                )
            else:
                self._cstore_send()

        # C-MOVE operations (transfer images) — instructs the PACS to move studies
        if getattr(self.args, "move", False):
            if not getattr(self.args, "confirm", False):
                self.logger.fail(
                    "--move instructs the PACS to transfer studies to a destination AET — requires --confirm"
                )
            else:
                self._cmove_request()

        # Fuzzing
        if getattr(self.args, "fuzz", False):
            self._handle_fuzz()

        # Security analysis
        self._analyze_security()

        # Export results if requested
        self._export_results()

        # Cleanup
        self._disconnect()

    def create_conn_obj(self) -> bool:
        """Establish DICOM association"""
        use_tls = getattr(self.args, "tls", False)
        # Resolve the effective port: explicit -p wins; otherwise the advertised
        # TLS port (2762) when --tls is set, else the de-facto PACS default
        # (self.default_port = 11112). Previously a bare --tls connected to 104.
        port = getattr(self.args, "port", None) or (2762 if use_tls else self.default_port)
        timeout = getattr(self.args, "timeout", 10)

        transport = "TLS" if use_tls else "TCP"
        self.logger.info(f"Connecting via {transport}")

        try:
            # Get lazy-loaded classes
            AE = _get_ae()
            evt = _pynetdicom.evt
            sop = _get_sop_classes()
            StoragePresentationContexts = _pynetdicom.StoragePresentationContexts

            # Create Application Entity
            self.ae = AE(ae_title=self.calling_aet)
            self.ae.maximum_pdu_size = getattr(self.args, "max_pdu", 16384)
            self.ae.network_timeout = timeout
            self.ae.acse_timeout = timeout
            self.ae.dimse_timeout = timeout
            # Bound the underlying TCP connect: network/acse/dimse timeouts only
            # apply AFTER the socket connects, so without this an unroutable host
            # hangs for the OS SYN-retry window (~minutes), ignoring --timeout.
            self.ae.connection_timeout = timeout

            # Add presentation contexts - C-ECHO
            self.ae.add_requested_context(sop["Verification"])

            # Add presentation contexts - C-FIND
            self.ae.add_requested_context(sop["PatientRootQueryRetrieveInformationModelFind"])
            self.ae.add_requested_context(sop["StudyRootQueryRetrieveInformationModelFind"])

            # Probe all operations if --probe-ops is set
            probe_ops = getattr(self.args, "probe_ops", False)

            # Add presentation contexts - C-GET (if --get, --dump-all, or --probe-ops).
            # --dump-all triggers _recursive_bulk_export() which issues C-GET, so it
            # MUST negotiate the same QR-model + storage contexts as --get.
            cget_storage_uids: list[str] = []
            if (
                getattr(self.args, "get", False)
                or getattr(self.args, "dump_all", False)
                or probe_ops
            ):
                self.ae.add_requested_context(sop["PatientRootQueryRetrieveInformationModelGet"])
                self.ae.add_requested_context(sop["StudyRootQueryRetrieveInformationModelGet"])
                # Add storage contexts for receiving images (limit to avoid 128 context limit)
                storage_contexts = (
                    list(StoragePresentationContexts)[:50]
                    if probe_ops
                    else StoragePresentationContexts
                )
                for context in storage_contexts:
                    self.ae.add_requested_context(context.abstract_syntax)
                    cget_storage_uids.append(str(context.abstract_syntax))

            # Add presentation contexts - C-MOVE (if --move or --probe-ops)
            if getattr(self.args, "move", False) or probe_ops:
                self.ae.add_requested_context(sop["PatientRootQueryRetrieveInformationModelMove"])
                self.ae.add_requested_context(sop["StudyRootQueryRetrieveInformationModelMove"])

            # Add presentation contexts - C-STORE (if --store, but not for probe - already added above)
            if getattr(self.args, "store", False) and not probe_ops:
                for context in StoragePresentationContexts:
                    self.ae.add_requested_context(context.abstract_syntax)

            # Add presentation contexts - Modality Worklist (if --worklist)
            if getattr(self.args, "worklist", False) and not probe_ops:
                self.ae.add_requested_context(sop["ModalityWorklistInformationFind"])

            # Add additional contexts for full probe
            if probe_ops:
                # Worklist (MWL)
                self.ae.add_requested_context(sop["ModalityWorklistInformationFind"])
                # MPPS
                self.ae.add_requested_context(sop["ModalityPerformedProcedureStep"])
                # Storage Commitment
                self.ae.add_requested_context(sop["StorageCommitmentPushModel"])
                # Print Management
                self.ae.add_requested_context(sop["BasicGrayscalePrintManagementMeta"])
                self.ae.add_requested_context(sop["BasicColorPrintManagementMeta"])
                self.ae.add_requested_context(sop["Printer"])
                self.ae.add_requested_context(sop["PrinterConfigurationRetrieval"])
                # Additional Query/Retrieve
                self.ae.add_requested_context(
                    sop["PatientStudyOnlyQueryRetrieveInformationModelFind"]
                )
                self.ae.add_requested_context(sop["CompositeInstanceRootRetrieveMove"])
                self.ae.add_requested_context(sop["CompositeInstanceRootRetrieveGet"])
                self.ae.add_requested_context(sop["CompositeInstanceRetrieveWithoutBulkDataGet"])
                # Unified Procedure Step (UPS)
                self.ae.add_requested_context(sop["UnifiedProcedureStepPush"])
                self.ae.add_requested_context(sop["UnifiedProcedureStepWatch"])
                self.ae.add_requested_context(sop["UnifiedProcedureStepPull"])
                self.ae.add_requested_context(sop["UnifiedProcedureStepQuery"])
                # Instance Availability
                self.ae.add_requested_context(sop["InstanceAvailabilityNotification"])
                # Hanging Protocol
                self.ae.add_requested_context(sop["HangingProtocolStorage"])
                self.ae.add_requested_context(sop["HangingProtocolInformationModelFind"])
                self.ae.add_requested_context(sop["HangingProtocolInformationModelMove"])
                self.ae.add_requested_context(sop["HangingProtocolInformationModelGet"])
                # Color Palette
                self.ae.add_requested_context(sop["ColorPaletteStorage"])
                self.ae.add_requested_context(sop["ColorPaletteInformationModelFind"])
                self.ae.add_requested_context(sop["ColorPaletteInformationModelMove"])
                self.ae.add_requested_context(sop["ColorPaletteInformationModelGet"])
                # Display System
                self.ae.add_requested_context(sop["DisplaySystem"])
                # Defined Procedure Protocol
                self.ae.add_requested_context(sop["DefinedProcedureProtocolInformationModelFind"])
                self.ae.add_requested_context(sop["DefinedProcedureProtocolInformationModelMove"])
                self.ae.add_requested_context(sop["DefinedProcedureProtocolInformationModelGet"])
                # Protocol Approval
                self.ae.add_requested_context(sop["ProtocolApprovalStorage"])
                self.ae.add_requested_context(sop["ProtocolApprovalInformationModelFind"])
                self.ae.add_requested_context(sop["ProtocolApprovalInformationModelMove"])
                self.ae.add_requested_context(sop["ProtocolApprovalInformationModelGet"])
                # Generic Implant Template
                self.ae.add_requested_context(sop["GenericImplantTemplateStorage"])
                self.ae.add_requested_context(sop["GenericImplantTemplateInformationModelFind"])
                self.ae.add_requested_context(sop["GenericImplantTemplateInformationModelMove"])
                self.ae.add_requested_context(sop["GenericImplantTemplateInformationModelGet"])
                # Inventory
                self.ae.add_requested_context(sop["InventoryStorage"])
                self.ae.add_requested_context(sop["InventoryFind"])
                self.ae.add_requested_context(sop["InventoryMove"])
                self.ae.add_requested_context(sop["InventoryGet"])
                self.ae.add_requested_context(sop["InventoryCreation"])
                # Relevant Patient Information
                self.ae.add_requested_context(sop["GeneralRelevantPatientInformationQuery"])
                self.ae.add_requested_context(sop["BreastImagingRelevantPatientInformationQuery"])
                self.ae.add_requested_context(sop["CardiacRelevantPatientInformationQuery"])
                # Media Creation
                self.ae.add_requested_context(sop["MediaCreationManagement"])
                # Substance
                self.ae.add_requested_context(sop["SubstanceApprovalQuery"])

            # Set up event handlers for C-GET if needed
            evt_handlers = []
            if getattr(self.args, "get", False) or getattr(self.args, "dump_all", False):
                evt_handlers = [(evt.EVT_C_STORE, self._handle_store_for_cget)]

            # C-GET requires the SCU to negotiate the SCP role on every storage
            # context so the peer can push C-STORE sub-operations back over the
            # same association. Without this role selection in ext_neg the handler
            # never fires and bulk export silently retrieves 0 images.
            ext_neg = None
            if cget_storage_uids:
                build_role = _pynetdicom.build_role
                ext_neg = [
                    build_role(uid, scp_role=True, scu_role=False) for uid in cget_storage_uids
                ]

            # Set up TLS context if requested
            tls_args = None
            if use_tls:
                from ...utils.socket_helpers import build_tls_context, check_tls_certificate

                tls_ca = getattr(self.args, "tls_ca", None)
                tls_insecure = getattr(self.args, "tls_insecure", False)
                ssl_cx = build_tls_context(
                    {
                        "tls-cert": getattr(self.args, "tls_cert", None),
                        "tls-key": getattr(self.args, "tls_key", None),
                        "tls-ca": tls_ca,
                        "tls-insecure": tls_insecure,
                    },
                    logger=self.logger,
                )
                # A supplied CA without --tls-insecure means the operator wants
                # real server-certificate verification, so enable hostname checking.
                if tls_ca and not tls_insecure:
                    ssl_cx.check_hostname = True
                tls_args = (ssl_cx, self.ip)  # (ssl_context, server_hostname)
                self.logger.display("Using DICOM TLS (Upper Layer Security)")

                # Probe cert before association (pynetdicom may not expose the socket)
                check_tls_certificate(
                    host=self.ip,
                    port=port,
                    logger=self.logger,
                    protocol="dicom",
                    timeout=getattr(self.args, "timeout", 10),
                    verbose=getattr(self.args, "verbose", 0) > 0,
                )

            # Request association
            tls_msg = " with TLS" if use_tls else ""
            self.logger.info(
                f"Requesting association{tls_msg} (AET: {self.calling_aet} -> {self.called_aet})"
            )
            self.assoc = self.ae.associate(
                self.ip,
                port,
                ae_title=self.called_aet,
                evt_handlers=evt_handlers,
                tls_args=tls_args,
                ext_neg=ext_neg,
            )

            if self.assoc.is_established:
                self.logger.success(
                    f"Association established via {transport} (AET: {self.calling_aet} -> {self.called_aet})"
                )
                self.results["data"]["connected"] = True
                self.results["data"]["calling_aet"] = self.calling_aet
                self.results["data"]["called_aet"] = self.called_aet

                return True
            else:
                reject_info = self._get_reject_info()
                self.logger.fail(f"Association rejected: {reject_info}")
                self.results["data"]["connected"] = False
                return False

        except Exception as e:
            self.logger.debug("create conn obj failed: %s", e)
            self.logger.fail(f"Connection failed: {e}")
            self.results["data"]["connected"] = False
            return False

    def _get_reject_info(self) -> str:
        """Get association rejection details"""
        if not self.assoc:
            return "Unknown"

        if self.assoc.is_rejected:
            info = getattr(self.assoc.acceptor, "info", None)
            source = info.get("result_source", "unknown") if isinstance(info, dict) else "unknown"
            return f"Rejected (source: {source})"
        elif self.assoc.is_aborted:
            return "Aborted by peer"
        else:
            return "Not established"

    def _disconnect(self):
        """Release DICOM association"""
        if self.assoc and self.assoc.is_established:
            try:
                self.assoc.release()
            except Exception as e:
                self.logger.debug(f"Association release failed: {e}")
            self.assoc = None


# Module-level exports
__all__ = ["dicom", "DEFAULT_AET_WORDLIST"]
