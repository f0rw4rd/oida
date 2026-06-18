#!/usr/bin/env python3
"""
Mock DICOM SCP (Service Class Provider) for testing OIDA DICOM scanner

Supports:
- C-ECHO (Verification)
- C-FIND (Patient/Study/Series/Image queries)
- C-GET (Image retrieval)
- C-MOVE (Image transfer to destination AET)
- C-STORE (Receive images)
- Personnel enumeration (--enum-operators)
- Device enumeration (--enum-devices)
- Time analysis (--time-analysis)
- Configurable AE Title whitelist

For AET whitelist testing, set DICOM_AET_WHITELIST environment variable.
"""

import logging
import os
from datetime import datetime

import numpy as np
from pynetdicom import AE, evt, StoragePresentationContexts
from pynetdicom.sop_class import (
    Verification,
    PatientRootQueryRetrieveInformationModelFind,
    StudyRootQueryRetrieveInformationModelFind,
    PatientRootQueryRetrieveInformationModelGet,
    StudyRootQueryRetrieveInformationModelGet,
    PatientRootQueryRetrieveInformationModelMove,
    StudyRootQueryRetrieveInformationModelMove,
    CTImageStorage,
    MRImageStorage,
    SecondaryCaptureImageStorage,
    StorageCommitmentPushModel,
    UnifiedProcedureStepPush,
    UnifiedProcedureStepPull,
    UnifiedProcedureStepWatch,
    UnifiedProcedureStepQuery,
)
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.uid import ImplicitVRLittleEndian, generate_uid

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Server configuration
SERVER_AET = os.environ.get("DICOM_AET", "MOCK_PACS")
SERVER_PORT = int(os.environ.get("DICOM_PORT", "11112"))

# AE Title whitelist (comma-separated, or empty for no whitelist)
AET_WHITELIST_STR = os.environ.get("DICOM_AET_WHITELIST", "")
AET_WHITELIST = [aet.strip() for aet in AET_WHITELIST_STR.split(",") if aet.strip()]

# Mock patient data
MOCK_PATIENTS = [
    {
        "PatientName": "DOE^JOHN",
        "PatientID": "PT001",
        "PatientBirthDate": "19800101",
        "PatientSex": "M",
        "NumberOfPatientRelatedStudies": "3",
    },
    {
        "PatientName": "SMITH^JANE",
        "PatientID": "PT002",
        "PatientBirthDate": "19750515",
        "PatientSex": "F",
        "NumberOfPatientRelatedStudies": "5",
    },
    {
        "PatientName": "JOHNSON^ROBERT",
        "PatientID": "PT003",
        "PatientBirthDate": "19650320",
        "PatientSex": "M",
        "NumberOfPatientRelatedStudies": "2",
    },
    {
        "PatientName": "WILLIAMS^MARY",
        "PatientID": "PT004",
        "PatientBirthDate": "19900710",
        "PatientSex": "F",
        "NumberOfPatientRelatedStudies": "1",
    },
    {
        "PatientName": "BROWN^DAVID",
        "PatientID": "PT005",
        "PatientBirthDate": "19551230",
        "PatientSex": "M",
        "NumberOfPatientRelatedStudies": "8",
    },
]

# Mock study data with personnel and device metadata for enumeration testing
# Studies span 2015-2024 for --time-analysis testing
MOCK_STUDIES = [
    # Patient PT001 studies (3 studies)
    {
        "PatientName": "DOE^JOHN",
        "PatientID": "PT001",
        "PatientBirthDate": "19800101",
        "PatientSex": "M",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.1.1",
        "StudyDate": "20150312",
        "StudyTime": "091500",
        "StudyDescription": "CT CHEST WITH CONTRAST",
        "AccessionNumber": "ACC001",
        "Modality": "CT",
        "OperatorsName": "TECH^SARAH^M",
        "PerformingPhysicianName": "RADIOLOGIST^JAMES^DR",
        "ReferringPhysicianName": "SMITH^MICHAEL^MD",
        "NameOfPhysiciansReadingStudy": "READER^ANNA^DR",
        "RequestingPhysician": "PRIMARY^CARE^DR",
        "StationName": "CT_SCANNER_01",
        "Manufacturer": "GE Healthcare",
        "ManufacturerModelName": "Revolution CT",
        "InstitutionName": "GENERAL HOSPITAL",
        "InstitutionalDepartmentName": "RADIOLOGY",
        "NumberOfStudyRelatedSeries": "4",
        "NumberOfStudyRelatedInstances": "256",
    },
    {
        "PatientName": "DOE^JOHN",
        "PatientID": "PT001",
        "PatientBirthDate": "19800101",
        "PatientSex": "M",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.1.2",
        "StudyDate": "20200623",
        "StudyTime": "143000",
        "StudyDescription": "MR BRAIN WITH GADOLINIUM",
        "AccessionNumber": "ACC002",
        "Modality": "MR",
        "OperatorsName": "TECH^ROBERT^J",
        "PerformingPhysicianName": "NEURORAD^LISA^DR",
        "ReferringPhysicianName": "NEUROLOGIST^DAVID^MD",
        "NameOfPhysiciansReadingStudy": "NEURORAD^LISA^DR",
        "RequestingPhysician": "NEUROLOGIST^DAVID^MD",
        "StationName": "MRI_SCANNER_02",
        "Manufacturer": "Siemens Healthineers",
        "ManufacturerModelName": "MAGNETOM Vida",
        "InstitutionName": "GENERAL HOSPITAL",
        "InstitutionalDepartmentName": "NEURORADIOLOGY",
        "NumberOfStudyRelatedSeries": "8",
        "NumberOfStudyRelatedInstances": "512",
    },
    {
        "PatientName": "DOE^JOHN",
        "PatientID": "PT001",
        "PatientBirthDate": "19800101",
        "PatientSex": "M",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.1.3",
        "StudyDate": "20241115",
        "StudyTime": "081500",
        "StudyDescription": "CT ABDOMEN PELVIS",
        "AccessionNumber": "ACC003",
        "Modality": "CT",
        "OperatorsName": "TECH^EMILY^K",
        "PerformingPhysicianName": "BODYIMAGING^MARK^DR",
        "ReferringPhysicianName": "GASTRO^SUSAN^MD",
        "NameOfPhysiciansReadingStudy": "BODYIMAGING^MARK^DR",
        "RequestingPhysician": "GASTRO^SUSAN^MD",
        "StationName": "CT_SCANNER_03",
        "Manufacturer": "Philips",
        "ManufacturerModelName": "Spectral CT 7500",
        "InstitutionName": "GENERAL HOSPITAL",
        "InstitutionalDepartmentName": "BODY IMAGING",
        "NumberOfStudyRelatedSeries": "3",
        "NumberOfStudyRelatedInstances": "180",
    },
    # Patient PT002 studies (5 studies spanning years)
    {
        "PatientName": "SMITH^JANE",
        "PatientID": "PT002",
        "PatientBirthDate": "19750515",
        "PatientSex": "F",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.2.1",
        "StudyDate": "20160815",
        "StudyTime": "102000",
        "StudyDescription": "US BREAST BILATERAL",
        "AccessionNumber": "ACC004",
        "Modality": "US",
        "OperatorsName": "SONOGRAPHER^MARY^A",
        "PerformingPhysicianName": "BREAST^IMAGING^DR",
        "ReferringPhysicianName": "ONCOLOGIST^KAREN^MD",
        "NameOfPhysiciansReadingStudy": "BREAST^IMAGING^DR",
        "RequestingPhysician": "ONCOLOGIST^KAREN^MD",
        "StationName": "US_BREAST_01",
        "Manufacturer": "Philips",
        "ManufacturerModelName": "EPIQ Elite",
        "InstitutionName": "WOMENS HEALTH CENTER",
        "InstitutionalDepartmentName": "BREAST IMAGING",
        "NumberOfStudyRelatedSeries": "2",
        "NumberOfStudyRelatedInstances": "45",
    },
    {
        "PatientName": "SMITH^JANE",
        "PatientID": "PT002",
        "PatientBirthDate": "19750515",
        "PatientSex": "F",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.2.2",
        "StudyDate": "20180312",
        "StudyTime": "140000",
        "StudyDescription": "MG SCREENING BILATERAL",
        "AccessionNumber": "ACC005",
        "Modality": "MG",
        "OperatorsName": "MAMMO^TECH^SUE",
        "PerformingPhysicianName": "BREAST^IMAGING^DR",
        "ReferringPhysicianName": "PRIMARY^JANE^MD",
        "NameOfPhysiciansReadingStudy": "BREAST^IMAGING^DR",
        "RequestingPhysician": "PRIMARY^JANE^MD",
        "StationName": "MAMMO_01",
        "Manufacturer": "Hologic",
        "ManufacturerModelName": "Selenia Dimensions",
        "InstitutionName": "WOMENS HEALTH CENTER",
        "InstitutionalDepartmentName": "MAMMOGRAPHY",
        "NumberOfStudyRelatedSeries": "4",
        "NumberOfStudyRelatedInstances": "8",
    },
    {
        "PatientName": "SMITH^JANE",
        "PatientID": "PT002",
        "PatientBirthDate": "19750515",
        "PatientSex": "F",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.2.3",
        "StudyDate": "20200615",
        "StudyTime": "093000",
        "StudyDescription": "CT CHEST LOW DOSE SCREENING",
        "AccessionNumber": "ACC006",
        "Modality": "CT",
        "OperatorsName": "TECH^SARAH^M",
        "PerformingPhysicianName": "PULM^RAD^DR",
        "ReferringPhysicianName": "PULMONOLOGIST^GARY^MD",
        "NameOfPhysiciansReadingStudy": "PULM^RAD^DR",
        "RequestingPhysician": "PULMONOLOGIST^GARY^MD",
        "StationName": "CT_SCANNER_01",
        "Manufacturer": "GE Healthcare",
        "ManufacturerModelName": "Revolution CT",
        "InstitutionName": "GENERAL HOSPITAL",
        "InstitutionalDepartmentName": "RADIOLOGY",
        "NumberOfStudyRelatedSeries": "2",
        "NumberOfStudyRelatedInstances": "120",
    },
    {
        "PatientName": "SMITH^JANE",
        "PatientID": "PT002",
        "PatientBirthDate": "19750515",
        "PatientSex": "F",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.2.4",
        "StudyDate": "20220901",
        "StudyTime": "110000",
        "StudyDescription": "MG DIAGNOSTIC LEFT",
        "AccessionNumber": "ACC007",
        "Modality": "MG",
        "OperatorsName": "MAMMO^TECH^RITA",
        "PerformingPhysicianName": "BREAST^IMAGING^DR",
        "ReferringPhysicianName": "SURGEON^BREAST^MD",
        "NameOfPhysiciansReadingStudy": "BREAST^IMAGING^DR",
        "RequestingPhysician": "SURGEON^BREAST^MD",
        "StationName": "MAMMO_02",
        "Manufacturer": "Hologic",
        "ManufacturerModelName": "3Dimensions",
        "InstitutionName": "WOMENS HEALTH CENTER",
        "InstitutionalDepartmentName": "MAMMOGRAPHY",
        "NumberOfStudyRelatedSeries": "6",
        "NumberOfStudyRelatedInstances": "12",
    },
    {
        "PatientName": "SMITH^JANE",
        "PatientID": "PT002",
        "PatientBirthDate": "19750515",
        "PatientSex": "F",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.2.5",
        "StudyDate": "20241201",
        "StudyTime": "143000",
        "StudyDescription": "PET CT ONCOLOGY",
        "AccessionNumber": "ACC008",
        "Modality": "PT",
        "OperatorsName": "NUCLEAR^TECH^JIM",
        "PerformingPhysicianName": "NUCLEAR^MED^DR",
        "ReferringPhysicianName": "ONCOLOGIST^KAREN^MD",
        "NameOfPhysiciansReadingStudy": "NUCLEAR^MED^DR",
        "RequestingPhysician": "ONCOLOGIST^KAREN^MD",
        "StationName": "PET_CT_01",
        "Manufacturer": "Siemens Healthineers",
        "ManufacturerModelName": "Biograph Vision",
        "InstitutionName": "CANCER CENTER",
        "InstitutionalDepartmentName": "NUCLEAR MEDICINE",
        "NumberOfStudyRelatedSeries": "5",
        "NumberOfStudyRelatedInstances": "350",
    },
    # Patient PT003 studies (2 studies)
    {
        "PatientName": "JOHNSON^ROBERT",
        "PatientID": "PT003",
        "PatientBirthDate": "19650320",
        "PatientSex": "M",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.3.1",
        "StudyDate": "20170520",
        "StudyTime": "083000",
        "StudyDescription": "XA CARDIAC CATH",
        "AccessionNumber": "ACC009",
        "Modality": "XA",
        "OperatorsName": "CATH^TECH^BOB",
        "PerformingPhysicianName": "CARDIO^INTERV^DR",
        "ReferringPhysicianName": "CARDIOLOGIST^PETER^MD",
        "NameOfPhysiciansReadingStudy": "CARDIO^INTERV^DR",
        "RequestingPhysician": "CARDIOLOGIST^PETER^MD",
        "StationName": "CATH_LAB_01",
        "Manufacturer": "GE Healthcare",
        "ManufacturerModelName": "Innova IGS 530",
        "InstitutionName": "CARDIAC CENTER",
        "InstitutionalDepartmentName": "CATH LAB",
        "NumberOfStudyRelatedSeries": "10",
        "NumberOfStudyRelatedInstances": "500",
    },
    {
        "PatientName": "JOHNSON^ROBERT",
        "PatientID": "PT003",
        "PatientBirthDate": "19650320",
        "PatientSex": "M",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.3.2",
        "StudyDate": "20231015",
        "StudyTime": "150000",
        "StudyDescription": "CT CORONARY ANGIO",
        "AccessionNumber": "ACC010",
        "Modality": "CT",
        "OperatorsName": "TECH^EMILY^K",
        "PerformingPhysicianName": "CARDIAC^CT^DR",
        "ReferringPhysicianName": "CARDIOLOGIST^PETER^MD",
        "NameOfPhysiciansReadingStudy": "CARDIAC^CT^DR",
        "RequestingPhysician": "CARDIOLOGIST^PETER^MD",
        "StationName": "CT_CARDIAC_01",
        "Manufacturer": "Canon Medical",
        "ManufacturerModelName": "Aquilion ONE",
        "InstitutionName": "CARDIAC CENTER",
        "InstitutionalDepartmentName": "CARDIAC CT",
        "NumberOfStudyRelatedSeries": "6",
        "NumberOfStudyRelatedInstances": "400",
    },
    # Patient PT004 studies (1 study - recent)
    {
        "PatientName": "WILLIAMS^MARY",
        "PatientID": "PT004",
        "PatientBirthDate": "19900710",
        "PatientSex": "F",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.4.1",
        "StudyDate": "20241210",
        "StudyTime": "091500",
        "StudyDescription": "CR CHEST PA LAT",
        "AccessionNumber": "ACC011",
        "Modality": "CR",
        "OperatorsName": "XRAY^TECH^DAN",
        "PerformingPhysicianName": "RADIOLOGIST^JAMES^DR",
        "ReferringPhysicianName": "ER^PHYSICIAN^MD",
        "NameOfPhysiciansReadingStudy": "RADIOLOGIST^JAMES^DR",
        "RequestingPhysician": "ER^PHYSICIAN^MD",
        "StationName": "CR_ER_01",
        "Manufacturer": "Carestream",
        "ManufacturerModelName": "DRX-Evolution Plus",
        "InstitutionName": "GENERAL HOSPITAL",
        "InstitutionalDepartmentName": "EMERGENCY RADIOLOGY",
        "NumberOfStudyRelatedSeries": "1",
        "NumberOfStudyRelatedInstances": "2",
    },
    # Patient PT005 studies (8 studies - longest history, for time analysis)
    {
        "PatientName": "BROWN^DAVID",
        "PatientID": "PT005",
        "PatientBirthDate": "19551230",
        "PatientSex": "M",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.5.1",
        "StudyDate": "20150105",
        "StudyTime": "080000",
        "StudyDescription": "CT HEAD WITHOUT CONTRAST",
        "AccessionNumber": "ACC012",
        "Modality": "CT",
        "OperatorsName": "TECH^OLD^TOM",
        "PerformingPhysicianName": "NEURORAD^LISA^DR",
        "ReferringPhysicianName": "NEUROLOGIST^DAVID^MD",
        "NameOfPhysiciansReadingStudy": "NEURORAD^LISA^DR",
        "RequestingPhysician": "NEUROLOGIST^DAVID^MD",
        "StationName": "CT_SCANNER_OLD",
        "Manufacturer": "Toshiba",
        "ManufacturerModelName": "Aquilion 64",
        "InstitutionName": "GENERAL HOSPITAL",
        "InstitutionalDepartmentName": "NEURORADIOLOGY",
        "NumberOfStudyRelatedSeries": "2",
        "NumberOfStudyRelatedInstances": "64",
    },
    {
        "PatientName": "BROWN^DAVID",
        "PatientID": "PT005",
        "PatientBirthDate": "19551230",
        "PatientSex": "M",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.5.2",
        "StudyDate": "20160708",
        "StudyTime": "100000",
        "StudyDescription": "US ABDOMEN COMPLETE",
        "AccessionNumber": "ACC013",
        "Modality": "US",
        "OperatorsName": "SONOGRAPHER^MARY^A",
        "PerformingPhysicianName": "BODYIMAGING^MARK^DR",
        "ReferringPhysicianName": "INTERNIST^JOHN^MD",
        "NameOfPhysiciansReadingStudy": "BODYIMAGING^MARK^DR",
        "RequestingPhysician": "INTERNIST^JOHN^MD",
        "StationName": "US_GENERAL_01",
        "Manufacturer": "GE Healthcare",
        "ManufacturerModelName": "LOGIQ E10",
        "InstitutionName": "GENERAL HOSPITAL",
        "InstitutionalDepartmentName": "ULTRASOUND",
        "NumberOfStudyRelatedSeries": "3",
        "NumberOfStudyRelatedInstances": "80",
    },
    {
        "PatientName": "BROWN^DAVID",
        "PatientID": "PT005",
        "PatientBirthDate": "19551230",
        "PatientSex": "M",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.5.3",
        "StudyDate": "20171115",
        "StudyTime": "143000",
        "StudyDescription": "NM BONE SCAN WHOLE BODY",
        "AccessionNumber": "ACC014",
        "Modality": "NM",
        "OperatorsName": "NUCLEAR^TECH^JIM",
        "PerformingPhysicianName": "NUCLEAR^MED^DR",
        "ReferringPhysicianName": "ORTHOPEDIC^SURGEON^MD",
        "NameOfPhysiciansReadingStudy": "NUCLEAR^MED^DR",
        "RequestingPhysician": "ORTHOPEDIC^SURGEON^MD",
        "StationName": "GAMMA_CAM_01",
        "Manufacturer": "Siemens Healthineers",
        "ManufacturerModelName": "Symbia Evo",
        "InstitutionName": "GENERAL HOSPITAL",
        "InstitutionalDepartmentName": "NUCLEAR MEDICINE",
        "NumberOfStudyRelatedSeries": "4",
        "NumberOfStudyRelatedInstances": "128",
    },
    {
        "PatientName": "BROWN^DAVID",
        "PatientID": "PT005",
        "PatientBirthDate": "19551230",
        "PatientSex": "M",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.5.4",
        "StudyDate": "20190220",
        "StudyTime": "083000",
        "StudyDescription": "MR LUMBAR SPINE",
        "AccessionNumber": "ACC015",
        "Modality": "MR",
        "OperatorsName": "TECH^ROBERT^J",
        "PerformingPhysicianName": "SPINE^RAD^DR",
        "ReferringPhysicianName": "NEUROSURGEON^SPINE^MD",
        "NameOfPhysiciansReadingStudy": "SPINE^RAD^DR",
        "RequestingPhysician": "NEUROSURGEON^SPINE^MD",
        "StationName": "MRI_SCANNER_02",
        "Manufacturer": "Siemens Healthineers",
        "ManufacturerModelName": "MAGNETOM Vida",
        "InstitutionName": "GENERAL HOSPITAL",
        "InstitutionalDepartmentName": "MUSCULOSKELETAL",
        "NumberOfStudyRelatedSeries": "5",
        "NumberOfStudyRelatedInstances": "200",
    },
    {
        "PatientName": "BROWN^DAVID",
        "PatientID": "PT005",
        "PatientBirthDate": "19551230",
        "PatientSex": "M",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.5.5",
        "StudyDate": "20200901",
        "StudyTime": "110000",
        "StudyDescription": "CT SPINE CERVICAL",
        "AccessionNumber": "ACC016",
        "Modality": "CT",
        "OperatorsName": "TECH^SARAH^M",
        "PerformingPhysicianName": "SPINE^RAD^DR",
        "ReferringPhysicianName": "NEUROSURGEON^SPINE^MD",
        "NameOfPhysiciansReadingStudy": "SPINE^RAD^DR",
        "RequestingPhysician": "NEUROSURGEON^SPINE^MD",
        "StationName": "CT_SCANNER_01",
        "Manufacturer": "GE Healthcare",
        "ManufacturerModelName": "Revolution CT",
        "InstitutionName": "GENERAL HOSPITAL",
        "InstitutionalDepartmentName": "MUSCULOSKELETAL",
        "NumberOfStudyRelatedSeries": "3",
        "NumberOfStudyRelatedInstances": "150",
    },
    {
        "PatientName": "BROWN^DAVID",
        "PatientID": "PT005",
        "PatientBirthDate": "19551230",
        "PatientSex": "M",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.5.6",
        "StudyDate": "20211105",
        "StudyTime": "150000",
        "StudyDescription": "DR KNEE LEFT 3 VIEWS",
        "AccessionNumber": "ACC017",
        "Modality": "DR",
        "OperatorsName": "XRAY^TECH^DAN",
        "PerformingPhysicianName": "RADIOLOGIST^JAMES^DR",
        "ReferringPhysicianName": "ORTHOPEDIC^SURGEON^MD",
        "NameOfPhysiciansReadingStudy": "RADIOLOGIST^JAMES^DR",
        "RequestingPhysician": "ORTHOPEDIC^SURGEON^MD",
        "StationName": "DR_ORTHO_01",
        "Manufacturer": "Fujifilm",
        "ManufacturerModelName": "FDR D-EVO II",
        "InstitutionName": "ORTHOPEDIC CLINIC",
        "InstitutionalDepartmentName": "ORTHOPEDIC IMAGING",
        "NumberOfStudyRelatedSeries": "1",
        "NumberOfStudyRelatedInstances": "3",
    },
    {
        "PatientName": "BROWN^DAVID",
        "PatientID": "PT005",
        "PatientBirthDate": "19551230",
        "PatientSex": "M",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.5.7",
        "StudyDate": "20230315",
        "StudyTime": "090000",
        "StudyDescription": "RF UPPER GI SERIES",
        "AccessionNumber": "ACC018",
        "Modality": "RF",
        "OperatorsName": "FLUORO^TECH^ANN",
        "PerformingPhysicianName": "GI^RAD^DR",
        "ReferringPhysicianName": "GASTRO^SUSAN^MD",
        "NameOfPhysiciansReadingStudy": "GI^RAD^DR",
        "RequestingPhysician": "GASTRO^SUSAN^MD",
        "StationName": "FLUORO_01",
        "Manufacturer": "Shimadzu",
        "ManufacturerModelName": "Sonialvision G4",
        "InstitutionName": "GENERAL HOSPITAL",
        "InstitutionalDepartmentName": "FLUOROSCOPY",
        "NumberOfStudyRelatedSeries": "2",
        "NumberOfStudyRelatedInstances": "50",
    },
    {
        "PatientName": "BROWN^DAVID",
        "PatientID": "PT005",
        "PatientBirthDate": "19551230",
        "PatientSex": "M",
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.5.8",
        "StudyDate": "20241218",
        "StudyTime": "081500",
        "StudyDescription": "CT CHEST ABDOMEN PELVIS",
        "AccessionNumber": "ACC019",
        "Modality": "CT",
        "OperatorsName": "TECH^EMILY^K",
        "PerformingPhysicianName": "BODYIMAGING^MARK^DR",
        "ReferringPhysicianName": "INTERNIST^JOHN^MD",
        "NameOfPhysiciansReadingStudy": "BODYIMAGING^MARK^DR",
        "RequestingPhysician": "INTERNIST^JOHN^MD",
        "StationName": "CT_SCANNER_03",
        "Manufacturer": "Philips",
        "ManufacturerModelName": "Spectral CT 7500",
        "InstitutionName": "GENERAL HOSPITAL",
        "InstitutionalDepartmentName": "BODY IMAGING",
        "NumberOfStudyRelatedSeries": "4",
        "NumberOfStudyRelatedInstances": "320",
    },
]

# Mock series data for SERIES-level queries and device enumeration
MOCK_SERIES = [
    # Series for first study (CT CHEST)
    {
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.1.1",
        "SeriesInstanceUID": "1.2.840.10008.5.1.4.1.1.1.1.1",
        "SeriesNumber": "1",
        "SeriesDescription": "SCOUT",
        "Modality": "CT",
        "StationName": "CT_SCANNER_01",
        "Manufacturer": "GE Healthcare",
        "ManufacturerModelName": "Revolution CT",
        "NumberOfSeriesRelatedInstances": "2",
        "OperatorsName": "TECH^SARAH^M",
        "PerformingPhysicianName": "RADIOLOGIST^JAMES^DR",
    },
    {
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.1.1",
        "SeriesInstanceUID": "1.2.840.10008.5.1.4.1.1.1.1.2",
        "SeriesNumber": "2",
        "SeriesDescription": "AXIAL IMAGES 5MM",
        "Modality": "CT",
        "StationName": "CT_SCANNER_01",
        "Manufacturer": "GE Healthcare",
        "ManufacturerModelName": "Revolution CT",
        "NumberOfSeriesRelatedInstances": "100",
        "OperatorsName": "TECH^SARAH^M",
        "PerformingPhysicianName": "RADIOLOGIST^JAMES^DR",
    },
    {
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.1.1",
        "SeriesInstanceUID": "1.2.840.10008.5.1.4.1.1.1.1.3",
        "SeriesNumber": "3",
        "SeriesDescription": "AXIAL IMAGES 1.25MM",
        "Modality": "CT",
        "StationName": "CT_SCANNER_01",
        "Manufacturer": "GE Healthcare",
        "ManufacturerModelName": "Revolution CT",
        "NumberOfSeriesRelatedInstances": "150",
        "OperatorsName": "TECH^SARAH^M",
        "PerformingPhysicianName": "RADIOLOGIST^JAMES^DR",
    },
    {
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.1.1",
        "SeriesInstanceUID": "1.2.840.10008.5.1.4.1.1.1.1.4",
        "SeriesNumber": "4",
        "SeriesDescription": "CORONAL REFORMATS",
        "Modality": "CT",
        "StationName": "CT_SCANNER_01",
        "Manufacturer": "GE Healthcare",
        "ManufacturerModelName": "Revolution CT",
        "NumberOfSeriesRelatedInstances": "4",
        "OperatorsName": "TECH^SARAH^M",
        "PerformingPhysicianName": "RADIOLOGIST^JAMES^DR",
    },
    # Series for MR Brain study
    {
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.1.2",
        "SeriesInstanceUID": "1.2.840.10008.5.1.4.1.1.1.2.1",
        "SeriesNumber": "1",
        "SeriesDescription": "3-PLANE LOCALIZER",
        "Modality": "MR",
        "StationName": "MRI_SCANNER_02",
        "Manufacturer": "Siemens Healthineers",
        "ManufacturerModelName": "MAGNETOM Vida",
        "NumberOfSeriesRelatedInstances": "15",
        "OperatorsName": "TECH^ROBERT^J",
        "PerformingPhysicianName": "NEURORAD^LISA^DR",
    },
    {
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.1.2",
        "SeriesInstanceUID": "1.2.840.10008.5.1.4.1.1.1.2.2",
        "SeriesNumber": "2",
        "SeriesDescription": "AX T1 MPRAGE",
        "Modality": "MR",
        "StationName": "MRI_SCANNER_02",
        "Manufacturer": "Siemens Healthineers",
        "ManufacturerModelName": "MAGNETOM Vida",
        "NumberOfSeriesRelatedInstances": "176",
        "OperatorsName": "TECH^ROBERT^J",
        "PerformingPhysicianName": "NEURORAD^LISA^DR",
    },
    {
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.1.2",
        "SeriesInstanceUID": "1.2.840.10008.5.1.4.1.1.1.2.3",
        "SeriesNumber": "3",
        "SeriesDescription": "AX T2 FLAIR",
        "Modality": "MR",
        "StationName": "MRI_SCANNER_02",
        "Manufacturer": "Siemens Healthineers",
        "ManufacturerModelName": "MAGNETOM Vida",
        "NumberOfSeriesRelatedInstances": "30",
        "OperatorsName": "TECH^ROBERT^J",
        "PerformingPhysicianName": "NEURORAD^LISA^DR",
    },
    {
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.1.2",
        "SeriesInstanceUID": "1.2.840.10008.5.1.4.1.1.1.2.4",
        "SeriesNumber": "4",
        "SeriesDescription": "AX DWI",
        "Modality": "MR",
        "StationName": "MRI_SCANNER_02",
        "Manufacturer": "Siemens Healthineers",
        "ManufacturerModelName": "MAGNETOM Vida",
        "NumberOfSeriesRelatedInstances": "60",
        "OperatorsName": "TECH^ROBERT^J",
        "PerformingPhysicianName": "NEURORAD^LISA^DR",
    },
    # Series for Cardiac Cath study
    {
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.3.1",
        "SeriesInstanceUID": "1.2.840.10008.5.1.4.1.1.3.1.1",
        "SeriesNumber": "1",
        "SeriesDescription": "LEFT CORONARY ARTERY",
        "Modality": "XA",
        "StationName": "CATH_LAB_01",
        "Manufacturer": "GE Healthcare",
        "ManufacturerModelName": "Innova IGS 530",
        "NumberOfSeriesRelatedInstances": "150",
        "OperatorsName": "CATH^TECH^BOB",
        "PerformingPhysicianName": "CARDIO^INTERV^DR",
    },
    {
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.3.1",
        "SeriesInstanceUID": "1.2.840.10008.5.1.4.1.1.3.1.2",
        "SeriesNumber": "2",
        "SeriesDescription": "RIGHT CORONARY ARTERY",
        "Modality": "XA",
        "StationName": "CATH_LAB_01",
        "Manufacturer": "GE Healthcare",
        "ManufacturerModelName": "Innova IGS 530",
        "NumberOfSeriesRelatedInstances": "100",
        "OperatorsName": "CATH^TECH^BOB",
        "PerformingPhysicianName": "CARDIO^INTERV^DR",
    },
    {
        "StudyInstanceUID": "1.2.840.10008.5.1.4.1.1.3.1",
        "SeriesInstanceUID": "1.2.840.10008.5.1.4.1.1.3.1.3",
        "SeriesNumber": "3",
        "SeriesDescription": "LEFT VENTRICULOGRAM",
        "Modality": "XA",
        "StationName": "CATH_LAB_01",
        "Manufacturer": "GE Healthcare",
        "ManufacturerModelName": "Innova IGS 530",
        "NumberOfSeriesRelatedInstances": "200",
        "OperatorsName": "CATH^TECH^BOB",
        "PerformingPhysicianName": "CARDIO^INTERV^DR",
    },
]

# Mock UPS (Unified Procedure Step) data for workflow testing
MOCK_UPS = [
    {
        "SOPInstanceUID": "1.2.840.10008.5.1.4.34.5.1",
        "ProcedureStepState": "SCHEDULED",
        "ProcedureStepLabel": "CT Chest Contrast",
        "WorklistLabel": "Radiology Worklist",
        "PatientName": "DOE^JOHN",
        "PatientID": "PT001",
        "PatientBirthDate": "19800101",
        "ScheduledProcedureStepStartDateTime": "20250130100000",
        "ScheduledStationName": "CT_SCANNER_01",
        "ScheduledProcessingParameters": "Standard Protocol",
    },
    {
        "SOPInstanceUID": "1.2.840.10008.5.1.4.34.5.2",
        "ProcedureStepState": "IN PROGRESS",
        "ProcedureStepLabel": "MR Brain Gadolinium",
        "WorklistLabel": "Radiology Worklist",
        "PatientName": "SMITH^JANE",
        "PatientID": "PT002",
        "PatientBirthDate": "19750515",
        "ScheduledProcedureStepStartDateTime": "20250130090000",
        "ScheduledStationName": "MRI_SCANNER_02",
        "ScheduledProcessingParameters": "Neuro Protocol",
    },
    {
        "SOPInstanceUID": "1.2.840.10008.5.1.4.34.5.3",
        "ProcedureStepState": "COMPLETED",
        "ProcedureStepLabel": "US Abdomen Complete",
        "WorklistLabel": "Ultrasound Worklist",
        "PatientName": "BROWN^DAVID",
        "PatientID": "PT005",
        "PatientBirthDate": "19551230",
        "ScheduledProcedureStepStartDateTime": "20250129140000",
        "ScheduledStationName": "US_GENERAL_01",
        "ScheduledProcessingParameters": "Abdominal Protocol",
    },
    {
        "SOPInstanceUID": "1.2.840.10008.5.1.4.34.5.4",
        "ProcedureStepState": "SCHEDULED",
        "ProcedureStepLabel": "XA Cardiac Catheterization",
        "WorklistLabel": "Cath Lab Worklist",
        "PatientName": "WILLIAMS^MARY",
        "PatientID": "PT004",
        "PatientBirthDate": "19900710",
        "ScheduledProcedureStepStartDateTime": "20250131080000",
        "ScheduledStationName": "CATH_LAB_01",
        "ScheduledProcessingParameters": "Cardiac Protocol",
    },
    {
        "SOPInstanceUID": "1.2.840.10008.5.1.4.34.5.5",
        "ProcedureStepState": "CANCELED",
        "ProcedureStepLabel": "CT Abdomen Pelvis",
        "WorklistLabel": "Radiology Worklist",
        "PatientName": "JOHNSON^ROBERT",
        "PatientID": "PT003",
        "PatientBirthDate": "19650320",
        "ScheduledProcedureStepStartDateTime": "20250128110000",
        "ScheduledStationName": "CT_SCANNER_03",
        "ScheduledProcessingParameters": "Body Protocol",
    },
]


def handle_assoc_request(event):
    """Handle association request - check AE Title whitelist"""
    requestor_aet = event.assoc.requestor.ae_title
    log.info(f"Association request from AET: {requestor_aet}")

    if AET_WHITELIST:
        if requestor_aet not in AET_WHITELIST:
            log.warning(f"AET '{requestor_aet}' not in whitelist, rejecting")
            return 0x01, 0x03  # Rejected, calling AE title not recognized
        log.info(f"AET '{requestor_aet}' is whitelisted, accepting")

    return None  # Accept


def handle_echo(event):
    """Handle C-ECHO request"""
    requestor_aet = event.assoc.requestor.ae_title
    log.info(f"C-ECHO from {requestor_aet}")
    return 0x0000  # Success


def _match_wildcard(pattern: str, value: str) -> bool:
    """Simple wildcard matching for DICOM queries"""
    if not pattern or pattern == "*":
        return True
    pattern = pattern.upper()
    value = value.upper()

    if pattern.endswith("*") and pattern.startswith("*"):
        return pattern[1:-1] in value
    elif pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    elif pattern.startswith("*"):
        return value.endswith(pattern[1:])
    elif "*" in pattern:
        return pattern.replace("*", "") in value
    else:
        return pattern == value


def _match_date_range(date_filter: str, study_date: str) -> bool:
    """Match study date against filter (supports ranges like '20240101-20241231')"""
    if not date_filter:
        return True
    if "-" in date_filter:
        start, end = date_filter.split("-", 1)
        return start <= study_date <= end
    return study_date == date_filter


def handle_find(event):
    """Handle C-FIND request at PATIENT, STUDY, or SERIES level (or UPS)"""
    requestor_aet = event.assoc.requestor.ae_title
    ds = event.identifier

    # Check if this is a UPS query (based on SOP class)
    abstract_syntax = event.context.abstract_syntax
    if abstract_syntax == UnifiedProcedureStepQuery:
        yield from handle_ups_find_internal(event)
        return

    # Get query retrieve level
    query_level = str(getattr(ds, "QueryRetrieveLevel", "PATIENT")).upper()

    # Get common query parameters
    patient_name = str(getattr(ds, "PatientName", "*"))
    patient_id = str(getattr(ds, "PatientID", ""))

    log.info(
        f"C-FIND from {requestor_aet}: Level={query_level}, PatientName={patient_name}, PatientID={patient_id}"
    )

    if query_level == "PATIENT":
        # PATIENT level query - return patient data
        for patient in MOCK_PATIENTS:
            if not _match_wildcard(patient_name, patient["PatientName"]):
                continue
            if patient_id and patient_id != patient["PatientID"]:
                continue

            identifier = Dataset()
            identifier.PatientName = patient["PatientName"]
            identifier.PatientID = patient["PatientID"]
            identifier.PatientBirthDate = patient["PatientBirthDate"]
            identifier.PatientSex = patient["PatientSex"]
            identifier.NumberOfPatientRelatedStudies = patient["NumberOfPatientRelatedStudies"]

            yield 0xFF00, identifier  # Pending

    elif query_level == "STUDY":
        # STUDY level query - return study data with personnel/device metadata
        study_date = str(getattr(ds, "StudyDate", ""))
        modality = str(getattr(ds, "Modality", ""))
        study_uid = str(getattr(ds, "StudyInstanceUID", ""))

        log.info(f"  STUDY query: StudyDate={study_date}, Modality={modality}")

        for study in MOCK_STUDIES:
            # Filter by patient
            if not _match_wildcard(patient_name, study["PatientName"]):
                continue
            if patient_id and patient_id != study["PatientID"]:
                continue
            # Filter by study criteria
            if not _match_date_range(study_date, study["StudyDate"]):
                continue
            if modality and modality != study["Modality"]:
                continue
            if study_uid and study_uid != study["StudyInstanceUID"]:
                continue

            identifier = Dataset()
            # Patient fields
            identifier.PatientName = study["PatientName"]
            identifier.PatientID = study["PatientID"]
            identifier.PatientBirthDate = study["PatientBirthDate"]
            identifier.PatientSex = study["PatientSex"]
            # Study fields
            identifier.StudyInstanceUID = study["StudyInstanceUID"]
            identifier.StudyDate = study["StudyDate"]
            identifier.StudyTime = study["StudyTime"]
            identifier.StudyDescription = study["StudyDescription"]
            identifier.AccessionNumber = study["AccessionNumber"]
            identifier.Modality = study["Modality"]
            # Personnel fields (for --enum-operators)
            identifier.OperatorsName = study["OperatorsName"]
            identifier.PerformingPhysicianName = study["PerformingPhysicianName"]
            identifier.ReferringPhysicianName = study["ReferringPhysicianName"]
            identifier.NameOfPhysiciansReadingStudy = study["NameOfPhysiciansReadingStudy"]
            identifier.RequestingPhysician = study["RequestingPhysician"]
            # Device fields (for --enum-devices)
            identifier.StationName = study["StationName"]
            identifier.Manufacturer = study["Manufacturer"]
            identifier.ManufacturerModelName = study["ManufacturerModelName"]
            identifier.InstitutionName = study["InstitutionName"]
            identifier.InstitutionalDepartmentName = study["InstitutionalDepartmentName"]
            # Counts
            identifier.NumberOfStudyRelatedSeries = study["NumberOfStudyRelatedSeries"]
            identifier.NumberOfStudyRelatedInstances = study["NumberOfStudyRelatedInstances"]

            yield 0xFF00, identifier  # Pending

    elif query_level == "SERIES":
        # SERIES level query - return series data with device metadata
        study_uid = str(getattr(ds, "StudyInstanceUID", ""))
        series_uid = str(getattr(ds, "SeriesInstanceUID", ""))
        modality = str(getattr(ds, "Modality", ""))

        log.info(f"  SERIES query: StudyUID={study_uid}, Modality={modality}")

        for series in MOCK_SERIES:
            # Filter by study
            if study_uid and study_uid != series["StudyInstanceUID"]:
                continue
            if series_uid and series_uid != series["SeriesInstanceUID"]:
                continue
            if modality and modality != series["Modality"]:
                continue

            identifier = Dataset()
            identifier.StudyInstanceUID = series["StudyInstanceUID"]
            identifier.SeriesInstanceUID = series["SeriesInstanceUID"]
            identifier.SeriesNumber = series["SeriesNumber"]
            identifier.SeriesDescription = series["SeriesDescription"]
            identifier.Modality = series["Modality"]
            # Device fields (for --enum-devices)
            identifier.StationName = series["StationName"]
            identifier.Manufacturer = series["Manufacturer"]
            identifier.ManufacturerModelName = series["ManufacturerModelName"]
            identifier.NumberOfSeriesRelatedInstances = series["NumberOfSeriesRelatedInstances"]
            # Personnel fields
            identifier.OperatorsName = series["OperatorsName"]
            identifier.PerformingPhysicianName = series["PerformingPhysicianName"]

            yield 0xFF00, identifier  # Pending

    elif query_level == "IMAGE":
        # IMAGE level - not implemented in this mock
        log.warning("IMAGE level query not implemented")
        # Return empty result

    # Final response
    yield 0x0000, None  # Success


# Mock image data - UIDs for instances within series
MOCK_INSTANCES = []
for series in MOCK_SERIES:
    num_instances = int(series.get("NumberOfSeriesRelatedInstances", 1))
    # Create at most 3 instances per series for testing (to keep response quick)
    for i in range(min(num_instances, 3)):
        MOCK_INSTANCES.append(
            {
                "StudyInstanceUID": series["StudyInstanceUID"],
                "SeriesInstanceUID": series["SeriesInstanceUID"],
                "SOPInstanceUID": f"{series['SeriesInstanceUID']}.{i + 1}",
                "SOPClassUID": CTImageStorage
                if series["Modality"] == "CT"
                else (
                    MRImageStorage if series["Modality"] == "MR" else SecondaryCaptureImageStorage
                ),
                "InstanceNumber": str(i + 1),
                "Modality": series["Modality"],
            }
        )


def _create_mock_dicom_dataset(instance_data: dict, study_data: dict = None) -> Dataset:
    """Create a mock DICOM dataset with minimal pixel data"""
    # Create file meta - use Implicit VR Little Endian for maximum compatibility
    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = instance_data["SOPClassUID"]
    file_meta.MediaStorageSOPInstanceUID = instance_data["SOPInstanceUID"]
    file_meta.TransferSyntaxUID = ImplicitVRLittleEndian  # Use Implicit VR for compatibility
    file_meta.ImplementationClassUID = generate_uid()

    # Create dataset
    ds = FileDataset(None, {}, file_meta=file_meta, preamble=b"\x00" * 128)

    # SOP Common
    ds.SOPClassUID = instance_data["SOPClassUID"]
    ds.SOPInstanceUID = instance_data["SOPInstanceUID"]

    # Patient Module (find matching study for patient data)
    if study_data:
        ds.PatientName = study_data.get("PatientName", "TEST^PATIENT")
        ds.PatientID = study_data.get("PatientID", "PT000")
        ds.PatientBirthDate = study_data.get("PatientBirthDate", "19700101")
        ds.PatientSex = study_data.get("PatientSex", "O")
    else:
        ds.PatientName = "TEST^PATIENT"
        ds.PatientID = "PT000"
        ds.PatientBirthDate = "19700101"
        ds.PatientSex = "O"

    # Study Module
    ds.StudyInstanceUID = instance_data["StudyInstanceUID"]
    ds.StudyDate = study_data.get("StudyDate", "20240101") if study_data else "20240101"
    ds.StudyTime = study_data.get("StudyTime", "120000") if study_data else "120000"
    ds.StudyDescription = (
        study_data.get("StudyDescription", "MOCK STUDY") if study_data else "MOCK STUDY"
    )

    # Series Module
    ds.SeriesInstanceUID = instance_data["SeriesInstanceUID"]
    ds.SeriesNumber = 1
    ds.Modality = instance_data["Modality"]

    # Instance
    ds.InstanceNumber = int(instance_data["InstanceNumber"])

    # Image Pixel Module - create small 64x64 test image
    ds.Rows = 64
    ds.Columns = 64
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0

    # Generate simple gradient pixel data
    arr = np.zeros((64, 64), dtype=np.uint16)
    for y in range(64):
        for x in range(64):
            arr[y, x] = ((x + y) * 32) % 4096  # Simple gradient pattern
    ds.PixelData = arr.tobytes()

    return ds


def _find_study_by_uid(study_uid: str) -> dict:
    """Find study data by Study Instance UID"""
    for study in MOCK_STUDIES:
        if study["StudyInstanceUID"] == study_uid:
            return study
    return None


def _get_instances_for_query(study_uid: str = None, series_uid: str = None) -> list:
    """Get instances matching the query criteria"""
    results = []
    for instance in MOCK_INSTANCES:
        if study_uid and instance["StudyInstanceUID"] != study_uid:
            continue
        if series_uid and instance["SeriesInstanceUID"] != series_uid:
            continue
        results.append(instance)
    return results


def handle_get(event):
    """Handle C-GET request - return matching instances"""
    requestor_aet = event.assoc.requestor.ae_title
    ds = event.identifier

    query_level = str(getattr(ds, "QueryRetrieveLevel", "STUDY")).upper()
    study_uid = str(getattr(ds, "StudyInstanceUID", ""))
    series_uid = str(getattr(ds, "SeriesInstanceUID", ""))

    log.info(
        f"C-GET from {requestor_aet}: Level={query_level}, StudyUID={study_uid}, SeriesUID={series_uid}"
    )

    # Find matching instances
    instances = _get_instances_for_query(study_uid or None, series_uid or None)

    if not instances:
        log.warning("C-GET: No instances found for query")
        yield 0xC000, None  # Failed - Unable to process
        return

    log.info(f"C-GET: Found {len(instances)} instances to retrieve")

    # Yield number of sub-operations
    yield len(instances)

    # Yield each instance
    for instance in instances:
        study_data = _find_study_by_uid(instance["StudyInstanceUID"])
        mock_ds = _create_mock_dicom_dataset(instance, study_data)
        yield 0xFF00, mock_ds  # Pending

    # Success
    yield 0x0000, None


def handle_move(event):
    """Handle C-MOVE request - simulate transfer to destination AET

    pynetdicom C-MOVE handler must yield in this order:
    1. (address, port) tuple - destination for C-STORE sub-operations
    2. int - number of sub-operations
    3. (status, dataset) pairs for each sub-operation

    For testing, the mock accepts "MOCK_DEST", "MOCK_PACS", or the server's
    own AET as known destinations (loopback to itself).
    """
    requestor_aet = event.assoc.requestor.ae_title
    ds = event.identifier
    dest_aet = event.move_destination

    query_level = str(getattr(ds, "QueryRetrieveLevel", "STUDY")).upper()
    study_uid = str(getattr(ds, "StudyInstanceUID", ""))
    series_uid = str(getattr(ds, "SeriesInstanceUID", ""))

    log.info(
        f"C-MOVE from {requestor_aet} to {dest_aet}: Level={query_level}, StudyUID={study_uid}"
    )

    # Find matching instances
    instances = _get_instances_for_query(study_uid or None, series_uid or None)

    if not instances:
        log.warning("C-MOVE: No instances found for query")
        # Still need to yield destination and count
        yield ("127.0.0.1", SERVER_PORT)
        yield 0  # Zero sub-operations
        return

    log.info(f"C-MOVE: Found {len(instances)} instances to transfer to {dest_aet}")

    # For testing, accept "MOCK_DEST" or "MOCK_PACS" as known destinations
    known_destinations = ["MOCK_DEST", "MOCK_PACS", SERVER_AET]

    if dest_aet not in known_destinations:
        log.warning(f"C-MOVE: Unknown destination AET '{dest_aet}'")
        # Return destination and 0 sub-ops to indicate failure
        yield ("127.0.0.1", SERVER_PORT)
        yield 0  # Zero sub-operations (destination unknown)
        return

    # For known destinations, yield our own address (loopback)
    log.info(f"C-MOVE: Transferring {len(instances)} instances to {dest_aet} (loopback)")

    # 1. Yield destination (address, port)
    yield ("127.0.0.1", SERVER_PORT)

    # 2. Yield number of sub-operations
    yield len(instances)

    # 3. Yield (status, dataset) tuples for each sub-operation
    for instance in instances:
        # Check if cancelled
        if event.is_cancelled:
            yield (0xFE00, None)  # Cancel
            return

        study_data = _find_study_by_uid(instance["StudyInstanceUID"])
        mock_ds = _create_mock_dicom_dataset(instance, study_data)
        yield (0xFF00, mock_ds)  # Pending status with dataset

    log.info(f"C-MOVE: Completed transfer of {len(instances)} instances")


# Track received C-STORE files
RECEIVED_CSTORE_FILES = []


def handle_store(event):
    """Handle C-STORE request - accept incoming DICOM images"""
    requestor_aet = event.assoc.requestor.ae_title
    ds = event.dataset

    sop_instance_uid = str(getattr(ds, "SOPInstanceUID", "unknown"))
    sop_class_uid = str(getattr(ds, "SOPClassUID", "unknown"))
    patient_name = str(getattr(ds, "PatientName", "unknown"))

    log.info(
        f"C-STORE from {requestor_aet}: SOPInstanceUID={sop_instance_uid[:40]}..., Patient={patient_name}"
    )

    # Store metadata about received file
    RECEIVED_CSTORE_FILES.append(
        {
            "SOPInstanceUID": sop_instance_uid,
            "SOPClassUID": sop_class_uid,
            "PatientName": patient_name,
            "ReceivedFrom": requestor_aet,
            "ReceivedAt": datetime.now().isoformat(),
        }
    )

    log.info(f"C-STORE: Accepted image (total received: {len(RECEIVED_CSTORE_FILES)})")

    return 0x0000  # Success


def handle_n_action(event):
    """Handle N-ACTION request for Storage Commitment

    Storage Commitment Push Model uses N-ACTION to request commitment.
    We respond with an N-EVENT-REPORT later (simulated with direct response here).
    """
    requestor_aet = event.assoc.requestor.ae_title
    action_type = event.action_type  # 1 = Storage Commitment Request
    ds = event.action_information

    log.info(f"N-ACTION from {requestor_aet}: ActionTypeID={action_type}")

    if action_type == 1:  # Storage Commitment Request
        # Get the transaction UID and referenced SOP instances
        transaction_uid = str(getattr(ds, "TransactionUID", generate_uid()))

        # Build response - accept all instances
        response = Dataset()
        response.TransactionUID = transaction_uid

        # Copy the Referenced SOP Sequence (pretend we committed all)
        if hasattr(ds, "ReferencedSOPSequence"):
            response.ReferencedSOPSequence = ds.ReferencedSOPSequence
            log.info(f"  Storage Commitment: Accepting {len(ds.ReferencedSOPSequence)} instances")

        # Return success
        return 0x0000, response
    else:
        log.warning(f"  Unknown N-ACTION type: {action_type}")
        return 0x0110, None  # Processing failure


def handle_ups_find_internal(event):
    """Handle C-FIND for UPS (Unified Procedure Step) queries - called from handle_find"""
    requestor_aet = event.assoc.requestor.ae_title
    ds = event.identifier

    # Get query filters
    state_filter = str(getattr(ds, "ProcedureStepState", ""))
    worklist_filter = str(getattr(ds, "WorklistLabel", ""))
    patient_name = str(getattr(ds, "PatientName", "*"))

    log.info(f"UPS C-FIND from {requestor_aet}: State={state_filter}, Worklist={worklist_filter}")

    for ups in MOCK_UPS:
        # Apply filters
        if state_filter and ups["ProcedureStepState"] != state_filter:
            continue
        if worklist_filter and ups["WorklistLabel"] != worklist_filter:
            continue
        if patient_name and patient_name != "*":
            if not _match_wildcard(patient_name, ups["PatientName"]):
                continue

        # Build response dataset
        identifier = Dataset()
        identifier.SOPInstanceUID = ups["SOPInstanceUID"]
        identifier.ProcedureStepState = ups["ProcedureStepState"]
        identifier.ProcedureStepLabel = ups["ProcedureStepLabel"]
        identifier.WorklistLabel = ups["WorklistLabel"]
        identifier.PatientName = ups["PatientName"]
        identifier.PatientID = ups["PatientID"]
        identifier.PatientBirthDate = ups["PatientBirthDate"]
        identifier.ScheduledProcedureStepStartDateTime = ups["ScheduledProcedureStepStartDateTime"]
        identifier.ScheduledStationName = ups["ScheduledStationName"]
        identifier.ScheduledProcessingParametersSequence = []  # Empty for mock

        yield 0xFF00, identifier  # Pending

    yield 0x0000, None  # Success


def main():
    """Start the mock DICOM SCP server"""
    log.info(f"Starting Mock DICOM SCP on port {SERVER_PORT}")
    log.info(f"Server AE Title: {SERVER_AET}")

    if AET_WHITELIST:
        log.info(f"AET Whitelist: {AET_WHITELIST}")
    else:
        log.info("AET Whitelist: DISABLED (accepting all)")

    # Create Application Entity
    ae = AE(ae_title=SERVER_AET)

    # Add supported presentation contexts
    # C-ECHO
    ae.add_supported_context(Verification)

    # C-FIND
    ae.add_supported_context(PatientRootQueryRetrieveInformationModelFind)
    ae.add_supported_context(StudyRootQueryRetrieveInformationModelFind)

    # C-GET
    ae.add_supported_context(PatientRootQueryRetrieveInformationModelGet)
    ae.add_supported_context(StudyRootQueryRetrieveInformationModelGet)

    # C-MOVE
    ae.add_supported_context(PatientRootQueryRetrieveInformationModelMove)
    ae.add_supported_context(StudyRootQueryRetrieveInformationModelMove)

    # C-STORE (for receiving images and for C-GET to send back)
    # Add common storage SOP classes with both SCU and SCP roles
    # SCU role is needed to send C-STORE during C-GET operations
    # SCP role is needed to receive C-STORE from clients
    ae.add_supported_context(CTImageStorage, scu_role=True, scp_role=True)
    ae.add_supported_context(MRImageStorage, scu_role=True, scp_role=True)
    ae.add_supported_context(SecondaryCaptureImageStorage, scu_role=True, scp_role=True)

    # Also add all storage contexts for broader compatibility with role selection
    for context in StoragePresentationContexts:
        ae.add_supported_context(context.abstract_syntax, scu_role=True, scp_role=True)

    # Add REQUESTED contexts for C-MOVE sub-operations (SCU to send C-STORE to destination)
    # This allows the server to initiate associations to send images during C-MOVE
    ae.add_requested_context(CTImageStorage)
    ae.add_requested_context(MRImageStorage)
    ae.add_requested_context(SecondaryCaptureImageStorage)
    for context in StoragePresentationContexts:
        ae.add_requested_context(context.abstract_syntax)

    # Storage Commitment Push Model (for --storage-commitment testing)
    ae.add_supported_context(StorageCommitmentPushModel)

    # UPS SOP Classes (for --ups-query testing)
    ae.add_supported_context(UnifiedProcedureStepPush)
    ae.add_supported_context(UnifiedProcedureStepPull)
    ae.add_supported_context(UnifiedProcedureStepWatch)
    ae.add_supported_context(UnifiedProcedureStepQuery)

    # Event handlers
    handlers = [
        (evt.EVT_C_ECHO, handle_echo),
        (evt.EVT_C_FIND, handle_find),
        (evt.EVT_C_GET, handle_get),
        (evt.EVT_C_MOVE, handle_move),
        (evt.EVT_C_STORE, handle_store),
        (evt.EVT_N_ACTION, handle_n_action),
        (evt.EVT_REQUESTED, handle_assoc_request),
    ]

    # Log database contents
    log.info("Mock database contents:")
    log.info(f"  - Patients: {len(MOCK_PATIENTS)}")
    log.info(f"  - Studies: {len(MOCK_STUDIES)} (spanning 2015-2024 for --time-analysis)")
    log.info(f"  - Series: {len(MOCK_SERIES)}")
    log.info(f"  - Instances: {len(MOCK_INSTANCES)} (for C-GET/C-MOVE)")

    # Log unique values for enumeration testing
    operators = set(s["OperatorsName"] for s in MOCK_STUDIES)
    stations = set(s["StationName"] for s in MOCK_STUDIES)
    manufacturers = set(s["Manufacturer"] for s in MOCK_STUDIES)
    modalities = set(s["Modality"] for s in MOCK_STUDIES)
    log.info(f"  - Unique operators: {len(operators)} (for --enum-operators)")
    log.info(f"  - Unique stations: {len(stations)} (for --enum-devices)")
    log.info(f"  - Unique manufacturers: {len(manufacturers)}")
    log.info(f"  - Modalities: {sorted(modalities)}")

    log.info(f"  - UPS Items: {len(MOCK_UPS)} (for --ups-query)")
    log.info(
        "Supported operations: C-ECHO, C-FIND, C-GET, C-MOVE, C-STORE, N-ACTION (Storage Commitment), UPS Query"
    )

    ae.start_server(("0.0.0.0", SERVER_PORT), evt_handlers=handlers, block=True)


if __name__ == "__main__":
    main()
