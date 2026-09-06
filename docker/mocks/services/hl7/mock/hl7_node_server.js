#!/usr/bin/env node
/**
 * Node.js HL7 v2 MLLP Mock Server
 *
 * A comprehensive HL7 MLLP server providing a non-Python stack for testing
 * the OIDA HL7 scanner. Uses raw TCP/TLS with proper MLLP framing to support
 * rich mock responses with realistic clinical data.
 *
 * Features:
 *   - Full MLLP framing (0x0B start, 0x1C 0x0D end)
 *   - TLS/MLLPS support via environment variables
 *   - Self-signed cert generation when TLS enabled without certs
 *   - All major HL7v2 message types with realistic responses
 *   - Configurable response modes: normal, error, reject, random
 *   - Rich mock data (patients, providers, locations, applications)
 *   - Health check via TCP connection test
 *   - Graceful shutdown on SIGTERM/SIGINT
 *
 * Environment Variables:
 *   PORT              - Listen port (default: 2576)
 *   TLS_ENABLED       - Enable TLS/MLLPS (default: false)
 *   TLS_CERT          - Path to TLS certificate
 *   TLS_KEY           - Path to TLS private key
 *   TLS_CA            - Path to CA certificate
 *   RESPONSE_MODE     - normal|error|reject|random (default: normal)
 *   SERVER_APP        - Sending application name (default: NODE_HIS)
 *   SERVER_FACILITY   - Sending facility name (default: GENERAL_HOSPITAL)
 *   HL7_VERSION       - HL7 version to report (default: 2.5.1)
 */

"use strict";

const net = require("net");
const tls = require("tls");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

// ---------------------------------------------------------------------------
// MLLP Framing Constants
// ---------------------------------------------------------------------------
const MLLP_START = Buffer.from([0x0b]); // VT (vertical tab)
const MLLP_END = Buffer.from([0x1c, 0x0d]); // FS + CR

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const PORT = parseInt(process.env.PORT || "2576", 10);
const TLS_ENABLED = (process.env.TLS_ENABLED || "").toLowerCase() === "true";
const TLS_CERT = process.env.TLS_CERT || "";
const TLS_KEY = process.env.TLS_KEY || "";
const TLS_CA = process.env.TLS_CA || "";
const RESPONSE_MODE = process.env.RESPONSE_MODE || "normal";
const SERVER_APP = process.env.SERVER_APP || "NODE_HIS";
const SERVER_FACILITY = process.env.SERVER_FACILITY || "GENERAL_HOSPITAL";
const HL7_VERSION = process.env.HL7_VERSION || "2.5.1";

// ---------------------------------------------------------------------------
// Mock Data: Patients
// ---------------------------------------------------------------------------
const MOCK_PATIENTS = [
  {
    id: "PT10001",
    name: "REYNOLDS^MARGARET^ANN",
    dob: "19720314",
    sex: "F",
    ssn: "321-54-9876",
    address: "1400 CEDAR BLVD^^PORTLAND^OR^97201^USA",
    phone: "(503)555-0142",
    mrn: "MRN-10001",
    account: "ACCT-50001",
    race: "2106-3^White^CDCREC",
    language: "en^English^ISO639",
  },
  {
    id: "PT10002",
    name: "CHEN^WILLIAM^WEI",
    dob: "19850607",
    sex: "M",
    ssn: "432-65-0987",
    address: "2750 LAKEVIEW DR^^SEATTLE^WA^98101^USA",
    phone: "(206)555-0233",
    mrn: "MRN-10002",
    account: "ACCT-50002",
    race: "2028-9^Asian^CDCREC",
    language: "en^English^ISO639",
  },
  {
    id: "PT10003",
    name: "OKAFOR^AMARA^NGOZI",
    dob: "19681121",
    sex: "F",
    ssn: "543-76-1098",
    address: "890 WILLOW CT^^CHICAGO^IL^60601^USA",
    phone: "(312)555-0377",
    mrn: "MRN-10003",
    account: "ACCT-50003",
    race: "2054-5^Black or African American^CDCREC",
    language: "en^English^ISO639",
  },
  {
    id: "PT10004",
    name: "GARCIA^CARLOS^MIGUEL",
    dob: "19910425",
    sex: "M",
    ssn: "654-87-2109",
    address: "3100 SUNSET AVE^^MIAMI^FL^33101^USA",
    phone: "(305)555-0418",
    mrn: "MRN-10004",
    account: "ACCT-50004",
    race: "2131-1^Other Race^CDCREC",
    language: "es^Spanish^ISO639",
  },
  {
    id: "PT10005",
    name: "THOMPSON^SARAH^ELIZABETH",
    dob: "19580902",
    sex: "F",
    ssn: "765-98-3210",
    address: "4567 BIRCH LN^^DENVER^CO^80201^USA",
    phone: "(720)555-0529",
    mrn: "MRN-10005",
    account: "ACCT-50005",
    race: "2106-3^White^CDCREC",
    language: "en^English^ISO639",
  },
  {
    id: "PT10006",
    name: "NAKAMURA^KENJI^",
    dob: "19790818",
    sex: "M",
    ssn: "876-09-4321",
    address: "7823 PINE RIDGE RD^^SAN FRANCISCO^CA^94102^USA",
    phone: "(415)555-0644",
    mrn: "MRN-10006",
    account: "ACCT-50006",
    race: "2028-9^Asian^CDCREC",
    language: "ja^Japanese^ISO639",
  },
];

// ---------------------------------------------------------------------------
// Mock Data: Providers (with realistic NPIs)
// ---------------------------------------------------------------------------
const MOCK_PROVIDERS = [
  { id: "1003456789", name: "HARTWELL^JAMES^RICHARD^MD", role: "ATTENDING", dept: "INTERNAL MED" },
  { id: "1014567890", name: "KUMAR^PRIYA^ANAND^MD", role: "REFERRING", dept: "CARDIOLOGY" },
  { id: "1025678901", name: "LARSSON^ERIK^JOHANNES^MD", role: "CONSULTING", dept: "NEUROLOGY" },
  { id: "1036789012", name: "WASHINGTON^DENISE^MARIE^MD", role: "ADMITTING", dept: "EMERGENCY" },
  { id: "1047890123", name: "PATEL^RAVI^SURESH^MD", role: "ORDERING", dept: "PATHOLOGY" },
  { id: "1058901234", name: "FITZGERALD^COLLEEN^ANN^DO", role: "PRIMARY", dept: "FAMILY MED" },
  { id: "1069012345", name: "ALVAREZ^DIEGO^FERNANDO^MD", role: "SURGEON", dept: "GENERAL SURG" },
  { id: "1070123456", name: "BROOKS^TANYA^RENEE^PHARM.D", role: "PHARMACIST", dept: "PHARMACY" },
];

// ---------------------------------------------------------------------------
// Mock Data: Locations
// ---------------------------------------------------------------------------
const MOCK_LOCATIONS = [
  "ICU^201^A^GENERAL_HOSPITAL^^^^^N",
  "ICU^202^B^GENERAL_HOSPITAL^^^^^N",
  "ICU^NICU-1^A^GENERAL_HOSPITAL^^^^^N",
  "ER^T-01^1^GENERAL_HOSPITAL^^^^^N",
  "ER^T-02^2^GENERAL_HOSPITAL^^^^^N",
  "ER^RESUS-1^^GENERAL_HOSPITAL^^^^^N",
  "OR^SURG-1^^SURGICAL_PAVILION^^^^^N",
  "OR^SURG-2^^SURGICAL_PAVILION^^^^^N",
  "OR^CARDIAC-1^^SURGICAL_PAVILION^^^^^N",
  "PACU^REC-1^A^SURGICAL_PAVILION^^^^^N",
  "PEDS^301^A^CHILDRENS_TOWER^^^^^N",
  "PEDS^302^B^CHILDRENS_TOWER^^^^^N",
  "MED-SURG^401^A^GENERAL_HOSPITAL^^^^^N",
  "MED-SURG^402^B^GENERAL_HOSPITAL^^^^^N",
  "MED-SURG^403^C^GENERAL_HOSPITAL^^^^^N",
  "ONCOLOGY^501^A^CANCER_CENTER^^^^^N",
  "ONCOLOGY^502^B^CANCER_CENTER^^^^^N",
  "CARDIAC^CCU-1^A^HEART_INSTITUTE^^^^^N",
  "CARDIAC^CCU-2^B^HEART_INSTITUTE^^^^^N",
  "NEURO^601^A^GENERAL_HOSPITAL^^^^^N",
  "L&D^701^A^WOMENS_CENTER^^^^^N",
  "PSYCH^801^A^BEHAVIORAL_HEALTH^^^^^N",
  "REHAB^901^A^REHAB_CENTER^^^^^N",
  "RAD^CTSCAN-1^^IMAGING_CENTER^^^^^N",
];

// ---------------------------------------------------------------------------
// Mock Data: Applications (for --enum-apps testing)
// ---------------------------------------------------------------------------
const MOCK_APPLICATIONS = [
  ["EPIC", "MAIN_CAMPUS"],
  ["EPIC", "NORTH_CAMPUS"],
  ["CERNER", "AMBULATORY_CLINICS"],
  ["MEDITECH", "SATELLITE_LAB"],
  ["MIRTH", "INTEGRATION_ENGINE"],
  ["RHAPSODY", "HIE_NODE"],
  ["ALLSCRIPTS", "PHYSICIAN_OFFICE"],
  ["NEXTGEN", "URGENT_CARE_EAST"],
  ["ATHENA", "TELEHEALTH_PORTAL"],
  ["SUNQUEST", "REFERENCE_LAB"],
];

// ---------------------------------------------------------------------------
// Mock Data: Observations / Lab Results
// ---------------------------------------------------------------------------
const MOCK_OBSERVATIONS = [
  { id: "718-7", name: "Hemoglobin", value: "14.1", units: "g/dL", range: "12.0-16.0", flag: "N" },
  { id: "789-8", name: "Erythrocytes", value: "4.72", units: "10*6/uL", range: "4.0-5.5", flag: "N" },
  { id: "6690-2", name: "Leukocytes", value: "11.8", units: "10*3/uL", range: "4.5-11.0", flag: "H" },
  { id: "777-3", name: "Platelets", value: "245", units: "10*3/uL", range: "150-400", flag: "N" },
  { id: "2345-7", name: "Glucose", value: "142", units: "mg/dL", range: "70-100", flag: "H" },
  { id: "2160-0", name: "Creatinine", value: "1.1", units: "mg/dL", range: "0.6-1.2", flag: "N" },
  { id: "3094-0", name: "BUN", value: "18", units: "mg/dL", range: "7-20", flag: "N" },
  { id: "2951-2", name: "Sodium", value: "138", units: "mmol/L", range: "136-145", flag: "N" },
  { id: "2823-3", name: "Potassium", value: "4.2", units: "mmol/L", range: "3.5-5.0", flag: "N" },
  { id: "17861-6", name: "Calcium", value: "9.4", units: "mg/dL", range: "8.5-10.5", flag: "N" },
];

// ---------------------------------------------------------------------------
// Mock Data: Medications
// ---------------------------------------------------------------------------
const MOCK_MEDICATIONS = [
  { code: "00069-1540-30", name: "Lisinopril 10mg Tablet", dose: "10", units: "mg", route: "PO" },
  { code: "00378-1800-01", name: "Metformin 500mg Tablet", dose: "500", units: "mg", route: "PO" },
  { code: "00173-0682-20", name: "Albuterol Inhaler 90mcg", dose: "2", units: "puffs", route: "INH" },
  { code: "00093-0058-01", name: "Amoxicillin 500mg Cap", dose: "500", units: "mg", route: "PO" },
  { code: "00074-3799-01", name: "Morphine Sulfate 4mg/mL", dose: "4", units: "mg", route: "IV" },
];

// ---------------------------------------------------------------------------
// Mock Data: Devices (for PCD/IHE Device Integration)
// ---------------------------------------------------------------------------
const MOCK_DEVICES = [
  { id: "DEV-PUMP-001", type: "69981^MDC_DEV_PUMP_INFUS_VMD^MDC", model: "Alaris 8015", mfg: "BD" },
  { id: "DEV-MON-001", type: "69965^MDC_DEV_MON_PHYSIO_MULTI_PARAM_MDS^MDC", model: "IntelliVue MX800", mfg: "Philips" },
  { id: "DEV-VENT-001", type: "70667^MDC_DEV_VENT_MDS^MDC", model: "Puritan Bennett 980", mfg: "Medtronic" },
  { id: "DEV-OX-001", type: "69801^MDC_DEV_ANALY_SAT_O2_MDS^MDC", model: "Nellcor N-600", mfg: "Medtronic" },
];

// ---------------------------------------------------------------------------
// Utility: Random selection
// ---------------------------------------------------------------------------
function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function timestamp() {
  const d = new Date();
  return (
    d.getFullYear().toString() +
    String(d.getMonth() + 1).padStart(2, "0") +
    String(d.getDate()).padStart(2, "0") +
    String(d.getHours()).padStart(2, "0") +
    String(d.getMinutes()).padStart(2, "0") +
    String(d.getSeconds()).padStart(2, "0")
  );
}

let msgCounter = 0;
function nextMsgId() {
  return `NMSG${++msgCounter}${Date.now()}`;
}

// ---------------------------------------------------------------------------
// MSH Parser
// ---------------------------------------------------------------------------
function parseMSH(message) {
  const info = {};
  const lines = message.split("\r");
  for (const line of lines) {
    if (line.startsWith("MSH")) {
      const sep = line.length > 3 ? line[3] : "|";
      const fields = line.split(sep);
      // MSH field numbering: MSH|^~\&| = fields[0]="MSH", [1]="^~\&" (encoding chars)
      // fields[2] = MSH-3 sending app, fields[3] = MSH-4 sending facility, etc.
      info.sendingApp = fields[2] || "";
      info.sendingFacility = fields[3] || "";
      info.receivingApp = fields[4] || "";
      info.receivingFacility = fields[5] || "";
      info.dateTime = fields[6] || "";
      info.security = fields[7] || "";
      info.messageType = fields[8] || "";
      info.messageControlId = fields[9] || "";
      info.processingId = fields[10] || "";
      info.version = fields[11] || "";
      break;
    }
  }
  return info;
}

// ---------------------------------------------------------------------------
// Segment Builders
// ---------------------------------------------------------------------------
function buildMSH(msh, responseType) {
  const [app, facility] = pick(MOCK_APPLICATIONS);
  const ts = timestamp();
  const version = msh.version || HL7_VERSION;
  return (
    `MSH|^~\\&|${app}|${facility}|` +
    `${msh.sendingApp || "UNKNOWN"}|${msh.sendingFacility || "UNKNOWN"}|` +
    `${ts}||${responseType}|${nextMsgId()}|P|${version}`
  );
}

function buildMSA(ackCode, controlId, text) {
  return `MSA|${ackCode}|${controlId}|${text || ""}`;
}

function buildPID(patient) {
  if (!patient) patient = pick(MOCK_PATIENTS);
  return (
    `PID|1||${patient.id}^^^HOSP^MR~${patient.ssn}^^^USSSA^SS||` +
    `${patient.name}||${patient.dob}|${patient.sex}||${patient.race || ""}|` +
    `${patient.address}||${patient.phone}||${patient.language || ""}||` +
    `${patient.account}|||||||||||||||`
  );
}

function buildPV1(location) {
  if (!location) location = pick(MOCK_LOCATIONS);
  const attending = MOCK_PROVIDERS.find((p) => p.role === "ATTENDING") || MOCK_PROVIDERS[0];
  const referring = MOCK_PROVIDERS.find((p) => p.role === "REFERRING") || MOCK_PROVIDERS[1];
  const consulting = MOCK_PROVIDERS.find((p) => p.role === "CONSULTING") || MOCK_PROVIDERS[2];
  const admitting = MOCK_PROVIDERS.find((p) => p.role === "ADMITTING") || MOCK_PROVIDERS[3];
  const ts = timestamp();
  return (
    `PV1|1|I|${location}||||` +
    `${attending.name}^${attending.id}^^^^^NPI|` +
    `${referring.name}^${referring.id}^^^^^NPI|` +
    `${consulting.name}^${consulting.id}^^^^^NPI|` +
    `||||||||` +
    `${admitting.name}^${admitting.id}^^^^^NPI|` +
    `||||||||||||||||||||||||||${ts}|`
  );
}

function buildEVN(eventCode) {
  return `EVN|${eventCode}|${timestamp()}|||REGISTRATION^SYSTEM`;
}

function buildORC(orderId) {
  if (!orderId) orderId = `ORD${timestamp()}`;
  const ordering = MOCK_PROVIDERS.find((p) => p.role === "ORDERING") || MOCK_PROVIDERS[4];
  const ts = timestamp();
  return (
    `ORC|OK|${orderId}||GRP001|||^^^${ts}^^R||${ts}|` +
    `${ordering.name}^${ordering.id}^^^^^NPI|` +
    `|||||||||`
  );
}

function buildOBR(orderId) {
  if (!orderId) orderId = `ORD${timestamp()}`;
  const ordering = MOCK_PROVIDERS.find((p) => p.role === "ORDERING") || MOCK_PROVIDERS[4];
  const ts = timestamp();
  return (
    `OBR|1|${orderId}||85025^CBC with Differential^L|||${ts}||||||||` +
    `BLOOD^VENOUS|` +
    `${ordering.name}^${ordering.id}^^^^^NPI|` +
    `|(503)555-9999|||||||||||||||||||||||`
  );
}

function buildOBXSet() {
  // Return a realistic set of OBX observations
  const lines = [];
  const count = Math.min(6, MOCK_OBSERVATIONS.length);
  for (let i = 0; i < count; i++) {
    const obs = MOCK_OBSERVATIONS[i];
    lines.push(
      `OBX|${i + 1}|NM|${obs.id}^${obs.name}^LN||${obs.value}|${obs.units}|${obs.range}|${obs.flag}|||F`
    );
  }
  return lines;
}

function buildDG1() {
  return "DG1|1|I10|J18.9^Pneumonia, unspecified organism^I10|||A|||||||||1";
}

function buildSCH(appointmentId) {
  if (!appointmentId) appointmentId = `APT${timestamp()}`;
  const provider = MOCK_PROVIDERS.find((p) => p.role === "ATTENDING") || MOCK_PROVIDERS[0];
  const ts = timestamp();
  return (
    `SCH|${appointmentId}||||||ROUTINE^Routine Visit^HL70276|OFFICE^Office Visit^HL70277|30|MIN^Minutes^ISO+|||` +
    `${provider.name}^${provider.id}^^^^^NPI||||` +
    `${ts}|${ts}|${provider.name}^${provider.id}^^^^^NPI|` +
    `${pick(MOCK_LOCATIONS)}|||||Booked`
  );
}

function buildTXA(docId) {
  if (!docId) docId = `DOC${timestamp()}`;
  const provider = MOCK_PROVIDERS.find((p) => p.role === "ATTENDING") || MOCK_PROVIDERS[0];
  const ts = timestamp();
  return (
    `TXA|1|HP^History & Physical^HL70270|TX||${ts}|` +
    `${provider.name}^${provider.id}^^^^^NPI|` +
    `|||||${docId}|||||AU|||||`
  );
}

function buildRXE(med) {
  if (!med) med = pick(MOCK_MEDICATIONS);
  return (
    `RXE|1|${med.code}^${med.name}^NDC|${med.dose}||${med.units}|TAB||||30|TAB||||RX${timestamp()}|5`
  );
}

function buildRXA(med) {
  if (!med) med = pick(MOCK_MEDICATIONS);
  const ts = timestamp();
  return (
    `RXA|0|1|${ts}||${med.code}^${med.name}^NDC|${med.dose}|${med.units}||${med.route}|||||LOT${Date.now()}|20271231|PHARMA_MFG||CP`
  );
}

function buildRXD(med) {
  if (!med) med = pick(MOCK_MEDICATIONS);
  const ts = timestamp();
  const pharmacist = MOCK_PROVIDERS.find((p) => p.role === "PHARMACIST");
  const pharmacistName = pharmacist ? pharmacist.name : "PHARMACIST^DEFAULT";
  return (
    `RXD|1|${med.code}^${med.name}^NDC|${ts}|30|TAB||RX${timestamp()}||DISPENSED|` +
    `${pharmacistName}|||||LOT${Date.now()}|20271231`
  );
}

function buildRXG(med) {
  if (!med) med = pick(MOCK_MEDICATIONS);
  return (
    `RXG|1|1||${med.code}^${med.name}^NDC|${med.dose}||${med.units}|TAB|||||||50|mL/hr|${med.dose}|${med.units}`
  );
}

function buildMFI(masterFileId) {
  const desc = masterFileId === "CDM" ? "Charge Description Master" : "Practitioner Master";
  return `MFI|${masterFileId || "PRA"}^${desc}^HL70175||REP|${timestamp()}|${timestamp()}|NE`;
}

function buildMFE(recordAction, primaryKey) {
  return `MFE|${recordAction || "MAD"}||${timestamp()}|${primaryKey || "STF001"}|CE`;
}

function buildSTF(provider) {
  if (!provider) provider = pick(MOCK_PROVIDERS);
  return (
    `STF|${provider.id}||${provider.name}|${provider.role}||||${provider.dept}||` +
    `(503)555-0100||admin@hospital.local|||A`
  );
}

function buildFT1(txnId) {
  if (!txnId) txnId = `TXN${timestamp()}`;
  const ts = timestamp();
  return (
    `FT1|1|${txnId}||${ts}|${ts}|CG|99213^Office Visit Level 3^CPT||1|150.00||||` +
    `BCBS-PPO^Blue Cross PPO^HL70072`
  );
}

function buildGT1(patient) {
  if (!patient) patient = pick(MOCK_PATIENTS);
  return (
    `GT1|1|GT${patient.id}|${patient.name}||${patient.address}|${patient.phone}|||||||${patient.ssn}||||EMPLOYER_CO||SELF`
  );
}

function buildIN1(patient) {
  if (!patient) patient = pick(MOCK_PATIENTS);
  return (
    `IN1|1|BCBS^Blue Cross Blue Shield^HL70072|BCBS001|Blue Cross Blue Shield|` +
    `200 INSURANCE BLVD^^HARTFORD^CT^06101||||||||||${patient.name}||` +
    `${patient.address}||||POL${patient.id}`
  );
}

// PCD / Device Integration segments
function buildOBXDevice(device, setId) {
  if (!device) device = pick(MOCK_DEVICES);
  return `OBX|${setId || 1}|ST|${device.type}||${device.model}^${device.mfg}||||||F|||${timestamp()}`;
}

function buildOBXVital(code, name, value, units, setId) {
  return `OBX|${setId || 1}|NM|${code}^${name}^MDC||${value}|${units}||N|||F|||${timestamp()}`;
}

function buildQAK(queryTag, queryStatus) {
  return `QAK|${queryTag || "1"}|${queryStatus || "OK"}|Q22^Find Candidates^HL70471`;
}

function buildQPD(queryTag) {
  return `QPD|Q22^Find Candidates^HL70471|${queryTag || "Q001"}|@PID.5.1^*`;
}

function buildERR(severity, code, text) {
  return `ERR|0|MSH^1^1|${code || "0"}|${severity || "I"}|0|${text || "SUCCESS"}|||Contact IT at helpdesk@hospital.local`;
}

function buildNTE(setId, text) {
  return `NTE|${setId || 1}|L|${text}`;
}

// ---------------------------------------------------------------------------
// Response Generators
// ---------------------------------------------------------------------------

function generateACK(msh) {
  const msgType = msh.messageType || "";
  const trigger = msgType.includes("^") ? msgType.split("^")[1] : "A01";
  const ackType = `ACK^${trigger}`;

  let ackCode, ackText;
  switch (RESPONSE_MODE) {
    case "error":
      ackCode = "AE";
      ackText = "Application error processing message";
      break;
    case "reject":
      ackCode = "AR";
      ackText = "Message rejected by server policy";
      break;
    case "random":
      ackCode = pick(["AA", "AA", "AA", "AE", "AR"]);
      ackText = ackCode === "AA" ? "Message accepted" : ackCode === "AE" ? "Application error" : "Rejected";
      break;
    default:
      ackCode = "AA";
      ackText = "Message accepted";
  }

  const lines = [
    buildMSH(msh, ackType),
    buildMSA(ackCode, msh.messageControlId || "UNKNOWN", ackText),
    buildERR("I", "0", "SUCCESS"),
    buildNTE(1, `Server: ${SERVER_APP} v${HL7_VERSION} at ${SERVER_FACILITY}`),
    buildNTE(2, "Interface Engine: Node.js HL7 Mock Server 1.0.0"),
  ];
  return lines.join("\r") + "\r";
}

function generateADTResponse(msh, message) {
  const msgType = msh.messageType || "ADT^A01";
  const trigger = msgType.includes("^") ? msgType.split("^")[1] : "A01";
  const ackType = `ACK^${trigger}`;
  const patient = pick(MOCK_PATIENTS);

  const lines = [
    buildMSH(msh, ackType),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Message accepted"),
    buildEVN(trigger),
    buildPID(patient),
    buildPV1(),
    buildDG1(),
  ];

  // Add MRG segment for A40 (merge) messages
  if (trigger === "A40") {
    const others = MOCK_PATIENTS.filter((p) => p.id !== patient.id);
    const mergePatient = others.length > 0 ? pick(others) : null;
    if (mergePatient) {
      lines.push(`MRG|${mergePatient.id}^^^HOSP^MR|||${mergePatient.name}`);
    }
  }

  return lines.join("\r") + "\r";
}

function generateORMResponse(msh) {
  const patient = pick(MOCK_PATIENTS);
  const orderId = `ORD${timestamp()}`;

  const lines = [
    buildMSH(msh, "ORR^O02"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Order accepted"),
    buildPID(patient),
    buildPV1(),
    buildORC(orderId),
    buildOBR(orderId),
  ];
  return lines.join("\r") + "\r";
}

function generateORUResponse(msh, message) {
  const patient = pick(MOCK_PATIENTS);

  // Check if this is a PCD ORU (device data)
  const isPCD = message.includes("PCD") || message.includes("MDC_DEV");

  const lines = [
    buildMSH(msh, "ACK^R01"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Results accepted"),
    buildPID(patient),
    buildPV1(),
    buildOBR(),
  ];

  if (isPCD) {
    // Add device observation data
    const device = pick(MOCK_DEVICES);
    lines.push(buildOBXDevice(device, 1));
    lines.push(buildOBXVital("147842", "MDC_ECG_HEART_RATE", "72", "264864^MDC_DIM_BEAT_PER_MIN^MDC", 2));
    lines.push(buildOBXVital("150456", "MDC_PULS_OXIM_SAT_O2", "97", "262688^MDC_DIM_PERCENT^MDC", 3));
    lines.push(buildOBXVital("150020", "MDC_PRESS_BLD_NONINV_SYS", "120", "266016^MDC_DIM_MMHG^MDC", 4));
    lines.push(buildOBXVital("150021", "MDC_PRESS_BLD_NONINV_DIA", "78", "266016^MDC_DIM_MMHG^MDC", 5));
  } else {
    lines.push(...buildOBXSet());
  }

  return lines.join("\r") + "\r";
}

function generateQueryResponse(msh) {
  const lines = [
    buildMSH(msh, "RSP^K11^RSP_K11"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Query successful"),
    buildQAK("1", "OK"),
    buildQPD("Q001"),
  ];

  // Return multiple patients with visit data
  const patientsToReturn = MOCK_PATIENTS.slice(0, 4);
  for (let i = 0; i < patientsToReturn.length; i++) {
    lines.push(buildPID(patientsToReturn[i]));
    lines.push(buildPV1(MOCK_LOCATIONS[i % MOCK_LOCATIONS.length]));
  }

  return lines.join("\r") + "\r";
}

function generateSIUResponse(msh) {
  const patient = pick(MOCK_PATIENTS);

  const lines = [
    buildMSH(msh, "ACK^S12"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Schedule confirmed"),
    buildSCH(),
    buildPID(patient),
    buildPV1(),
  ];
  return lines.join("\r") + "\r";
}

function generateMDMResponse(msh) {
  const patient = pick(MOCK_PATIENTS);

  const lines = [
    buildMSH(msh, "ACK^T02"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Document notification accepted"),
    buildPID(patient),
    buildPV1(),
    buildTXA(),
    `OBX|1|TX|HP^History and Physical^HL70270||Patient presents with chief complaint of chest pain. Vitals stable. ECG normal sinus rhythm.||||||F`,
  ];
  return lines.join("\r") + "\r";
}

function generateMFNResponse(msh) {
  const lines = [
    buildMSH(msh, "MFK^M01"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Master file update accepted"),
    buildMFI("PRA"),
  ];

  // Add staff entries
  for (let i = 0; i < 3; i++) {
    const provider = MOCK_PROVIDERS[i];
    lines.push(buildMFE("MAD", provider.id));
    lines.push(buildSTF(provider));
  }

  return lines.join("\r") + "\r";
}

function generateBARResponse(msh) {
  const patient = pick(MOCK_PATIENTS);

  const lines = [
    buildMSH(msh, "ACK^P01"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Billing account accepted"),
    buildPID(patient),
    buildPV1(),
    buildDG1(),
    buildGT1(patient),
    buildIN1(patient),
    buildFT1(),
  ];
  return lines.join("\r") + "\r";
}

function generateDFTResponse(msh) {
  const patient = pick(MOCK_PATIENTS);

  const lines = [
    buildMSH(msh, "ACK^P03"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Financial transaction accepted"),
    buildPID(patient),
    buildPV1(),
    buildFT1(),
    buildFT1(`TXN2${timestamp()}`),
  ];
  return lines.join("\r") + "\r";
}

function generateRDEResponse(msh) {
  const patient = pick(MOCK_PATIENTS);
  const med = pick(MOCK_MEDICATIONS);

  const lines = [
    buildMSH(msh, "RRE^O12"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Pharmacy order accepted"),
    buildPID(patient),
    buildPV1(),
    buildORC(),
    buildRXE(med),
  ];
  return lines.join("\r") + "\r";
}

function generateRASResponse(msh) {
  const patient = pick(MOCK_PATIENTS);
  const med = pick(MOCK_MEDICATIONS);

  const lines = [
    buildMSH(msh, "ACK^O17"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Administration recorded"),
    buildPID(patient),
    buildPV1(),
    buildORC(),
    buildRXA(med),
  ];
  return lines.join("\r") + "\r";
}

function generateRGVResponse(msh) {
  const patient = pick(MOCK_PATIENTS);
  const med = pick(MOCK_MEDICATIONS);

  const lines = [
    buildMSH(msh, "ACK^O15"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Pharmacy give recorded"),
    buildPID(patient),
    buildPV1(),
    buildORC(),
    buildRXG(med),
  ];
  return lines.join("\r") + "\r";
}

function generateRDSResponse(msh) {
  const patient = pick(MOCK_PATIENTS);
  const med = pick(MOCK_MEDICATIONS);

  const lines = [
    buildMSH(msh, "ACK^O13"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Dispense recorded"),
    buildPID(patient),
    buildPV1(),
    buildORC(),
    buildRXD(med),
  ];
  return lines.join("\r") + "\r";
}

function generatePCDResponse(msh, message) {
  const patient = pick(MOCK_PATIENTS);
  const device = pick(MOCK_DEVICES);

  const lines = [
    buildMSH(msh, "ACK^R01"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Device data accepted"),
    buildPID(patient),
    buildPV1(),
    `OBR|1||${device.id}|${device.type}|||${timestamp()}`,
    buildOBXDevice(device, 1),
    buildOBXVital("147842", "MDC_ECG_HEART_RATE", "75", "264864^MDC_DIM_BEAT_PER_MIN^MDC", 2),
    buildOBXVital("150456", "MDC_PULS_OXIM_SAT_O2", "98", "262688^MDC_DIM_PERCENT^MDC", 3),
    buildOBXVital("151562", "MDC_RESP_RATE", "16", "264928^MDC_DIM_RESP_PER_MIN^MDC", 4),
    buildOBXVital("150020", "MDC_PRESS_BLD_NONINV_SYS", "118", "266016^MDC_DIM_MMHG^MDC", 5),
    buildOBXVital("150021", "MDC_PRESS_BLD_NONINV_DIA", "76", "266016^MDC_DIM_MMHG^MDC", 6),
    buildOBXVital("150022", "MDC_PRESS_BLD_NONINV_MEAN", "90", "266016^MDC_DIM_MMHG^MDC", 7),
    buildOBXVital("188740", "MDC_TEMP", "36.8", "266112^MDC_DIM_DEGC^MDC", 8),
  ];
  return lines.join("\r") + "\r";
}

function generateQBPResponse(msh, message) {
  // Handle various QBP query types
  const msgType = msh.messageType || "";
  const trigger = msgType.includes("^") ? msgType.split("^")[1] : "Q13";

  if (trigger === "Q40") {
    // WhoAmI query - return server identity
    const lines = [
      buildMSH(msh, "RSP^K40^RSP_K11"),
      buildMSA("AA", msh.messageControlId || "UNKNOWN", "WhoAmI query successful"),
      buildQAK("1", "OK"),
      buildQPD("Q001"),
      buildNTE(1, `Application: ${SERVER_APP}`),
      buildNTE(2, `Facility: ${SERVER_FACILITY}`),
      buildNTE(3, `Version: ${HL7_VERSION}`),
      buildNTE(4, `Platform: Node.js ${process.version}`),
      buildNTE(5, `Uptime: ${Math.floor(process.uptime())}s`),
    ];
    return lines.join("\r") + "\r";
  }

  if (trigger === "Z34" || trigger === "Z44") {
    // Immunization history / forecast
    const patient = pick(MOCK_PATIENTS);
    const lines = [
      buildMSH(msh, `RSP^${trigger}^RSP_K11`),
      buildMSA("AA", msh.messageControlId || "UNKNOWN", "Immunization query successful"),
      buildQAK("1", "OK"),
      buildQPD("Q001"),
      buildPID(patient),
      `RXA|0|1|20240115||08^Hepatitis B^CVX|0.5|mL||00^New^NIP001|||LOT2024HB|20260115|MSD^Merck^^MVX||CP`,
      `RXA|0|1|20240315||03^MMR^CVX|0.5|mL||00^New^NIP001|||LOT2024MMR|20260315|MSD^Merck^^MVX||CP`,
      `RXA|0|1|20240601||115^Tdap^CVX|0.5|mL||00^New^NIP001|||LOT2024TDAP|20260601|SKB^GlaxoSmithKline^^MVX||CP`,
    ];
    return lines.join("\r") + "\r";
  }

  // Default tabular query response
  return generateQueryResponse(msh);
}

function generateVXUResponse(msh) {
  const patient = pick(MOCK_PATIENTS);

  const lines = [
    buildMSH(msh, "ACK^V04"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Vaccination update accepted"),
    buildPID(patient),
    `RXA|0|1|${timestamp()}||08^Hepatitis B^CVX|0.5|mL||00^New^NIP001|||LOT${Date.now()}|20271231|MSD^Merck^^MVX||CP`,
  ];
  return lines.join("\r") + "\r";
}

function generateMFQResponse(msh) {
  const lines = [
    buildMSH(msh, "MFR^M01"),
    buildMSA("AA", msh.messageControlId || "UNKNOWN", "Master file query response"),
    buildMFI("PRA"),
  ];

  // Return all providers as master file records
  for (const provider of MOCK_PROVIDERS) {
    lines.push(buildMFE("MUP", provider.id));
    lines.push(buildSTF(provider));
  }

  return lines.join("\r") + "\r";
}

// ---------------------------------------------------------------------------
// Main Message Router
// ---------------------------------------------------------------------------
function routeMessage(msh, rawMessage) {
  const msgType = msh.messageType || "";
  const parts = msgType.split("^");
  const type = parts[0] || "";

  // Apply response mode overrides for error/reject
  if (RESPONSE_MODE === "error") {
    return generateACK(msh); // generateACK handles AE code
  }
  if (RESPONSE_MODE === "reject") {
    return generateACK(msh); // generateACK handles AR code
  }
  if (RESPONSE_MODE === "random" && Math.random() < 0.2) {
    return generateACK(msh); // 20% chance of just ACK in random mode
  }

  switch (type) {
    case "ADT":
      return generateADTResponse(msh, rawMessage);

    case "ORM":
      return generateORMResponse(msh);

    case "ORU":
      // Check for PCD-like ORU messages with device content
      if (rawMessage.includes("MDC_DEV") || rawMessage.includes("PCD")) {
        return generatePCDResponse(msh, rawMessage);
      }
      return generateORUResponse(msh, rawMessage);

    case "QRY":
      return generateQueryResponse(msh);

    case "QBP":
      return generateQBPResponse(msh, rawMessage);

    case "SIU":
      return generateSIUResponse(msh);

    case "MDM":
      return generateMDMResponse(msh);

    case "MFN":
      return generateMFNResponse(msh);

    case "MFQ":
      return generateMFQResponse(msh);

    case "BAR":
      return generateBARResponse(msh);

    case "DFT":
      return generateDFTResponse(msh);

    case "RDE":
      return generateRDEResponse(msh);

    case "RAS":
      return generateRASResponse(msh);

    case "RGV":
      return generateRGVResponse(msh);

    case "RDS":
      return generateRDSResponse(msh);

    case "VXU":
      return generateVXUResponse(msh);

    case "PCD":
      return generatePCDResponse(msh, rawMessage);

    default:
      return generateACK(msh);
  }
}

// ---------------------------------------------------------------------------
// MLLP Connection Handler
// ---------------------------------------------------------------------------
function handleConnection(socket) {
  const remoteAddr = `${socket.remoteAddress}:${socket.remotePort}`;
  console.log(`[CONN] Client connected: ${remoteAddr}`);

  let buffer = Buffer.alloc(0);

  socket.setTimeout(30000); // 30s idle timeout

  socket.on("data", (data) => {
    buffer = Buffer.concat([buffer, data]);

    // Process all complete MLLP messages in the buffer
    while (true) {
      const startIdx = buffer.indexOf(MLLP_START);
      if (startIdx === -1) {
        buffer = Buffer.alloc(0);
        break;
      }

      // Find the end of the MLLP message
      const endIdx = buffer.indexOf(MLLP_END, startIdx + 1);
      if (endIdx === -1) {
        // Incomplete message, wait for more data
        break;
      }

      // Extract the HL7 message (between start and end markers)
      const hl7Data = buffer.slice(startIdx + 1, endIdx);
      const message = hl7Data.toString("utf-8");

      // Advance buffer past this message
      buffer = buffer.slice(endIdx + MLLP_END.length);

      // Parse and route
      const msh = parseMSH(message);
      const msgType = msh.messageType || "UNKNOWN";
      console.log(
        `[MSG]  Type=${msgType} From=${msh.sendingApp || "?"}/${msh.sendingFacility || "?"} ` +
          `ID=${msh.messageControlId || "?"} (${message.length} bytes)`
      );

      try {
        const response = routeMessage(msh, message);
        const framed = Buffer.concat([MLLP_START, Buffer.from(response, "utf-8"), MLLP_END]);
        socket.write(framed);
        console.log(`[RESP] Sent ${response.length} bytes for ${msgType}`);
      } catch (err) {
        console.error(`[ERR]  Failed to generate response for ${msgType}: ${err.message}`);
        // Send a generic AE response
        const errorResp =
          [
            buildMSH(msh, "ACK"),
            buildMSA("AE", msh.messageControlId || "UNKNOWN", `Server error: ${err.message}`),
          ].join("\r") + "\r";
        const framed = Buffer.concat([MLLP_START, Buffer.from(errorResp, "utf-8"), MLLP_END]);
        socket.write(framed);
      }
    }
  });

  socket.on("timeout", () => {
    console.log(`[CONN] Timeout: ${remoteAddr}`);
    socket.end();
  });

  socket.on("error", (err) => {
    if (err.code !== "ECONNRESET") {
      console.error(`[ERR]  Socket error from ${remoteAddr}: ${err.message}`);
    }
  });

  socket.on("close", () => {
    console.log(`[CONN] Client disconnected: ${remoteAddr}`);
  });
}

// ---------------------------------------------------------------------------
// TLS Certificate Generation (uses execFileSync with fixed args, no user input)
// ---------------------------------------------------------------------------
function generateSelfSignedCert() {
  const certDir = "/tmp/hl7-node-certs";
  const certPath = path.join(certDir, "server.pem");
  const keyPath = path.join(certDir, "server.key");

  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    return { cert: certPath, key: keyPath };
  }

  console.log("[TLS]  Generating self-signed certificate...");
  fs.mkdirSync(certDir, { recursive: true });

  try {
    execFileSync("openssl", [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-days",
      "365",
      "-nodes",
      "-subj",
      "/CN=hl7-node-mock/O=OIDA Test/C=US",
    ]);
    console.log("[TLS]  Self-signed certificate generated");
    return { cert: certPath, key: keyPath };
  } catch (err) {
    console.error(`[TLS]  Failed to generate certificate: ${err.message}`);
    console.error("[TLS]  Falling back to plaintext MLLP");
    return null;
  }
}

// ---------------------------------------------------------------------------
// Server Startup
// ---------------------------------------------------------------------------
function startServer() {
  let server;

  if (TLS_ENABLED) {
    let certPath = TLS_CERT;
    let keyPath = TLS_KEY;

    // Generate self-signed cert if none provided
    if (!certPath || !keyPath || !fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
      const generated = generateSelfSignedCert();
      if (generated) {
        certPath = generated.cert;
        keyPath = generated.key;
      } else {
        // Fall back to plain TCP
        server = net.createServer(handleConnection);
        console.log("[WARN] TLS requested but cert generation failed, using plain TCP");
      }
    }

    if (!server) {
      const tlsOptions = {
        cert: fs.readFileSync(certPath),
        key: fs.readFileSync(keyPath),
        rejectUnauthorized: false,
      };

      if (TLS_CA && fs.existsSync(TLS_CA)) {
        tlsOptions.ca = fs.readFileSync(TLS_CA);
        tlsOptions.requestCert = true;
      }

      server = tls.createServer(tlsOptions, handleConnection);
      console.log(`[TLS]  MLLPS enabled (cert=${certPath})`);
    }
  } else {
    server = net.createServer(handleConnection);
  }

  server.on("error", (err) => {
    console.error(`[ERR]  Server error: ${err.message}`);
    if (err.code === "EADDRINUSE") {
      console.error(`[ERR]  Port ${PORT} is already in use`);
      process.exit(1);
    }
  });

  server.listen(PORT, "0.0.0.0", () => {
    console.log("=".repeat(60));
    console.log("HL7 Node.js MLLP Mock Server");
    console.log("=".repeat(60));
    console.log(`  Port:          ${PORT}`);
    console.log(`  TLS:           ${TLS_ENABLED ? "Enabled (MLLPS)" : "Disabled (MLLP)"}`);
    console.log(`  Application:   ${SERVER_APP}`);
    console.log(`  Facility:      ${SERVER_FACILITY}`);
    console.log(`  HL7 Version:   ${HL7_VERSION}`);
    console.log(`  Response Mode: ${RESPONSE_MODE}`);
    console.log(`  Node.js:       ${process.version}`);
    console.log("-".repeat(60));
    console.log("Mock data loaded:");
    console.log(`  Patients:      ${MOCK_PATIENTS.length}`);
    console.log(`  Providers:     ${MOCK_PROVIDERS.length}`);
    console.log(`  Locations:     ${MOCK_LOCATIONS.length}`);
    console.log(`  Applications:  ${MOCK_APPLICATIONS.length}`);
    console.log(`  Observations:  ${MOCK_OBSERVATIONS.length}`);
    console.log(`  Medications:   ${MOCK_MEDICATIONS.length}`);
    console.log(`  Devices:       ${MOCK_DEVICES.length}`);
    console.log("-".repeat(60));
    console.log("Supported message types:");
    console.log("  ADT (A01-A08, A40), ORM, ORU, QRY, QBP (Q13/Q40/Z34/Z44)");
    console.log("  SIU, MDM, MFN, MFQ, BAR, DFT, VXU");
    console.log("  RDE, RAS, RGV, RDS (pharmacy)");
    console.log("  PCD/ORU with device data (IHE PCD)");
    console.log("=".repeat(60));
    console.log(`[OK]   Listening on 0.0.0.0:${PORT}`);
  });

  return server;
}

// ---------------------------------------------------------------------------
// Graceful Shutdown
// ---------------------------------------------------------------------------
let serverInstance = null;

function shutdown(signal) {
  console.log(`\n[SHUT] Received ${signal}, shutting down...`);
  if (serverInstance) {
    serverInstance.close(() => {
      console.log("[SHUT] Server closed");
      process.exit(0);
    });
    // Force exit after 5 seconds
    setTimeout(() => {
      console.log("[SHUT] Forced exit after timeout");
      process.exit(1);
    }, 5000);
  } else {
    process.exit(0);
  }
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
serverInstance = startServer();
