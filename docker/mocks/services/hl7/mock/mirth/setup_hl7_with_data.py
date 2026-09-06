#!/usr/bin/env python3
"""
Setup Mirth Connect with HL7 channel containing sample patient data.
Usage: python setup_hl7_with_data.py [host] [port]
"""

import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = sys.argv[2] if len(sys.argv) > 2 else "8443"
BASE_URL = f"https://{HOST}:{PORT}/api"
HEADERS = {"X-Requested-With": "python", "Content-Type": "application/xml"}

# Sample patient database as JavaScript
PATIENT_DATA_JS = """
// Sample Patient Database for HL7 Testing
var patients = [
    {id: "PT001", mrn: "MRN001", name: "DOE^JOHN^MICHAEL", dob: "19800115", sex: "M", ssn: "123-45-6789", addr: "123 MAIN ST^^ANYTOWN^CA^90210^USA", phone: "(555)123-4567", ins: "BCBS^BC123456", dx: "I10^Essential hypertension^ICD10"},
    {id: "PT002", mrn: "MRN002", name: "SMITH^JANE^ANN", dob: "19750520", sex: "F", ssn: "234-56-7890", addr: "456 OAK AVE^^SOMEWHERE^NY^10001^USA", phone: "(555)234-5678", ins: "AETNA^AE789012", dx: "E11.9^Type 2 diabetes^ICD10"},
    {id: "PT003", mrn: "MRN003", name: "JOHNSON^ROBERT^LEE", dob: "19650310", sex: "M", ssn: "345-67-8901", addr: "789 ELM ST^^NOWHERE^TX^75001^USA", phone: "(555)345-6789", ins: "UNITED^UH345678", dx: "J44.9^COPD^ICD10"},
    {id: "PT004", mrn: "MRN004", name: "WILLIAMS^MARY^KATE", dob: "19900725", sex: "F", ssn: "456-78-9012", addr: "321 PINE RD^^ELSEWHERE^FL^33101^USA", phone: "(555)456-7890", ins: "CIGNA^CG901234", dx: "F32.9^Major depression^ICD10"},
    {id: "PT005", mrn: "MRN005", name: "BROWN^DAVID^JAMES", dob: "19551215", sex: "M", ssn: "567-89-0123", addr: "654 MAPLE DR^^ANYWHERE^WA^98001^USA", phone: "(555)567-8901", ins: "HUMANA^HM567890", dx: "I25.10^CAD^ICD10"},
    {id: "PT006", mrn: "MRN006", name: "GARCIA^MARIA^ELENA", dob: "19850403", sex: "F", ssn: "678-90-1234", addr: "987 CEDAR LN^^SOMEPLACE^AZ^85001^USA", phone: "(555)678-9012", ins: "KAISER^KP123789", dx: "N18.3^CKD Stage 3^ICD10"},
    {id: "PT007", mrn: "MRN007", name: "MILLER^JAMES^THOMAS", dob: "19700918", sex: "M", ssn: "789-01-2345", addr: "147 BIRCH WAY^^OTHERTOWN^CO^80001^USA", phone: "(555)789-0123", ins: "MEDICARE^MC456012", dx: "G20^Parkinson disease^ICD10"},
    {id: "PT008", mrn: "MRN008", name: "DAVIS^SARAH^LYNN", dob: "19950601", sex: "F", ssn: "890-12-3456", addr: "258 WILLOW CT^^NEWTOWN^OR^97001^USA", phone: "(555)890-1234", ins: "MEDICAID^MD789345", dx: "J45.20^Mild asthma^ICD10"},
    {id: "PT009", mrn: "MRN009", name: "MARTINEZ^CARLOS^JOSE", dob: "19600822", sex: "M", ssn: "901-23-4567", addr: "369 SPRUCE PL^^OLDTOWN^NV^89001^USA", phone: "(555)901-2345", ins: "TRICARE^TC012678", dx: "M54.5^Low back pain^ICD10"},
    {id: "PT010", mrn: "MRN010", name: "ANDERSON^EMILY^ROSE", dob: "20000214", sex: "F", ssn: "012-34-5678", addr: "480 ASPEN RD^^LAKETOWN^MN^55001^USA", phone: "(555)012-3456", ins: "BSHIELD^BS345901", dx: "K21.0^GERD^ICD10"}
];

var providers = [
    {npi: "1234567890", name: "SMITH^WILLIAM^MD", specialty: "Internal Medicine"},
    {npi: "2345678901", name: "JONES^PATRICIA^MD", specialty: "Cardiology"},
    {npi: "3456789012", name: "WILSON^ROBERT^MD", specialty: "Pulmonology"},
    {npi: "4567890123", name: "TAYLOR^JENNIFER^MD", specialty: "Endocrinology"},
    {npi: "5678901234", name: "BROWN^MICHAEL^MD", specialty: "Nephrology"}
];

var locations = [
    "ICU^101^A^MAIN_HOSPITAL",
    "ER^001^1^EMERGENCY",
    "MED-SURG^201^B^MAIN_HOSPITAL",
    "CARDIAC^301^A^HEART_CENTER",
    "ONCOLOGY^401^A^CANCER_CENTER"
];
"""

RESPONSE_LOGIC_JS = """
var now = DateUtil.getCurrentDate("yyyyMMddHHmmss");
var msgType = "";
var msgTrigger = "";
var msgControlId = "UNKNOWN";
var sendingApp = "UNKNOWN";
var sendingFac = "UNKNOWN";

try {
    msgType = msg['MSH']['MSH.9']['MSH.9.1'].toString();
    msgTrigger = msg['MSH']['MSH.9']['MSH.9.2'] ? msg['MSH']['MSH.9']['MSH.9.2'].toString() : "";
    msgControlId = msg['MSH']['MSH.10'].toString();
    sendingApp = msg['MSH']['MSH.3'] ? msg['MSH']['MSH.3'].toString() : "UNKNOWN";
    sendingFac = msg['MSH']['MSH.4'] ? msg['MSH']['MSH.4'].toString() : "UNKNOWN";
} catch(e) {
    logger.info("MSH parse error: " + e);
}

var response = "";
var prov = providers[Math.floor(Math.random() * providers.length)];
var loc = locations[Math.floor(Math.random() * locations.length)];

if (msgType == "QRY" || msgType == "QBP") {
    // Query response - return patient list
    response = "MSH|^~\\\\&|HOSPITAL_HIS|MAIN_HOSPITAL|" + sendingApp + "|" + sendingFac + "|" + now + "||RSP^K11|RSP" + now + "|P|2.5\\r";
    response += "MSA|AA|" + msgControlId + "|Query successful\\r";
    response += "QAK|1|OK|Q22^Find Candidates^HL70471\\r";

    for (var i = 0; i < Math.min(5, patients.length); i++) {
        var p = patients[i];
        response += "PID|" + (i+1) + "||" + p.id + "^^^HOSP^MR~" + p.ssn + "^^^SSA^SS||" + p.name + "||" + p.dob + "|" + p.sex + "|||" + p.addr + "||" + p.phone + "\\r";
        response += "PV1|1|I|" + loc + "||||" + prov.name + "^" + prov.npi + "^^^^^NPI\\r";
    }
} else if (msgType == "ADT") {
    response = "MSH|^~\\\\&|HOSPITAL_HIS|MAIN_HOSPITAL|" + sendingApp + "|" + sendingFac + "|" + now + "||ACK^" + msgTrigger + "|ACK" + now + "|P|2.5\\r";
    response += "MSA|AA|" + msgControlId + "|ADT message accepted\\r";
    var p = patients[Math.floor(Math.random() * patients.length)];
    response += "PID|1||" + p.id + "^^^HOSP^MR||" + p.name + "||" + p.dob + "|" + p.sex + "|||" + p.addr + "||" + p.phone + "\\r";
    response += "PV1|1|I|" + loc + "||||" + prov.name + "^" + prov.npi + "^^^^^NPI\\r";
    response += "DG1|1|I10|" + p.dx + "|||A\\r";
} else if (msgType == "ORM" || msgType == "ORU") {
    response = "MSH|^~\\\\&|HOSPITAL_HIS|MAIN_HOSPITAL|" + sendingApp + "|" + sendingFac + "|" + now + "||ORR^O02|ORR" + now + "|P|2.5\\r";
    response += "MSA|AA|" + msgControlId + "|Order accepted\\r";
    var p = patients[Math.floor(Math.random() * patients.length)];
    response += "PID|1||" + p.id + "^^^HOSP^MR||" + p.name + "||" + p.dob + "|" + p.sex + "\\r";
    response += "ORC|OK|ORD" + now + "|||CM\\r";
    response += "OBR|1|ORD" + now + "||CBC^Complete Blood Count^L|||" + now + "\\r";
    response += "OBX|1|NM|WBC^White Blood Cell^L||7.5|10*3/uL|4.5-11.0|N|||F\\r";
    response += "OBX|2|NM|HGB^Hemoglobin^L||14.2|g/dL|12.0-16.0|N|||F\\r";
} else {
    response = "MSH|^~\\\\&|HOSPITAL_HIS|MAIN_HOSPITAL|" + sendingApp + "|" + sendingFac + "|" + now + "||ACK|ACK" + now + "|P|2.5\\r";
    response += "MSA|AA|" + msgControlId + "|Message received\\r";
}

responseMap.put("response", response);
return response;
"""

CHANNEL_XML = """<?xml version="1.0" encoding="UTF-8"?>
<channel version="4.5.0">
  <id>hl7-patient-data</id>
  <nextMetaDataId>2</nextMetaDataId>
  <name>HL7 Patient Data Server</name>
  <description>HL7 MLLP listener with sample patient database</description>
  <revision>1</revision>
  <sourceConnector version="4.5.0">
    <metaDataId>0</metaDataId>
    <name>sourceConnector</name>
    <properties class="com.mirth.connect.connectors.tcp.TcpReceiverProperties" version="4.5.0">
      <pluginProperties/>
      <listenerConnectorProperties version="4.5.0">
        <host>0.0.0.0</host>
        <port>6661</port>
      </listenerConnectorProperties>
      <sourceConnectorProperties version="4.5.0">
        <responseVariable>d1</responseVariable>
        <respondAfterProcessing>true</respondAfterProcessing>
        <processBatch>false</processBatch>
        <firstResponse>false</firstResponse>
        <processingThreads>1</processingThreads>
        <resourceIds class="linked-hash-map">
          <entry>
            <string>Default Resource</string>
            <string>[Default Resource]</string>
          </entry>
        </resourceIds>
        <queueBufferSize>1000</queueBufferSize>
      </sourceConnectorProperties>
      <transmissionModeProperties class="com.mirth.connect.plugins.mllpmode.MLLPModeProperties" version="4.5.0">
        <pluginPointName>MLLP</pluginPointName>
        <startOfMessageBytes>0B</startOfMessageBytes>
        <endOfMessageBytes>1C0D</endOfMessageBytes>
        <useMLLPv2>false</useMLLPv2>
        <ackBytes>06</ackBytes>
        <nackBytes>15</nackBytes>
        <maxRetries>0</maxRetries>
      </transmissionModeProperties>
      <serverMode>true</serverMode>
      <reconnectInterval>5000</reconnectInterval>
      <receiveTimeout>0</receiveTimeout>
      <bufferSize>65536</bufferSize>
      <maxConnections>10</maxConnections>
      <keepConnectionOpen>true</keepConnectionOpen>
      <dataTypeBinary>false</dataTypeBinary>
      <charsetEncoding>DEFAULT_ENCODING</charsetEncoding>
      <respondOnNewConnection>0</respondOnNewConnection>
      <responseConnectorProperties version="4.5.0">
        <responseVariable>d1</responseVariable>
      </responseConnectorProperties>
    </properties>
    <transformer version="4.5.0">
      <elements/>
      <inboundDataType>HL7V2</inboundDataType>
      <outboundDataType>HL7V2</outboundDataType>
      <inboundProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2DataTypeProperties" version="4.5.0">
        <serializationProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2SerializationProperties" version="4.5.0">
          <handleRepetitions>true</handleRepetitions>
          <handleSubcomponents>true</handleSubcomponents>
          <useStrictParser>false</useStrictParser>
          <useStrictValidation>false</useStrictValidation>
          <stripNamespaces>true</stripNamespaces>
          <segmentDelimiter>\\r</segmentDelimiter>
          <convertLineBreaks>true</convertLineBreaks>
        </serializationProperties>
        <deserializationProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2DeserializationProperties" version="4.5.0">
          <useStrictParser>false</useStrictParser>
          <useStrictValidation>false</useStrictValidation>
          <segmentDelimiter>\\r</segmentDelimiter>
        </deserializationProperties>
        <batchProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2BatchProperties" version="4.5.0">
          <splitType>MSH_Segment</splitType>
        </batchProperties>
        <responseGenerationProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2ResponseGenerationProperties" version="4.5.0">
          <segmentDelimiter>\\r</segmentDelimiter>
          <successfulACKCode>AA</successfulACKCode>
          <errorACKCode>AE</errorACKCode>
          <rejectedACKCode>AR</rejectedACKCode>
          <msh15ACKAccept>false</msh15ACKAccept>
          <dateFormat>yyyyMMddHHmmss.SSS</dateFormat>
        </responseGenerationProperties>
        <responseValidationProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2ResponseValidationProperties" version="4.5.0">
          <successfulACKCode>AA,CA</successfulACKCode>
          <errorACKCode>AE,CE</errorACKCode>
          <rejectedACKCode>AR,CR</rejectedACKCode>
          <validateMessageControlId>true</validateMessageControlId>
          <originalMessageControlId>Destination_Encoded</originalMessageControlId>
        </responseValidationProperties>
      </inboundProperties>
      <outboundProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2DataTypeProperties" version="4.5.0">
        <serializationProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2SerializationProperties" version="4.5.0">
          <handleRepetitions>true</handleRepetitions>
          <handleSubcomponents>true</handleSubcomponents>
          <useStrictParser>false</useStrictParser>
          <useStrictValidation>false</useStrictValidation>
          <stripNamespaces>true</stripNamespaces>
          <segmentDelimiter>\\r</segmentDelimiter>
          <convertLineBreaks>true</convertLineBreaks>
        </serializationProperties>
        <deserializationProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2DeserializationProperties" version="4.5.0">
          <useStrictParser>false</useStrictParser>
          <useStrictValidation>false</useStrictValidation>
          <segmentDelimiter>\\r</segmentDelimiter>
        </deserializationProperties>
        <batchProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2BatchProperties" version="4.5.0">
          <splitType>MSH_Segment</splitType>
        </batchProperties>
        <responseGenerationProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2ResponseGenerationProperties" version="4.5.0">
          <segmentDelimiter>\\r</segmentDelimiter>
          <successfulACKCode>AA</successfulACKCode>
          <errorACKCode>AE</errorACKCode>
          <rejectedACKCode>AR</rejectedACKCode>
          <msh15ACKAccept>false</msh15ACKAccept>
          <dateFormat>yyyyMMddHHmmss.SSS</dateFormat>
        </responseGenerationProperties>
        <responseValidationProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2ResponseValidationProperties" version="4.5.0">
          <successfulACKCode>AA,CA</successfulACKCode>
          <errorACKCode>AE,CE</errorACKCode>
          <rejectedACKCode>AR,CR</rejectedACKCode>
          <validateMessageControlId>true</validateMessageControlId>
          <originalMessageControlId>Destination_Encoded</originalMessageControlId>
        </responseValidationProperties>
      </outboundProperties>
    </transformer>
    <filter version="4.5.0">
      <elements/>
    </filter>
    <transportName>TCP Listener</transportName>
    <mode>SOURCE</mode>
    <enabled>true</enabled>
    <waitForPrevious>true</waitForPrevious>
  </sourceConnector>
  <destinationConnectors>
    <connector version="4.5.0">
      <metaDataId>1</metaDataId>
      <name>Patient Response</name>
      <properties class="com.mirth.connect.connectors.js.JavaScriptDispatcherProperties" version="4.5.0">
        <pluginProperties/>
        <destinationConnectorProperties version="4.5.0">
          <queueEnabled>false</queueEnabled>
          <sendFirst>false</sendFirst>
          <retryIntervalMillis>10000</retryIntervalMillis>
          <regenerateTemplate>false</regenerateTemplate>
          <retryCount>0</retryCount>
          <rotate>false</rotate>
          <includeFilterTransformer>false</includeFilterTransformer>
          <threadCount>1</threadCount>
          <validateResponse>false</validateResponse>
          <resourceIds class="linked-hash-map">
            <entry>
              <string>Default Resource</string>
              <string>[Default Resource]</string>
            </entry>
          </resourceIds>
          <queueBufferSize>1000</queueBufferSize>
          <reattachAttachments>true</reattachAttachments>
        </destinationConnectorProperties>
        <script>__SCRIPT_PLACEHOLDER__</script>
      </properties>
      <transformer version="4.5.0">
        <elements/>
        <inboundDataType>HL7V2</inboundDataType>
        <outboundDataType>RAW</outboundDataType>
        <inboundProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2DataTypeProperties" version="4.5.0">
          <serializationProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2SerializationProperties" version="4.5.0">
            <handleRepetitions>true</handleRepetitions>
            <handleSubcomponents>true</handleSubcomponents>
            <useStrictParser>false</useStrictParser>
            <useStrictValidation>false</useStrictValidation>
            <stripNamespaces>true</stripNamespaces>
            <segmentDelimiter>\\r</segmentDelimiter>
            <convertLineBreaks>true</convertLineBreaks>
          </serializationProperties>
          <deserializationProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2DeserializationProperties" version="4.5.0">
            <useStrictParser>false</useStrictParser>
            <useStrictValidation>false</useStrictValidation>
            <segmentDelimiter>\\r</segmentDelimiter>
          </deserializationProperties>
          <batchProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2BatchProperties" version="4.5.0">
            <splitType>MSH_Segment</splitType>
          </batchProperties>
          <responseGenerationProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2ResponseGenerationProperties" version="4.5.0">
            <segmentDelimiter>\\r</segmentDelimiter>
            <successfulACKCode>AA</successfulACKCode>
            <errorACKCode>AE</errorACKCode>
            <rejectedACKCode>AR</rejectedACKCode>
            <msh15ACKAccept>false</msh15ACKAccept>
            <dateFormat>yyyyMMddHHmmss.SSS</dateFormat>
          </responseGenerationProperties>
          <responseValidationProperties class="com.mirth.connect.plugins.datatypes.hl7v2.HL7v2ResponseValidationProperties" version="4.5.0">
            <successfulACKCode>AA,CA</successfulACKCode>
            <errorACKCode>AE,CE</errorACKCode>
            <rejectedACKCode>AR,CR</rejectedACKCode>
            <validateMessageControlId>true</validateMessageControlId>
            <originalMessageControlId>Destination_Encoded</originalMessageControlId>
          </responseValidationProperties>
        </inboundProperties>
        <outboundProperties class="com.mirth.connect.plugins.datatypes.raw.RawDataTypeProperties" version="4.5.0">
          <batchProperties class="com.mirth.connect.plugins.datatypes.raw.RawBatchProperties" version="4.5.0">
            <splitType>JavaScript</splitType>
          </batchProperties>
        </outboundProperties>
      </transformer>
      <responseTransformer version="4.5.0">
        <elements/>
        <inboundDataType>RAW</inboundDataType>
        <outboundDataType>RAW</outboundDataType>
        <inboundProperties class="com.mirth.connect.plugins.datatypes.raw.RawDataTypeProperties" version="4.5.0">
          <batchProperties class="com.mirth.connect.plugins.datatypes.raw.RawBatchProperties" version="4.5.0">
            <splitType>JavaScript</splitType>
          </batchProperties>
        </inboundProperties>
        <outboundProperties class="com.mirth.connect.plugins.datatypes.raw.RawDataTypeProperties" version="4.5.0">
          <batchProperties class="com.mirth.connect.plugins.datatypes.raw.RawBatchProperties" version="4.5.0">
            <splitType>JavaScript</splitType>
          </batchProperties>
        </outboundProperties>
      </responseTransformer>
      <filter version="4.5.0">
        <elements/>
      </filter>
      <transportName>JavaScript Writer</transportName>
      <mode>DESTINATION</mode>
      <enabled>true</enabled>
      <waitForPrevious>true</waitForPrevious>
    </connector>
  </destinationConnectors>
  <preprocessingScript>return message;</preprocessingScript>
  <postprocessingScript>return;</postprocessingScript>
  <deployScript>return;</deployScript>
  <undeployScript>return;</undeployScript>
  <properties version="4.5.0">
    <clearGlobalChannelMap>true</clearGlobalChannelMap>
    <messageStorageMode>DEVELOPMENT</messageStorageMode>
    <encryptData>false</encryptData>
    <encryptAttachments>false</encryptAttachments>
    <initialState>STARTED</initialState>
    <storeAttachments>true</storeAttachments>
    <metaDataColumns/>
    <attachmentProperties version="4.5.0">
      <type>None</type>
      <properties/>
    </attachmentProperties>
    <resourceIds class="linked-hash-map">
      <entry>
        <string>Default Resource</string>
        <string>[Default Resource]</string>
      </entry>
    </resourceIds>
  </properties>
</channel>
"""


def main():
    print(f"Setting up Mirth Connect at {BASE_URL}...")

    session = requests.Session()
    session.verify = False

    # Login
    print("Logging in...")
    resp = session.post(
        f"{BASE_URL}/users/_login",
        headers={"X-Requested-With": "python", "Content-Type": "application/x-www-form-urlencoded"},
        data={"username": "admin", "password": "admin"},
    )
    if resp.status_code != 200:
        print(f"Login failed: {resp.status_code} {resp.text}")
        return 1
    print("  Login successful")

    # Check existing channels
    print("Checking existing channels...")
    resp = session.get(f"{BASE_URL}/channels", headers={"X-Requested-With": "python"})
    print(f"  Current channels: {resp.text[:200]}...")

    # Delete existing channel if exists
    print("Removing old channel if exists...")
    session.delete(f"{BASE_URL}/channels/hl7-patient-data", headers={"X-Requested-With": "python"})
    session.delete(f"{BASE_URL}/channels/hl7-test-listener", headers={"X-Requested-With": "python"})

    # Build the full script
    full_script = PATIENT_DATA_JS + "\n" + RESPONSE_LOGIC_JS

    # Escape for XML
    full_script = full_script.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Insert script into channel XML
    channel_xml = CHANNEL_XML.replace("__SCRIPT_PLACEHOLDER__", full_script)

    # Create channel
    print("Creating HL7 Patient Data channel...")
    resp = session.post(f"{BASE_URL}/channels", headers=HEADERS, data=channel_xml.encode("utf-8"))
    if resp.status_code not in [200, 201]:
        print(f"Channel creation failed: {resp.status_code}")
        print(resp.text[:500])
        return 1
    print(f"  Channel created: {resp.text}")

    # Deploy channel
    print("Deploying channel...")
    resp = session.post(
        f"{BASE_URL}/channels/hl7-patient-data/_deploy", headers={"X-Requested-With": "python"}
    )
    if resp.status_code not in [200, 204]:
        print(f"Deploy failed: {resp.status_code} {resp.text}")
        return 1
    print("  Channel deployed")

    print()
    print("=" * 60)
    print("SUCCESS! HL7 Patient Data Server running on port 6661")
    print("=" * 60)
    print()
    print("Sample patient data loaded:")
    print("  - 10 patients with MRN, SSN, diagnoses, insurance")
    print("  - 5 providers with NPI numbers")
    print("  - 5 hospital locations")
    print()
    print("Test with:")
    print("  oida hl7 127.0.0.1 -p 6661 --send-qry --patient-id '*'")
    print()
    print("Web console: https://localhost:8443 (admin/admin)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
