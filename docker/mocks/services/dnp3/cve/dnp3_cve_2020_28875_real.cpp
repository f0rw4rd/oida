/*
 * REAL opendnp3 1.1.0 APDU-parser over-read - RANGE qualifier family.
 *
 * Bug family: ICSA-13-291-01 "aegis" DNP3 application-layer parser cluster.
 * Vulnerable code: opendnp3::APDU::ReadObjectHeader (src/opendnp3/APDU.cpp),
 *   OT_PLACEHOLDER arm leaves data_size == 0, so a range-qualified header over a
 *   var-0 (placeholder) object passes the `data_size > aRemainder` length guard
 *   even though GetNumObjects() (range Stop-Start+1) yields iterable objects.
 *   opendnp3::ObjectReadIterator::operator* then returns a data pointer past the
 *   fragment's real bytes -> out-of-bounds read (CWE-125).
 *
 * Trigger qualifier: QC_1B_START_STOP (0x00) - 1-byte start/stop range header.
 *
 * Loosely tracked here under CVE-2020-28875 (the historical opendnp3 over-read
 * label used by this mock fleet); the authentic defect is the aegis APDU
 * object-header over-read, demonstrated against the genuine 1.1.0 parser.
 *
 * CRASH CLASS: contained over-read made observable with a fragment-tight buffer
 *   fence (ASan reports the read 0 bytes past the genuine CopyableBuffer alloc).
 *
 * FOR AUTHORIZED SECURITY TESTING ONLY - DO NOT USE IN PRODUCTION.
 */
#define DNP3_PORT 20000
#include "dnp3_outstation_common.h"

int main(void) {
    return run_outstation(
        DNP3_PORT,
        "  REAL opendnp3 CVE-2020-28875 outstation\n"
        "  APDU range-qualifier object over-read\n");
}
