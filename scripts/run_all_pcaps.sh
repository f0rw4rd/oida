#!/usr/bin/env bash
# Run oida pcap against all test fixture pcaps and audit the resulting CSVs.
# Usage: ./scripts/run_all_pcaps.sh [output_dir]
#
# Captures full command output per pcap into <output_dir>/logs/<name>.log
# then scans every generated CSV for quality issues (empty fields, bad data).

set -euo pipefail

OUTDIR="${1:-/tmp/test_pcap_audit}"
LOGDIR="$OUTDIR/logs"
TIMEOUT=45          # seconds per pcap
FIXTURES="tests/fixtures/pcap"

rm -rf "$OUTDIR"
mkdir -p "$LOGDIR"

# Collect all pcap/pcapng files
mapfile -t PCAPS < <(find "$FIXTURES" -type f \( -name '*.pcap' -o -name '*.pcapng' \) | sort)
TOTAL=${#PCAPS[@]}
echo "=== OIDA PCAP audit: $TOTAL pcap files ==="
echo "Output dir : $OUTDIR"
echo "Per-pcap timeout: ${TIMEOUT}s"
echo ""

PASS=0
FAIL=0
TIMEOUT_COUNT=0
EMPTY=0

for i in "${!PCAPS[@]}"; do
    pcap="${PCAPS[$i]}"
    # Short name for log file (replace / with _)
    short="${pcap#$FIXTURES/}"
    logname="${short//\//_}"
    logname="${logname%.pcap}"
    logname="${logname%.pcapng}"
    logfile="$LOGDIR/${logname}.log"

    idx=$((i + 1))
    printf "[%3d/%d] %-70s " "$idx" "$TOTAL" "$short"

    # Run oida pcap with timeout, capture all output
    set +e
    timeout "$TIMEOUT" oida -o "$OUTDIR" pcap "$pcap" > "$logfile" 2>&1
    rc=$?
    set -e

    if [ $rc -eq 124 ]; then
        echo "TIMEOUT"
        TIMEOUT_COUNT=$((TIMEOUT_COUNT + 1))
    elif [ $rc -ne 0 ]; then
        echo "FAIL (rc=$rc)"
        FAIL=$((FAIL + 1))
    else
        echo "OK"
        PASS=$((PASS + 1))
    fi
done

echo ""
echo "=== Run summary ==="
echo "  Total : $TOTAL"
echo "  Pass  : $PASS"
echo "  Fail  : $FAIL"
echo "  Timeout: $TIMEOUT_COUNT"
echo ""

# ─── CSV Quality Audit ───────────────────────────────────────────────────────

echo "=== CSV Quality Audit ==="

REPORT="$OUTDIR/csv_audit_report.txt"
: > "$REPORT"

# Find all CSVs produced
mapfile -t CSVS < <(find "$OUTDIR" -name '*.csv' -not -path '*/logs/*' | sort)
echo "Found ${#CSVS[@]} CSV files to audit"
echo ""

issues_found=0

for csv in "${CSVS[@]}"; do
    relpath="${csv#$OUTDIR/}"
    line_count=$(wc -l < "$csv")

    # Skip empty files (header only or truly empty)
    if [ "$line_count" -le 1 ]; then
        continue
    fi

    # Read header to know column count
    header=$(head -1 "$csv")
    IFS=',' read -ra cols <<< "$header"
    ncols=${#cols[@]}

    problems=()

    # 1) Check for rows with trailing/leading empty fields
    #    i.e. lines ending with , or containing ,,
    empty_field_rows=$(grep -cE '(^,|,,|,$)' "$csv" 2>/dev/null || true)
    if [ "$empty_field_rows" -gt 0 ]; then
        # Exclude header from count
        header_empty=$(echo "$header" | grep -cE '(^,|,,|,$)' 2>/dev/null || true)
        data_empty=$((empty_field_rows - header_empty))
        if [ "$data_empty" -gt 0 ]; then
            pct=$(( (data_empty * 100) / (line_count - 1) ))
            problems+=("empty_fields: $data_empty/${line_count} rows ($pct%)")
        fi
    fi

    # 2) Check for EkMultiField leak in CSV data
    ekm_rows=$(grep -ciE 'EkMultiField' "$csv" 2>/dev/null || true)
    if [ "$ekm_rows" -gt 0 ]; then
        problems+=("EkMultiField_leak: $ekm_rows rows")
    fi

    # 3) Check for Python repr leak (e.g. <class, <built-in, [<)
    repr_rows=$(grep -cE '<(class|built-in|EkMultiField|module)' "$csv" 2>/dev/null || true)
    if [ "$repr_rows" -gt 0 ]; then
        problems+=("python_repr_leak: $repr_rows rows")
    fi

    # 4) Check for 'None' string in data (should be empty)
    none_rows=$(grep -cw 'None' "$csv" 2>/dev/null || true)
    if [ "$none_rows" -gt 0 ]; then
        problems+=("None_string: $none_rows rows")
    fi

    # 5) Check for Request/Response as generic operation in interaction CSVs
    if echo "$relpath" | grep -qiE 'interaction|smb|http|ftp|smtp|imap|pop3|telnet|ssh|sip|kerberos|ntlm'; then
        generic_ops=$(grep -cE '(,Request$|,Response$|, Request,|, Response,)' "$csv" 2>/dev/null || true)
        if [ "$generic_ops" -gt 0 ]; then
            problems+=("generic_Request/Response: $generic_ops rows")
        fi
    fi

    # 6) Check column count consistency
    bad_cols=$(awk -F',' -v expected="$ncols" 'NR>1 && NF!=expected {count++} END {print count+0}' "$csv")
    if [ "$bad_cols" -gt 0 ]; then
        problems+=("column_mismatch: $bad_cols rows (expected $ncols cols)")
    fi

    if [ ${#problems[@]} -gt 0 ]; then
        issues_found=$((issues_found + 1))
        echo "ISSUE: $relpath ($line_count lines, $ncols cols)" | tee -a "$REPORT"
        for p in "${problems[@]}"; do
            echo "  - $p" | tee -a "$REPORT"
        done
        # Show first few bad rows for context
        if [ "$empty_field_rows" -gt 0 ] && [ "$data_empty" -gt 0 ]; then
            echo "  sample rows with empty fields:" | tee -a "$REPORT"
            grep -nE '(^,|,,|,$)' "$csv" | head -3 | sed 's/^/    /' | tee -a "$REPORT"
        fi
        if [ "$ekm_rows" -gt 0 ]; then
            echo "  sample EkMultiField rows:" | tee -a "$REPORT"
            grep -iE 'EkMultiField' "$csv" | head -3 | sed 's/^/    /' | tee -a "$REPORT"
        fi
        echo "" | tee -a "$REPORT"
    fi
done

echo "=== Audit complete ==="
echo "  CSVs checked  : ${#CSVS[@]}"
echo "  Issues found  : $issues_found"
echo "  Full report   : $REPORT"
echo ""

# ─── Credential/Hash summary ─────────────────────────────────────────────────

echo "=== Credential & Hash extraction summary ==="
cred_csvs=$(find "$OUTDIR" -name '*credential*' -o -name '*hash*' | wc -l)
echo "  Credential/hash CSVs: $cred_csvs"
if [ "$cred_csvs" -gt 0 ]; then
    for f in $(find "$OUTDIR" -name '*credential*' -o -name '*hash*' | sort); do
        lines=$(wc -l < "$f")
        echo "  $(basename "$f"): $((lines - 1)) entries"
    done
fi

echo ""
echo "=== Log files with errors ==="
err_logs=$(grep -rlE '(Traceback|Error|FAIL|exception)' "$LOGDIR"/ 2>/dev/null | wc -l)
echo "  Logs with errors: $err_logs / $TOTAL"
if [ "$err_logs" -gt 0 ]; then
    for f in $(grep -rlE '(Traceback|Error|FAIL|exception)' "$LOGDIR"/ 2>/dev/null | head -20); do
        echo "  - $(basename "$f" .log)"
        grep -m2 -E '(Traceback|Error|FAIL|exception)' "$f" | sed 's/^/      /'
    done
fi

echo ""
echo "Done. All output in: $OUTDIR"
