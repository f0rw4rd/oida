#!/bin/bash
# Senior Code Review Script for MSF-ICS Protocol Modules
# Usage: ./scripts/code_review.sh msf_ics/protocols/MODULE_NAME
#
# This script performs a comprehensive code review checking:
# 1. Import hygiene (no local imports)
# 2. Fallback imports (should use lazy_import)
# 3. Print statements (should use logger)
# 4. Logging module usage (should use ICSLogger)
# 5. Dead code detection
# 6. Black formatting
# 7. Flake8 style
# 8. Bandit security
# 9. MyPy type checking
# 10. Test coverage
# 11. Pattern checks (bare except, TODO, eval, hardcoded creds)
# 12. CLI options compliance
# 13. File size check (large files should be split)
# 14. Export utilities check (use export_table/get_export_path)
# 15. Connection handling (no redundant sockets with protocol libs)
# 16. Protocol debug logging (TX/RX hex for in-house protocols)
# 17. NXC architecture compliance (proto_logger, class attrs, create_conn_obj)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check arguments
if [ -z "$1" ]; then
    echo -e "${RED}Usage: $0 msf_ics/protocols/MODULE_NAME${NC}"
    echo "Example: $0 msf_ics/protocols/modbus"
    exit 1
fi

MODULE_PATH="$1"
MODULE_NAME=$(basename "$MODULE_PATH")
REPORT_DIR="code_quality_reports/${MODULE_NAME}"

# Check if module exists
if [ ! -d "$MODULE_PATH" ]; then
    echo -e "${RED}Error: Module path does not exist: $MODULE_PATH${NC}"
    exit 1
fi

# Create report directory
mkdir -p "$REPORT_DIR"

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  Senior Code Review: ${MODULE_NAME}${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Initialize counters
TOTAL_ISSUES=0
CRITICAL_ISSUES=0

# Function to check tool availability
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${YELLOW}Warning: $1 not installed, skipping...${NC}"
        return 1
    fi
    return 0
}

# 1. Import Hygiene
echo -e "${BLUE}[1/17]${NC} Checking import hygiene..."
# Find imports not at top level (indented imports)
# Match: "    import X" or "    from X import Y" (must have 'import' keyword)
grep -rn "^\s\+import \|^\s\+from [^ ]* import " "$MODULE_PATH" 2>/dev/null \
    | grep -v "_get_\|def \|#\|\.pyc\|\"\"\"" > "$REPORT_DIR/local_imports.txt" || true
LOCAL_IMPORTS=$(wc -l < "$REPORT_DIR/local_imports.txt" | tr -d ' ')
if [ "$LOCAL_IMPORTS" -gt 0 ]; then
    echo -e "  ${YELLOW}Found $LOCAL_IMPORTS local imports (review for lazy getter pattern)${NC}"
else
    echo -e "  ${GREEN}No local imports found${NC}"
fi

# 2. Fallback Imports (should be none - use lazy_import instead)
echo -e "${BLUE}[2/17]${NC} Checking for fallback imports..."
{
    grep -rn "except ImportError" "$MODULE_PATH" 2>/dev/null || true
    grep -rn "= None.*#.*import\|import.*= None" "$MODULE_PATH" 2>/dev/null || true
} | grep -v "\.pyc" > "$REPORT_DIR/fallback_imports.txt" || true
FALLBACKS=$(wc -l < "$REPORT_DIR/fallback_imports.txt" | tr -d ' ')
if [ "$FALLBACKS" -gt 0 ]; then
    echo -e "  ${RED}CRITICAL: Found $FALLBACKS fallback imports (use lazy_import instead)${NC}"
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + FALLBACKS))
else
    echo -e "  ${GREEN}No fallback imports found${NC}"
fi

# 3. Print statements (should use logger)
echo -e "${BLUE}[3/17]${NC} Checking for print statements..."
grep -rn "print(" "$MODULE_PATH" 2>/dev/null \
    | grep -v "# noqa\|\.pyc\|__pycache__" > "$REPORT_DIR/print_statements.txt" || true
PRINTS=$(wc -l < "$REPORT_DIR/print_statements.txt" | tr -d ' ')
if [ "$PRINTS" -gt 0 ]; then
    echo -e "  ${RED}CRITICAL: Found $PRINTS print() statements (use self.logger instead)${NC}"
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + PRINTS))
else
    echo -e "  ${GREEN}No print statements found${NC}"
fi

# 4. Logging module usage (should use ICSLogger)
echo -e "${BLUE}[4/17]${NC} Checking for logging module usage..."
grep -rn "logging\.\|^import logging\|^from logging" "$MODULE_PATH" 2>/dev/null \
    | grep -v "\.pyc\|__pycache__" > "$REPORT_DIR/logging_usage.txt" || true
LOGGING=$(wc -l < "$REPORT_DIR/logging_usage.txt" | tr -d ' ')
if [ "$LOGGING" -gt 0 ]; then
    echo -e "  ${YELLOW}Found $LOGGING logging module usages (should use ICSLogger)${NC}"
    TOTAL_ISSUES=$((TOTAL_ISSUES + LOGGING))
else
    echo -e "  ${GREEN}No logging module usage found${NC}"
fi

# 5. Dead code (autoflake)
echo -e "${BLUE}[5/17]${NC} Checking for dead code..."
if check_tool autoflake; then
    autoflake --check --remove-all-unused-imports --remove-unused-variables \
        "$MODULE_PATH" > "$REPORT_DIR/dead_code.txt" 2>&1 || true
    DEAD_CODE=$(grep -c "would remove" "$REPORT_DIR/dead_code.txt" 2>/dev/null | tr -d ' ' || echo "0")
    DEAD_CODE=${DEAD_CODE:-0}
    if [ "$DEAD_CODE" -gt 0 ] 2>/dev/null; then
        echo -e "  ${YELLOW}Found dead code in $DEAD_CODE files${NC}"
        TOTAL_ISSUES=$((TOTAL_ISSUES + DEAD_CODE))
    else
        echo -e "  ${GREEN}No dead code found${NC}"
    fi
else
    echo "  Skipped" > "$REPORT_DIR/dead_code.txt"
fi

# 6. Black formatting
echo -e "${BLUE}[6/17]${NC} Checking Black formatting..."
if check_tool black; then
    black --check --line-length 100 "$MODULE_PATH" > "$REPORT_DIR/black.txt" 2>&1 || true
    BLACK_ISSUES=$(grep -c "would reformat" "$REPORT_DIR/black.txt" 2>/dev/null || echo "0")
    if [ "$BLACK_ISSUES" -gt 0 ]; then
        echo -e "  ${YELLOW}Found $BLACK_ISSUES files need reformatting${NC}"
        TOTAL_ISSUES=$((TOTAL_ISSUES + BLACK_ISSUES))
    else
        echo -e "  ${GREEN}All files properly formatted${NC}"
    fi
else
    echo "  Skipped" > "$REPORT_DIR/black.txt"
fi

# 7. Flake8 style
echo -e "${BLUE}[7/17]${NC} Running Flake8..."
if check_tool flake8; then
    flake8 --max-line-length=100 --ignore=E203,E501,W503 \
        --per-file-ignores="__init__.py:F401" \
        "$MODULE_PATH" > "$REPORT_DIR/flake8.txt" 2>&1 || true
    FLAKE8_ISSUES=$(wc -l < "$REPORT_DIR/flake8.txt" | tr -d ' ')
    if [ "$FLAKE8_ISSUES" -gt 0 ]; then
        echo -e "  ${YELLOW}Found $FLAKE8_ISSUES style issues${NC}"
        TOTAL_ISSUES=$((TOTAL_ISSUES + FLAKE8_ISSUES))
    else
        echo -e "  ${GREEN}No style issues found${NC}"
    fi
else
    echo "  Skipped" > "$REPORT_DIR/flake8.txt"
fi

# 8. Bandit security
echo -e "${BLUE}[8/17]${NC} Running Bandit security scan..."
if check_tool bandit; then
    bandit -r "$MODULE_PATH" --exclude B101,B404,B603,B607 \
        -f txt > "$REPORT_DIR/bandit.txt" 2>&1 || true
    BANDIT_ISSUES=$(grep -c "Issue:" "$REPORT_DIR/bandit.txt" 2>/dev/null || echo "0")
    if [ "$BANDIT_ISSUES" -gt 0 ]; then
        echo -e "  ${YELLOW}Found $BANDIT_ISSUES security issues${NC}"
        TOTAL_ISSUES=$((TOTAL_ISSUES + BANDIT_ISSUES))
    else
        echo -e "  ${GREEN}No security issues found${NC}"
    fi
else
    echo "  Skipped" > "$REPORT_DIR/bandit.txt"
fi

# 9. MyPy type checking
echo -e "${BLUE}[9/17]${NC} Running MyPy..."
if check_tool mypy; then
    mypy "$MODULE_PATH" --ignore-missing-imports \
        > "$REPORT_DIR/mypy.txt" 2>&1 || true
    MYPY_ISSUES=$(grep -c "error:" "$REPORT_DIR/mypy.txt" 2>/dev/null || echo "0")
    if [ "$MYPY_ISSUES" -gt 0 ]; then
        echo -e "  ${YELLOW}Found $MYPY_ISSUES type errors${NC}"
        TOTAL_ISSUES=$((TOTAL_ISSUES + MYPY_ISSUES))
    else
        echo -e "  ${GREEN}No type errors found${NC}"
    fi
else
    echo "  Skipped" > "$REPORT_DIR/mypy.txt"
fi

# 10. Test coverage
echo -e "${BLUE}[10/17]${NC} Checking test coverage..."
TEST_DIR="tests/unit/${MODULE_NAME}"
INTEGRATION_TEST="tests/integration/test_${MODULE_NAME}_integration.py"
if [ -d "$TEST_DIR" ]; then
    TEST_COUNT=$(find "$TEST_DIR" -name "test_*.py" | wc -l)
    echo -e "  Found ${TEST_COUNT} test file(s) in $TEST_DIR"
    if check_tool pytest; then
        pytest "$TEST_DIR" --cov="$MODULE_PATH" \
            --cov-report=term-missing --tb=no > "$REPORT_DIR/coverage.txt" 2>&1 || true

        # Parse test results (passed, failed, skipped) - look for "X passed" or "X failed" pattern
        TEST_SUMMARY=$(grep -E "[0-9]+ (passed|failed|skipped|error)" "$REPORT_DIR/coverage.txt" 2>/dev/null | tail -1)
        PASSED=$(echo "$TEST_SUMMARY" | grep -oE "[0-9]+ passed" | grep -oE "[0-9]+" || echo "0")
        FAILED=$(echo "$TEST_SUMMARY" | grep -oE "[0-9]+ failed" | grep -oE "[0-9]+" || echo "0")
        SKIPPED=$(echo "$TEST_SUMMARY" | grep -oE "[0-9]+ skipped" | grep -oE "[0-9]+" || echo "0")
        ERRORS=$(echo "$TEST_SUMMARY" | grep -oE "[0-9]+ error" | grep -oE "[0-9]+" || echo "0")

        # Report test results
        if [ "$FAILED" -gt 0 ] 2>/dev/null; then
            echo -e "  ${RED}CRITICAL: Tests: ${PASSED} passed, ${FAILED} failed, ${SKIPPED} skipped${NC}"
            CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        elif [ "$ERRORS" -gt 0 ] 2>/dev/null; then
            echo -e "  ${RED}CRITICAL: Tests: ${PASSED} passed, ${ERRORS} errors, ${SKIPPED} skipped${NC}"
            CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        elif [ "$SKIPPED" -gt 0 ] 2>/dev/null; then
            echo -e "  ${YELLOW}Tests: ${PASSED} passed, ${SKIPPED} skipped${NC}"
        elif [ "$PASSED" -gt 0 ] 2>/dev/null; then
            echo -e "  ${GREEN}Tests: ${PASSED} passed${NC}"
        fi

        # Parse coverage
        COVERAGE=$(grep "TOTAL" "$REPORT_DIR/coverage.txt" 2>/dev/null | awk '{print $NF}' | tr -d '%' || echo "0")
        if [ -n "$COVERAGE" ] && [ "$COVERAGE" != "0" ]; then
            if [ "$COVERAGE" -lt 70 ]; then
                echo -e "  ${RED}CRITICAL: Coverage: ${COVERAGE}% (below 70% threshold)${NC}"
                TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
                CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
            else
                echo -e "  ${GREEN}Coverage: ${COVERAGE}%${NC}"
            fi
        else
            echo -e "  ${YELLOW}Could not determine coverage${NC}"
        fi
    else
        echo "  pytest not available" > "$REPORT_DIR/coverage.txt"
    fi
    # Check for integration test
    if [ -f "$INTEGRATION_TEST" ]; then
        echo -e "  ${GREEN}Integration test found: $INTEGRATION_TEST${NC}"
    else
        echo -e "  ${YELLOW}No integration test at $INTEGRATION_TEST${NC}"
    fi
else
    echo -e "  ${YELLOW}WARNING: No test directory found at $TEST_DIR${NC}"
    echo "WARNING: No test directory found at $TEST_DIR" > "$REPORT_DIR/coverage.txt"
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
fi

# 11. Pattern checks
echo -e "${BLUE}[11/17]${NC} Running pattern checks..."
{
    echo "=== Bare except clauses (use 'except Exception:' minimum) ==="
    grep -rn "except:" "$MODULE_PATH" 2>/dev/null | grep -v "\.pyc" || echo "  None found"
    echo ""
    echo "=== TODO/FIXME/HACK comments ==="
    grep -rn "TODO\|FIXME\|HACK" "$MODULE_PATH" 2>/dev/null | grep -v "\.pyc" || echo "  None found"
    echo ""
    echo "=== eval/exec usage (security risk) ==="
    grep -rn "eval(\|exec(" "$MODULE_PATH" 2>/dev/null | grep -v "\.pyc" || echo "  None found"
    echo ""
    echo "=== Hardcoded credentials (security risk) ==="
    grep -rn "password\s*=\s*[\"']\|api_key\s*=\s*[\"']\|secret\s*=\s*[\"']" "$MODULE_PATH" 2>/dev/null \
        | grep -v "\.pyc\|# noqa\|default\|None\|''\|\"\"" || echo "  None found"
    echo ""
    echo "=== Assert statements (use proper validation) ==="
    grep -rn "^\s*assert\s" "$MODULE_PATH" 2>/dev/null | grep -v "\.pyc\|test_" || echo "  None found"
    echo ""
    echo "=== AI-generated hints (remove before commit) ==="
    grep -rni "generated by\|generated with\|written by ai\|ai-generated\|chatgpt\|claude\|copilot\|gpt-4\|gpt-3" "$MODULE_PATH" 2>/dev/null \
        | grep -v "\.pyc" || echo "  None found"
    echo ""
    echo "=== Global keyword usage (breaks thread safety) ==="
    grep -rn "^\s*global\s" "$MODULE_PATH" 2>/dev/null | grep -v "\.pyc" || echo "  None found"
    echo ""
    echo "=== Consecutive logger calls (potential spam) ==="
    # Find files with 3+ consecutive self.logger calls (potential spam)
    for file in $(find "$MODULE_PATH" -name "*.py" 2>/dev/null); do
        awk '/self\.logger\.(display|success|fail|warning)/{count++; if(count>=3) print FILENAME":"NR": potential log spam (3+ consecutive)"; next} {count=0}' "$file" 2>/dev/null
    done || echo "  None found"
} > "$REPORT_DIR/patterns.txt" 2>&1

BARE_EXCEPT=$(grep -c "except:" "$MODULE_PATH" 2>/dev/null | head -1 | tr -d ' ' || echo "0")
BARE_EXCEPT=${BARE_EXCEPT:-0}
if [ "$BARE_EXCEPT" -gt 0 ] 2>/dev/null; then
    echo -e "  ${YELLOW}Found bare except clauses${NC}"
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
fi

EVAL_EXEC=$(grep -rc "eval(\|exec(" "$MODULE_PATH" 2>/dev/null | grep -v ":0$" | wc -l | tr -d ' ' || echo "0")
EVAL_EXEC=${EVAL_EXEC:-0}
if [ "$EVAL_EXEC" -gt 0 ] 2>/dev/null; then
    echo -e "  ${RED}CRITICAL: Found eval/exec usage${NC}"
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + EVAL_EXEC))
fi

AI_HINTS=$(grep -rci "generated by\|generated with\|written by ai\|ai-generated\|chatgpt\|claude\|copilot\|gpt-4\|gpt-3" "$MODULE_PATH" 2>/dev/null | grep -v ":0$" | wc -l | tr -d ' ' || echo "0")
AI_HINTS=${AI_HINTS:-0}
if [ "$AI_HINTS" -gt 0 ] 2>/dev/null; then
    echo -e "  ${YELLOW}Found AI-generated hints (remove before commit)${NC}"
    TOTAL_ISSUES=$((TOTAL_ISSUES + AI_HINTS))
fi

GLOBAL_USAGE=$(grep -rc "^\s*global\s" "$MODULE_PATH" 2>/dev/null | grep -v ":0$" | wc -l | tr -d ' ' || echo "0")
GLOBAL_USAGE=${GLOBAL_USAGE:-0}
if [ "$GLOBAL_USAGE" -gt 0 ] 2>/dev/null; then
    echo -e "  ${RED}CRITICAL: Found 'global' keyword (breaks thread safety)${NC}"
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + GLOBAL_USAGE))
else
    echo -e "  ${GREEN}Pattern checks passed${NC}"
fi

# 12. CLI options check
echo -e "${BLUE}[12/17]${NC} Checking CLI options..."
PROTO_ARGS="$MODULE_PATH/proto_args.py"
if [ -f "$PROTO_ARGS" ]; then
    {
        echo "=== Required CLI options check ==="
        echo ""
        grep -q "target\|positional" "$PROTO_ARGS" 2>/dev/null && echo "target: FOUND" || echo "target: MISSING"
        grep -q "\-\-port\|'-p'" "$PROTO_ARGS" 2>/dev/null && echo "--port: FOUND" || echo "--port: MISSING"
        grep -q "\-\-timeout" "$PROTO_ARGS" 2>/dev/null && echo "--timeout: FOUND" || echo "--timeout: MISSING"
        grep -q "\-\-confirm" "$PROTO_ARGS" 2>/dev/null && echo "--confirm: FOUND" || echo "--confirm: MISSING"
        grep -q "\-\-output\|'-o'" "$PROTO_ARGS" 2>/dev/null && echo "--output: FOUND" || echo "--output: MISSING"
        echo ""
        echo "=== Short flag consistency check ==="
        echo "Standard: -p=port, -t=timeout, -o=output, -u=user, -P=password, -i=interface, -T=threads"
        echo ""
        # Check for conflicting short flags
        grep -n "'-p'.*password\|'-t'.*thread\|'-u'.*port\|'-i'.*input" "$PROTO_ARGS" 2>/dev/null && echo "WARNING: Conflicting short flags found!" || echo "  No conflicts found"
        echo ""
        echo "=== add_common_args usage ==="
        grep -n "add_common_args" "$PROTO_ARGS" 2>/dev/null && echo "add_common_args: FOUND" || echo "add_common_args: MISSING (should use central function)"
    } > "$REPORT_DIR/cli_options.txt"

    MISSING_OPTS=$(grep -c "MISSING" "$REPORT_DIR/cli_options.txt" 2>/dev/null | tr -d ' ' || echo "0")
    MISSING_OPTS=${MISSING_OPTS:-0}
    if [ "$MISSING_OPTS" -gt 0 ] 2>/dev/null; then
        echo -e "  ${YELLOW}Missing $MISSING_OPTS required CLI options${NC}"
        TOTAL_ISSUES=$((TOTAL_ISSUES + MISSING_OPTS))
    else
        echo -e "  ${GREEN}All required CLI options present${NC}"
    fi
else
    echo -e "  ${YELLOW}WARNING: No proto_args.py found${NC}"
    echo "WARNING: No proto_args.py found" > "$REPORT_DIR/cli_options.txt"
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
fi

# 13. File size check
# Exclude constants.py/const.py - these legitimately contain large data definitions
echo -e "${BLUE}[13/17]${NC} Checking file sizes..."
{
    echo "=== File size check (>1000 lines should be split) ==="
    echo "Note: constants.py/const.py excluded (data definitions allowed)"
    echo ""
    find "$MODULE_PATH" -name "*.py" ! -name "constants.py" ! -name "const.py" -exec wc -l {} \; 2>/dev/null | sort -rn | while read lines file; do
        if [ "$lines" -gt 1500 ]; then
            echo "MUST SPLIT: $file ($lines lines)"
        elif [ "$lines" -gt 1000 ]; then
            echo "SHOULD SPLIT: $file ($lines lines)"
        elif [ "$lines" -gt 500 ]; then
            echo "REVIEW: $file ($lines lines)"
        else
            echo "OK: $file ($lines lines)"
        fi
    done
} > "$REPORT_DIR/file_sizes.txt"

LARGE_FILES=$(find "$MODULE_PATH" -name "*.py" ! -name "constants.py" ! -name "const.py" -exec sh -c 'lines=$(wc -l < "$1"); [ "$lines" -gt 1000 ] && echo "$1"' _ {} \; 2>/dev/null | wc -l | tr -d ' ')
LARGE_FILES=${LARGE_FILES:-0}
if [ "$LARGE_FILES" -gt 0 ] 2>/dev/null; then
    echo -e "  ${YELLOW}Found $LARGE_FILES files over 1000 lines (consider splitting)${NC}"
    TOTAL_ISSUES=$((TOTAL_ISSUES + LARGE_FILES))
else
    echo -e "  ${GREEN}All files within size limits${NC}"
fi

# 14. Export utilities check
echo -e "${BLUE}[14/17]${NC} Checking export utilities usage..."
{
    echo "=== Export utilities check ==="
    echo ""
    echo "--- Required: export_table or get_export_path usage ---"
    grep -rn "export_table\|get_export_path" "$MODULE_PATH" 2>/dev/null | grep -v "\.pyc" || echo "  NOT FOUND - module should use export_utils"
    echo ""
    echo "--- Forbidden: Custom file writes (open with 'w') ---"
    grep -rn "open(.*['\"]w['\"])\|open(.*mode.*=.*['\"]w\|\.write_text(\|\.write_bytes(" "$MODULE_PATH" 2>/dev/null \
        | grep -v "\.pyc\|get_export_path\|# noqa" || echo "  None found (good)"
    echo ""
    echo "--- Forbidden: Direct file path construction ---"
    grep -rn "with open(\|Path(.*\.write" "$MODULE_PATH" 2>/dev/null \
        | grep -v "\.pyc\|get_export_path\|# noqa\|args\.\|config\." || echo "  None found (good)"
} > "$REPORT_DIR/export_utils.txt"

# Check if export utilities are used
USES_EXPORT=$(grep -rc "export_table\|get_export_path" "$MODULE_PATH" 2>/dev/null | grep -v ":0$" | wc -l | tr -d ' ' || echo "0")
USES_EXPORT=${USES_EXPORT:-0}

# Check for custom file writes (forbidden)
CUSTOM_WRITES=$(grep -rn "open(.*['\"]w['\"])\|\.write_text(\|\.write_bytes(" "$MODULE_PATH" 2>/dev/null \
    | grep -v "\.pyc\|get_export_path\|# noqa" | wc -l | tr -d ' ' || echo "0")
CUSTOM_WRITES=${CUSTOM_WRITES:-0}

if [ "$CUSTOM_WRITES" -gt 0 ] 2>/dev/null; then
    echo -e "  ${YELLOW}Found $CUSTOM_WRITES custom file writes (use export_table/get_export_path)${NC}"
    TOTAL_ISSUES=$((TOTAL_ISSUES + CUSTOM_WRITES))
elif [ "$USES_EXPORT" -eq 0 ] 2>/dev/null; then
    echo -e "  ${YELLOW}No export_table/get_export_path usage found${NC}"
else
    echo -e "  ${GREEN}Export utilities used correctly${NC}"
fi

# 15. Connection handling check (no redundant sockets with protocol libs)
echo -e "${BLUE}[15/17]${NC} Checking connection handling..."
{
    echo "=== Connection handling check ==="
    echo ""
    echo "--- Protocol library imports ---"
    grep -rn "from pymodbus\|from asyncua\|from snap7\|import pyads\|from c104\|from xknx\|from cpppo" "$MODULE_PATH" 2>/dev/null \
        | grep -v "\.pyc" || echo "  No third-party protocol libraries found"
    echo ""
    echo "--- Raw socket usage ---"
    grep -rn "socket\.socket\|socket\.AF_INET\|socket\.SOCK_STREAM\|socket\.SOCK_DGRAM" "$MODULE_PATH" 2>/dev/null \
        | grep -v "\.pyc" || echo "  No raw socket usage found"
    echo ""
    echo "--- Potential redundancy (both library AND raw sockets) ---"
} > "$REPORT_DIR/connection_handling.txt"

# Check for redundant socket usage (has both protocol lib and raw sockets)
HAS_PROTO_LIB=$(grep -rl "from pymodbus\|from asyncua\|from snap7\|import pyads\|from c104\|from xknx\|from cpppo" "$MODULE_PATH" 2>/dev/null | grep -v "\.pyc" | wc -l | tr -d ' ' || echo "0")
HAS_RAW_SOCKET=$(grep -rl "socket\.socket\|\.connect(\|\.send(\|\.recv(" "$MODULE_PATH" 2>/dev/null | grep -v "\.pyc" | wc -l | tr -d ' ' || echo "0")
HAS_PROTO_LIB=${HAS_PROTO_LIB:-0}
HAS_RAW_SOCKET=${HAS_RAW_SOCKET:-0}

if [ "$HAS_PROTO_LIB" -gt 0 ] && [ "$HAS_RAW_SOCKET" -gt 0 ] 2>/dev/null; then
    echo -e "  ${YELLOW}Found both protocol library AND raw sockets (review for redundancy)${NC}"
    echo "WARNING: Module uses both protocol library and raw sockets - review for redundancy" >> "$REPORT_DIR/connection_handling.txt"
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
else
    echo -e "  ${GREEN}Connection handling OK${NC}"
fi

# 16. Protocol debug logging check (for in-house protocols)
echo -e "${BLUE}[16/17]${NC} Checking protocol debug logging..."
{
    echo "=== Protocol debug logging check ==="
    echo ""
    echo "In-house protocols (profinet, codesys, mms, tase2) must log TX/RX packets"
    echo ""
    echo "--- TX (send) debug logging ---"
    grep -rn "debug.*TX\|debug.*send\|debug.*->.*hex\|logger\.debug.*\.hex()" "$MODULE_PATH" 2>/dev/null \
        | grep -v "\.pyc" || echo "  No TX debug logging found"
    echo ""
    echo "--- RX (receive) debug logging ---"
    grep -rn "debug.*RX\|debug.*recv\|debug.*<-.*hex\|debug.*received.*hex" "$MODULE_PATH" 2>/dev/null \
        | grep -v "\.pyc" || echo "  No RX debug logging found"
    echo ""
    echo "--- Parse status/error logging ---"
    grep -rn "debug.*[Pp]ars\|debug.*unpack\|debug.*decode" "$MODULE_PATH" 2>/dev/null \
        | grep -v "\.pyc" || echo "  No parse debug logging found"
} > "$REPORT_DIR/protocol_debug.txt"

# Check if this is an in-house protocol that requires debug logging
INHOUSE_PROTOCOLS="profinet|codesys|mms|tase2|iec61850"
IS_INHOUSE=$(echo "$MODULE_NAME" | grep -iE "$INHOUSE_PROTOCOLS" | wc -l | tr -d ' ')
IS_INHOUSE=${IS_INHOUSE:-0}

if [ "$IS_INHOUSE" -gt 0 ] 2>/dev/null; then
    # Check for TX/RX debug logging
    HAS_TX_LOG=$(grep -rc "debug.*TX\|debug.*send\|debug.*\.hex()" "$MODULE_PATH" 2>/dev/null | grep -v ":0$" | wc -l | tr -d ' ' || echo "0")
    HAS_RX_LOG=$(grep -rc "debug.*RX\|debug.*recv\|debug.*received" "$MODULE_PATH" 2>/dev/null | grep -v ":0$" | wc -l | tr -d ' ' || echo "0")
    HAS_TX_LOG=${HAS_TX_LOG:-0}
    HAS_RX_LOG=${HAS_RX_LOG:-0}

    if [ "$HAS_TX_LOG" -eq 0 ] || [ "$HAS_RX_LOG" -eq 0 ] 2>/dev/null; then
        echo -e "  ${YELLOW}In-house protocol missing TX/RX debug logging${NC}"
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
    else
        echo -e "  ${GREEN}Protocol debug logging present${NC}"
    fi
else
    echo -e "  ${GREEN}Not an in-house protocol (debug logging optional)${NC}"
fi

# 17. NXC architecture compliance check
echo -e "${BLUE}[17/17]${NC} Checking NXC architecture..."
INIT_FILE="$MODULE_PATH/__init__.py"
{
    echo "=== NXC Architecture compliance ==="
    echo ""
    echo "--- Class attributes (name, protocol_name, default_port) ---"
    grep -n "^\s*name\s*=\|^\s*protocol_name\s*=\|^\s*default_port\s*=" "$INIT_FILE" 2>/dev/null || echo "  NOT FOUND"
    echo ""
    echo "--- proto_logger() call in proto_flow ---"
    grep -n "proto_logger\|self\.proto_logger()" "$INIT_FILE" 2>/dev/null || echo "  NOT FOUND"
    echo ""
    echo "--- create_conn_obj method ---"
    grep -n "def create_conn_obj" "$INIT_FILE" 2>/dev/null || echo "  NOT FOUND"
    echo ""
    echo "--- self.results usage ---"
    grep -n "self\.results\[" "$INIT_FILE" 2>/dev/null || echo "  NOT FOUND"
} > "$REPORT_DIR/nxc_architecture.txt"

if [ -f "$INIT_FILE" ]; then
    NXC_ISSUES=0

    # Check for class attributes
    HAS_NAME=$(grep -c "^\s*name\s*=" "$INIT_FILE" 2>/dev/null || echo "0")
    HAS_DEFAULT_PORT=$(grep -c "^\s*default_port\s*=" "$INIT_FILE" 2>/dev/null || echo "0")

    if [ "$HAS_NAME" -eq 0 ] || [ "$HAS_DEFAULT_PORT" -eq 0 ] 2>/dev/null; then
        echo -e "  ${YELLOW}Missing class attributes (name/default_port)${NC}"
        NXC_ISSUES=$((NXC_ISSUES + 1))
    fi

    # Check for proto_logger call
    HAS_PROTO_LOGGER=$(grep -c "proto_logger\|self\.proto_logger()" "$INIT_FILE" 2>/dev/null || echo "0")
    if [ "$HAS_PROTO_LOGGER" -eq 0 ] 2>/dev/null; then
        echo -e "  ${YELLOW}Missing proto_logger() call${NC}"
        NXC_ISSUES=$((NXC_ISSUES + 1))
    fi

    # Check for create_conn_obj
    HAS_CONN_OBJ=$(grep -c "def create_conn_obj" "$INIT_FILE" 2>/dev/null || echo "0")
    if [ "$HAS_CONN_OBJ" -eq 0 ] 2>/dev/null; then
        echo -e "  ${YELLOW}Missing create_conn_obj() method${NC}"
        NXC_ISSUES=$((NXC_ISSUES + 1))
    fi

    if [ "$NXC_ISSUES" -gt 0 ] 2>/dev/null; then
        TOTAL_ISSUES=$((TOTAL_ISSUES + NXC_ISSUES))
    else
        echo -e "  ${GREEN}NXC architecture compliant${NC}"
    fi
else
    echo -e "  ${YELLOW}No __init__.py found${NC}"
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
fi

# Generate summary
echo ""
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  SUMMARY${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo "Reports saved to: $REPORT_DIR/"
echo ""
echo "Issue counts:"
echo "  Local imports: $LOCAL_IMPORTS"
echo "  Fallback imports: $FALLBACKS (CRITICAL)"
echo "  Print statements: $PRINTS (CRITICAL)"
echo "  Logging module: $LOGGING"
echo "  Large files (>1000 lines): $LARGE_FILES"
echo "  Custom file writes: $CUSTOM_WRITES"
echo "  AI-generated hints: $AI_HINTS"
echo "  Global keyword: $GLOBAL_USAGE (CRITICAL)"
echo ""
echo "Total issues: $TOTAL_ISSUES"
echo "Critical issues: $CRITICAL_ISSUES"

# Exit with error if critical issues
if [ "$CRITICAL_ISSUES" -gt 0 ]; then
    echo ""
    echo -e "${RED}======================================${NC}"
    echo -e "${RED}  REVIEW FAILED: Critical issues found${NC}"
    echo -e "${RED}======================================${NC}"
    echo ""
    echo "Critical issues must be fixed before merge:"
    if [ "$FALLBACKS" -gt 0 ]; then
        echo "  - Replace try/except ImportError with lazy_import()"
    fi
    if [ "$PRINTS" -gt 0 ]; then
        echo "  - Replace print() with self.logger.display/success/fail()"
    fi
    if [ "$EVAL_EXEC" -gt 0 ]; then
        echo "  - Remove eval/exec usage (security risk)"
    fi
    if [ "$GLOBAL_USAGE" -gt 0 ]; then
        echo "  - Remove 'global' keyword (breaks thread safety, use class attributes)"
    fi
    exit 1
fi

if [ "$TOTAL_ISSUES" -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}======================================${NC}"
    echo -e "${YELLOW}  REVIEW PASSED WITH WARNINGS${NC}"
    echo -e "${YELLOW}======================================${NC}"
    echo ""
    echo "Please review the reports and address warnings."
    exit 0
fi

echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}  REVIEW PASSED${NC}"
echo -e "${GREEN}======================================${NC}"
exit 0
