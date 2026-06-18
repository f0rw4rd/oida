#!/bin/bash
# Code Quality Check Script for MSF-ICS
# Runs flake8, black, mypy, bandit, and other static analysis tools

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Output directory for reports
REPORT_DIR="$PROJECT_ROOT/code_quality_reports"
mkdir -p "$REPORT_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  MSF-ICS Code Quality Analysis${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Track overall status
OVERALL_STATUS=0

# Function to run a tool
run_tool() {
    local tool_name="$1"
    local command="$2"
    local report_file="$3"

    echo -e "${YELLOW}[$tool_name]${NC} Running..."

    if eval "$command" > "$REPORT_DIR/$report_file" 2>&1; then
        echo -e "${GREEN}[$tool_name]${NC} Passed"
        return 0
    else
        echo -e "${RED}[$tool_name]${NC} Issues found - see $REPORT_DIR/$report_file"
        OVERALL_STATUS=1
        return 1
    fi
}

# Function to run a tool and show output
run_tool_verbose() {
    local tool_name="$1"
    local command="$2"
    local report_file="$3"

    echo -e "${YELLOW}[$tool_name]${NC} Running..."

    if eval "$command" 2>&1 | tee "$REPORT_DIR/$report_file"; then
        if [ ${PIPESTATUS[0]} -eq 0 ]; then
            echo -e "${GREEN}[$tool_name]${NC} Passed"
            return 0
        fi
    fi
    echo -e "${RED}[$tool_name]${NC} Issues found"
    OVERALL_STATUS=1
    return 1
}

echo -e "${BLUE}[1/7] Checking tool availability...${NC}"
echo ""

# Check for required tools
TOOLS_MISSING=0
for tool in flake8 black mypy bandit autoflake isort pylint; do
    if command -v $tool &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${RED}✗${NC} $tool (not installed)"
        TOOLS_MISSING=1
    fi
done

if [ $TOOLS_MISSING -eq 1 ]; then
    echo ""
    echo -e "${YELLOW}Install missing tools with:${NC}"
    echo "  pip install flake8 black mypy bandit autoflake isort pylint"
    echo ""
fi

echo ""
echo -e "${BLUE}[2/7] Running Black (code formatting check)...${NC}"
echo ""

# Black - Check formatting without modifying
black --check --diff --line-length 100 msf_ics/ tests/ 2>&1 | head -100 | tee "$REPORT_DIR/black.txt" || {
    echo -e "${RED}Black found formatting issues${NC}"
    OVERALL_STATUS=1
}

echo ""
echo -e "${BLUE}[3/7] Running Flake8 (style guide enforcement)...${NC}"
echo ""

# Flake8 - Style checking
flake8 msf_ics/ tests/ \
    --max-line-length=100 \
    --extend-ignore=E203,E501,W503 \
    --per-file-ignores="__init__.py:F401" \
    --statistics \
    --count \
    2>&1 | tee "$REPORT_DIR/flake8.txt" || {
    echo -e "${YELLOW}Flake8 found issues (see above)${NC}"
    OVERALL_STATUS=1
}

echo ""
echo -e "${BLUE}[4/7] Running Autoflake (unused imports/variables)...${NC}"
echo ""

# Autoflake - Check for unused imports and variables
autoflake --check --recursive \
    --remove-all-unused-imports \
    --remove-unused-variables \
    --ignore-init-module-imports \
    msf_ics/ 2>&1 | head -50 | tee "$REPORT_DIR/autoflake.txt" || {
    echo -e "${YELLOW}Autoflake found unused imports/variables${NC}"
    OVERALL_STATUS=1
}

echo ""
echo -e "${BLUE}[5/7] Running Bandit (security linting)...${NC}"
echo ""

# Bandit - Security linting
bandit -r msf_ics/ \
    -ll \
    --skip B101,B404,B603,B607 \
    -f txt \
    2>&1 | tee "$REPORT_DIR/bandit.txt" || {
    echo -e "${YELLOW}Bandit found security issues${NC}"
    OVERALL_STATUS=1
}

echo ""
echo -e "${BLUE}[6/7] Running custom pattern checks...${NC}"
echo ""

# Custom pattern checks
echo "Checking for common anti-patterns..."

# Check for bare except clauses
echo -e "\n${YELLOW}Bare 'except:' clauses (should use specific exceptions):${NC}"
grep -rn "except:" msf_ics/ --include="*.py" | grep -v "except Exception" | grep -v "except:" | head -20 || echo "  None found (grep pattern issue)"
grep -rn "^[[:space:]]*except:[[:space:]]*$" msf_ics/ --include="*.py" | tee -a "$REPORT_DIR/patterns.txt" | head -20

# Check for TODO/FIXME/HACK comments
echo -e "\n${YELLOW}TODO/FIXME/HACK comments:${NC}"
grep -rn -E "(TODO|FIXME|HACK|XXX)" msf_ics/ --include="*.py" | tee -a "$REPORT_DIR/patterns.txt" | head -20

# Check for print statements (should use logging)
echo -e "\n${YELLOW}Print statements (consider using logging):${NC}"
grep -rn "^[[:space:]]*print(" msf_ics/ --include="*.py" | grep -v "# noqa" | tee -a "$REPORT_DIR/patterns.txt" | head -20

# Check for hardcoded credentials patterns
echo -e "\n${YELLOW}Potential hardcoded credentials:${NC}"
grep -rn -iE "(password|passwd|secret|api_key|apikey)[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]" msf_ics/ --include="*.py" | grep -v "help=" | grep -v "#" | tee -a "$REPORT_DIR/patterns.txt" | head -10

# Check for eval/exec usage
echo -e "\n${YELLOW}eval/exec usage (security risk):${NC}"
grep -rn -E "\b(eval|exec)\s*\(" msf_ics/ --include="*.py" | tee -a "$REPORT_DIR/patterns.txt" | head -10

# Check for assert statements (disabled in optimized mode)
echo -e "\n${YELLOW}Assert statements (disabled with -O flag):${NC}"
grep -rn "^[[:space:]]*assert " msf_ics/ --include="*.py" | tee -a "$REPORT_DIR/patterns.txt" | wc -l | xargs echo "  Count:"

echo ""
echo -e "${BLUE}[7/7] Running MyPy (type checking) - optional...${NC}"
echo ""

# MyPy - Type checking (may take a while and produce many errors)
if command -v mypy &> /dev/null; then
    mypy msf_ics/ \
        --ignore-missing-imports \
        --no-error-summary \
        --show-error-codes \
        2>&1 | head -100 | tee "$REPORT_DIR/mypy.txt" || {
        echo -e "${YELLOW}MyPy found type issues (see report)${NC}"
    }
else
    echo "MyPy not installed, skipping..."
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Reports saved to: $REPORT_DIR/"
ls -la "$REPORT_DIR/"
echo ""

if [ $OVERALL_STATUS -eq 0 ]; then
    echo -e "${GREEN}All checks passed!${NC}"
else
    echo -e "${YELLOW}Some checks found issues. Review the reports above.${NC}"
fi

exit $OVERALL_STATUS
