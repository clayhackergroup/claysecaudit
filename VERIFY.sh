#!/bin/bash

# Clay Sec Audit - Verification Script
# Checks that all project files are in place

echo "============================================"
echo "Clay Sec Audit - Build Verification"
echo "============================================"
echo

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check counters
TOTAL=0
PASSED=0

# Function to check file
check_file() {
    TOTAL=$((TOTAL + 1))
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} $1"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗${NC} $1 (MISSING)"
    fi
}

# Function to check directory
check_dir() {
    TOTAL=$((TOTAL + 1))
    if [ -d "$1" ]; then
        echo -e "${GREEN}✓${NC} $1/"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗${NC} $1/ (MISSING)"
    fi
}

echo "Checking directory structure..."
check_dir "src"
check_dir "src/scanner"
check_dir "src/fix_engine"
check_dir "src/reports"
check_dir "src/cli"
check_dir "src/dashboard"
check_dir "tests"
check_dir "docs"
echo

echo "Checking scanner modules..."
check_file "src/scanner/__init__.py"
check_file "src/scanner/utils.py"
check_file "src/scanner/ports.py"
check_file "src/scanner/ssh.py"
check_file "src/scanner/nginx.py"
check_file "src/scanner/apache.py"
check_file "src/scanner/filesystem.py"
check_file "src/scanner/db.py"
check_file "src/scanner/api_scanner.py"
echo

echo "Checking fix engine modules..."
check_file "src/fix_engine/__init__.py"
check_file "src/fix_engine/backup.py"
check_file "src/fix_engine/rollback.py"
check_file "src/fix_engine/ssh_fix.py"
check_file "src/fix_engine/nginx_fix.py"
check_file "src/fix_engine/apache_fix.py"
check_file "src/fix_engine/db_fix.py"
check_file "src/fix_engine/permissions_fix.py"
echo

echo "Checking reporting modules..."
check_file "src/reports/__init__.py"
check_file "src/reports/json_export.py"
check_file "src/reports/pdf_generator.py"
echo

echo "Checking interface modules..."
check_file "src/cli/__init__.py"
check_file "src/cli/cli.py"
check_file "src/dashboard/__init__.py"
check_file "src/dashboard/api.py"
echo

echo "Checking test modules..."
check_file "tests/__init__.py"
check_file "tests/test_scanners.py"
check_file "tests/test_fix_engine.py"
echo

echo "Checking documentation..."
check_file "README.md"
check_file "QUICKSTART.md"
check_file "PROJECT_SUMMARY.md"
check_file "BUILD_COMPLETE.txt"
check_file "docs/installation.md"
check_file "docs/usage.md"
check_file "docs/architecture.md"
check_file "docs/API.md"
echo

echo "Checking configuration files..."
check_file "setup.py"
check_file "requirements.txt"
check_file "LICENSE"
check_file ".gitignore"
echo

echo "Verifying Python syntax..."
python3 -m py_compile src/**/*.py 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} All Python files are syntactically correct"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗${NC} Python syntax errors found"
fi
TOTAL=$((TOTAL + 1))
echo

# Summary
echo "============================================"
echo "Verification Summary"
echo "============================================"
echo -e "Files checked: $TOTAL"
echo -e "Files found: ${GREEN}$PASSED${NC}"
if [ $PASSED -eq $TOTAL ]; then
    echo -e "${GREEN}Status: BUILD COMPLETE ✓${NC}"
    exit 0
else
    MISSING=$((TOTAL - PASSED))
    echo -e "${RED}Status: $MISSING files missing${NC}"
    exit 1
fi
