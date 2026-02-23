#!/bin/bash

# DDoSamurai Comprehensive Test Runner
# This script runs all tests in the test2 directory.

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting DDoSamurai Test Suite...${NC}"

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Warning: Not running as root. Some tests (Raw Sockets, C Extension) may fail or be skipped.${NC}"
fi

# Ensure project root is in PYTHONPATH
export PYTHONPATH=$PYTHONPATH:$(pwd)

# Run pytest
echo -e "${GREEN}Running pytest...${NC}"
pytest -v test2/

if [ $? -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed. Check the output above.${NC}"
    exit 1
fi
