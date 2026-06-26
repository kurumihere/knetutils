#!/bin/bash
set -e

echo "Running knetutils basic tests..."

./bin/knetutils --help > /dev/null 2>&1 || true

TOOLS=("arping" "ping" "sniff" "tcping" "traceroute" "pscan")

for tool in "${TOOLS[@]}"; do
    echo "Testing $tool help menu..."
    ./bin/$tool -h > /dev/null 2>&1 || { echo "$tool -h failed"; exit 1; }
    
    echo "Testing $tool without arguments..."
    if ./bin/$tool > /dev/null 2>&1; then
        echo "$tool unexpectedly succeeded without arguments"
        exit 1
    fi
done

echo "Basic tests passed! (No segmentation faults during help execution)"
