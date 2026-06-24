#!/bin/bash
set -e

echo "Running knetutils basic tests..."

./bin/knetutils --help > /dev/null 2>&1 || true

TOOLS=("arping" "ping" "sniff" "tcping" "traceroute")

for tool in "${TOOLS[@]}"; do
    echo "Testing $tool help menu..."
    ./bin/$tool -h > /dev/null 2>&1 || { echo "$tool failed"; exit 1; }
done

echo "Basic tests passed! (No segmentation faults during help execution)"
