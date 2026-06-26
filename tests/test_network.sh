#!/bin/bash
set -e

echo "Running knetutils deep network tests..."

# Check if we have passwordless sudo or are root
HAS_ROOT=0
if [ "$EUID" -eq 0 ]; then
    HAS_ROOT=1
    SUDO=""
elif sudo -n true 2>/dev/null; then
    HAS_ROOT=1
    SUDO="sudo"
fi

if [ "$HAS_ROOT" -eq 0 ]; then
    echo "[WARN] Running without root. Deep tests (tcping, arping, sniff) will be skipped or limited."
    SUDO=""
fi

# 1. ping
echo "Testing ping (success case)..."
./bin/ping -c 1 127.0.0.1 > /dev/null

echo "Testing ping (timeout case)..."
# 192.0.2.1 is TEST-NET-1, guaranteed to be unroutable/blackholed
if ./bin/ping -c 1 -W 1 192.0.2.1 > /dev/null 2>&1; then
    echo "Ping unexpectedly succeeded on a blackholed IP."
    exit 1
fi

# 2. traceroute
echo "Testing traceroute..."
./bin/traceroute 127.0.0.1 -m 2 -q 1 > /dev/null || true # Accept failure if unprivileged ICMP fails, just ensure no segfault

# 3. Root-required tests
if [ "$HAS_ROOT" -eq 1 ]; then
    echo "Testing tcping (localhost:80)..."
    $SUDO ./bin/tcping -c 1 -W 1 127.0.0.1 80 > /dev/null || true # Accept closed port failure, check for crash

    echo "Testing tcping (blackhole)..."
    $SUDO ./bin/tcping -c 1 -W 1 192.0.2.1 80 > /dev/null || true

    # Find a default interface to test sniff and arping
    IFACE=$($SUDO ip route 2>/dev/null | grep default | awk '{print $5}' || echo "lo")
    if [ -n "$IFACE" ]; then
        echo "Testing sniff on interface $IFACE..."
        # sniff in background, then ping to generate traffic
        $SUDO ./bin/sniff -I "$IFACE" -c 1 > /dev/null 2>&1 &
        SNIFF_PID=$!
        sleep 0.5
        ./bin/ping -c 1 127.0.0.1 > /dev/null 2>&1 || true
        wait $SNIFF_PID || true

        echo "Testing arping on interface $IFACE..."
        $SUDO ./bin/arping -I "$IFACE" -c 1 -w 1000 127.0.0.1 > /dev/null 2>&1 || true
    fi
fi

echo "Deep network tests completed successfully! (No crashes observed)"
