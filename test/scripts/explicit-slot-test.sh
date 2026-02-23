#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause-LBNL
#
# Test script for explicit slot routing.
#
# This script:
# 1. Starts a mock LB if EJFAT_URI is not set
# 2. Reserves a load balancer in explicit mode
# 3. Starts two receivers (one on slot 1, one on slot 2)
# 4. Sends 4 events: 2 to slot 1, 2 to slot 2
# 5. Cleans up on exit

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
UDPLBD="${UDPLBD:-$PROJECT_ROOT/target/debug/udplbd}"
MOCK_PID=""
RECV1_PID=""
RECV2_PID=""
RESERVATION_URI=""

# Cleanup function - frees reservation and kills background processes
cleanup() {
    echo ""
    echo "Cleaning up..."

    # Free the reservation if we have one
    if [ -n "$RESERVATION_URI" ]; then
        echo "Freeing reservation..."
        EJFAT_URI="$RESERVATION_URI" "$UDPLBD" client free 2>/dev/null || true
    fi

    # Kill receivers
    if [ -n "$RECV1_PID" ] && kill -0 "$RECV1_PID" 2>/dev/null; then
        echo "Stopping receiver 1 (PID $RECV1_PID)..."
        kill "$RECV1_PID" 2>/dev/null || true
    fi
    if [ -n "$RECV2_PID" ] && kill -0 "$RECV2_PID" 2>/dev/null; then
        echo "Stopping receiver 2 (PID $RECV2_PID)..."
        kill "$RECV2_PID" 2>/dev/null || true
    fi

    # Kill mock server if we started one
    if [ -n "$MOCK_PID" ] && kill -0 "$MOCK_PID" 2>/dev/null; then
        echo "Stopping mock server (PID $MOCK_PID)..."
        kill "$MOCK_PID" 2>/dev/null || true
    fi

    # Clean up temp files
    rm -f /tmp/udplbd-explicit-test.db
    rm -f /tmp/recv1-output.txt /tmp/recv2-output.txt

    echo "Cleanup complete."
}

# Set trap to cleanup on any exit
trap cleanup EXIT INT TERM

# Check if udplbd binary exists
if [ ! -x "$UDPLBD" ]; then
    echo "Error: udplbd binary not found at $UDPLBD"
    echo "Please build the project first: cargo build"
    exit 1
fi

# Start mock server if EJFAT_URI is not set
if [ -z "$EJFAT_URI" ]; then
    echo "EJFAT_URI not set, starting mock server..."

    "$UDPLBD" mock --db /tmp/udplbd-explicit-test.db &
    MOCK_PID=$!

    # Wait for mock server to be ready
    echo "Waiting for mock server to start..."
    for i in {1..30}; do
        if nc -z 127.0.0.1 19523 2>/dev/null; then
            echo "Mock server is ready."
            break
        fi
        if ! kill -0 "$MOCK_PID" 2>/dev/null; then
            echo "Error: Mock server died"
            exit 1
        fi
        sleep 0.5
    done

    if ! nc -z 127.0.0.1 19523 2>/dev/null; then
        echo "Error: Mock server did not start in time"
        exit 1
    fi

    # Set default URI for mock server
    EJFAT_URI="ejfat://udplbd2changeme@127.0.0.1:19523"
fi

echo "Using EJFAT_URI: $EJFAT_URI"
export EJFAT_URI

# Reserve load balancer in explicit mode
echo ""
echo "Reserving load balancer in explicit mode..."
RESERVE_OUTPUT=$("$UDPLBD" client reserve explicit-slot-test --strategy explicit --sender 127.0.0.1 --after "600s")
echo "$RESERVE_OUTPUT"

# Extract the EJFAT_URI from the output
RESERVATION_URI=$(echo "$RESERVE_OUTPUT" | grep "EJFAT_URI=" | sed "s/export 'EJFAT_URI=//;s/'$//")
if [ -z "$RESERVATION_URI" ]; then
    echo "Error: Failed to extract reservation URI"
    exit 1
fi
echo "Reservation URI: $RESERVATION_URI"
export EJFAT_URI="$RESERVATION_URI"

# Start receiver 1 on slot 1
echo ""
echo "Starting receiver 1 on slot 1..."
"$UDPLBD" dataplane recv \
    --address 127.0.0.1 \
    --port 20001 \
    --name recv1 \
    --slots "1-2" \
    -- cat > /tmp/recv1-output.txt 2>&1 &
RECV1_PID=$!
echo "Receiver 1 started (PID $RECV1_PID)"

# Start receiver 2 on slot 2 (slots 128-256)
echo "Starting receiver 2 on slot 2..."
"$UDPLBD" dataplane recv \
    --address 127.0.0.1 \
    --port 20002 \
    --name recv2 \
    --slots "2-3" \
    -- cat > /tmp/recv2-output.txt 2>&1 &
RECV2_PID=$!
echo "Receiver 2 started (PID $RECV2_PID)"

# Wait for receivers to register
echo "Waiting for receivers to register..."
sleep 3

# Show overview
echo ""
echo "Load balancer overview:"
"$UDPLBD" client overview

# Send events
echo ""
echo "Sending events..."

echo "Sending event 1 to slot 1..."
echo "Event 1 for slot 1" | "$UDPLBD" dataplane send - --slot 1

echo "Sending event 2 to slot 1..."
echo "Event 2 for slot 1" | "$UDPLBD" dataplane send - --slot 1

echo "Sending event 3 to slot 2..."
echo "Event 3 for slot 2" | "$UDPLBD" dataplane send - --slot 2

echo "Sending event 4 to slot 2..."
echo "Event 4 for slot 2" | "$UDPLBD" dataplane send - --slot 2

# Wait for events to be processed
echo ""
echo "Waiting for events to be processed..."
sleep 2

# Show results
echo ""
echo "=== Results ==="
echo ""
echo "Receiver 1 output (should have events 1 and 2):"
cat /tmp/recv1-output.txt 2>/dev/null || echo "(no output)"
echo ""
echo "Receiver 2 output (should have events 3 and 4):"
cat /tmp/recv2-output.txt 2>/dev/null || echo "(no output)"
echo ""
echo "=== Test complete ==="
