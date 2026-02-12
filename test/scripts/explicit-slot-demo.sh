#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause-LBNL
#
# Interactive demo script for explicit slot routing.
#
# This script demonstrates how explicit slot-based load balancing works
# by walking through each step with explanations.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
UDPLBD="${UDPLBD:-$PROJECT_ROOT/target/debug/udplbd}"
MOCK_PID=""
RECV1_PID=""
RECV2_PID=""
RESERVATION_URI=""

# Colors for output
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Wait for user to press enter
wait_for_enter() {
    echo ""
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Print a step header
step() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  $1${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Print explanation text
explain() {
    echo -e "${CYAN}$1${NC}"
}

# Print command being run
show_cmd() {
    echo -e "${BLUE}> $1${NC}"
}

# Cleanup function
cleanup() {
    echo ""
    step "Cleanup"

    if [ -n "$RESERVATION_URI" ]; then
        explain "Freeing the load balancer reservation via gRPC FreeLoadBalancer RPC..."
        show_cmd "EJFAT_URI=\"\$RESERVATION_URI\" udplbd client free"
        EJFAT_URI="$RESERVATION_URI" "$UDPLBD" client free 2>/dev/null || true
    fi

    if [ -n "$RECV1_PID" ] && kill -0 "$RECV1_PID" 2>/dev/null; then
        explain "Stopping receiver 1..."
        kill "$RECV1_PID" 2>/dev/null || true
    fi
    if [ -n "$RECV2_PID" ] && kill -0 "$RECV2_PID" 2>/dev/null; then
        explain "Stopping receiver 2..."
        kill "$RECV2_PID" 2>/dev/null || true
    fi

    if [ -n "$MOCK_PID" ] && kill -0 "$MOCK_PID" 2>/dev/null; then
        explain "Stopping mock server..."
        kill "$MOCK_PID" 2>/dev/null || true
    fi

    rm -f /tmp/udplbd-explicit-demo.db
    rm -f /tmp/recv1-output.txt /tmp/recv2-output.txt

    echo ""
    echo -e "${GREEN}Demo complete!${NC}"
}

trap cleanup EXIT INT TERM

# Check binary
if [ ! -x "$UDPLBD" ]; then
    echo "Error: udplbd binary not found at $UDPLBD"
    echo "Please build the project first: cargo build"
    exit 1
fi

# Title
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         EJFAT Explicit Slot Routing Demo                      ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
explain "This demo shows how explicit slot-based load balancing works."
explain "In explicit mode, senders choose which slot (0-511) to send to,"
explain "and receivers register for specific slot ranges."
explain ""
explain "The 'tick' field in the LB header is used as the slot index."
wait_for_enter

# Step 1: Start mock server
step "Step 1: Start Mock Load Balancer"

if [ -z "$EJFAT_URI" ]; then
    explain "EJFAT_URI is not set, so we'll start a local mock server."
    explain "The mock server simulates the FPGA-based load balancer in software."
    explain "It listens on port 19523 for gRPC control plane requests."
    echo ""
    show_cmd "udplbd mock --db /tmp/udplbd-explicit-demo.db &"

    "$UDPLBD" mock --db /tmp/udplbd-explicit-demo.db &
    MOCK_PID=$!

    echo "Waiting for mock server (PID $MOCK_PID)..."
    for i in {1..30}; do
        if nc -z 127.0.0.1 19523 2>/dev/null; then
            echo -e "${GREEN}Mock server is ready!${NC}"
            break
        fi
        sleep 0.5
    done

    EJFAT_URI="ejfat://udplbd2changeme@127.0.0.1:19523"
else
    explain "Using existing EJFAT_URI from environment."
fi

echo ""
explain "Control plane URI: $EJFAT_URI"
export EJFAT_URI
wait_for_enter

# Step 2: Reserve load balancer
step "Step 2: Reserve Load Balancer (Explicit Mode)"

explain "We'll reserve a load balancer using the ReserveLoadBalancer gRPC RPC."
explain ""
explain "Key parameters:"
explain "  --strategy explicit  : Use explicit slot routing (tick = slot index)"
explain "  --sender 127.0.0.1   : Allow packets from this sender IP"
explain "  --after 600s         : Reservation expires in 10 minutes"
explain ""
explain "The gRPC request includes:"
explain "  - name: 'explicit-slot-demo'"
explain "  - strategy: EXPLICIT"
explain "  - sender_addresses: ['127.0.0.1']"
explain "  - expiration: now + 600 seconds"
echo ""
show_cmd "udplbd client reserve explicit-slot-demo --strategy explicit --sender 127.0.0.1 --after 600s"
wait_for_enter

RESERVE_OUTPUT=$("$UDPLBD" client reserve explicit-slot-demo --strategy explicit --sender 127.0.0.1 --after "600s")
echo "$RESERVE_OUTPUT"

RESERVATION_URI=$(echo "$RESERVE_OUTPUT" | grep "EJFAT_URI=" | sed "s/export 'EJFAT_URI=//;s/'$//")
export EJFAT_URI="$RESERVATION_URI"

echo ""
explain "The response includes:"
explain "  - lb_id: Unique identifier for this reservation"
explain "  - data addresses: Where to send UDP data packets"
explain "  - sync addresses: Where to send sync/timing packets"
explain "  - token: Authentication token for this reservation"
wait_for_enter

# Step 3: Start receivers
step "Step 3: Start Receivers"

explain "Now we'll start two receivers, each requesting different slot ranges."
explain ""
explain "Receiver 1: Requests slots 1-2 (just slot 1)"
explain "Receiver 2: Requests slots 2-3 (just slot 2)"
explain ""
explain "Each receiver calls the RegisterWorker gRPC RPC with:"
explain "  - name: receiver identifier"
explain "  - ip_address/udp_port: where to receive packets"
explain "  - slot_ranges: which slots this receiver wants"
explain ""
explain "The receivers run 'cat' to output received event data."
echo ""

show_cmd "udplbd dataplane recv -a 127.0.0.1 -p 20001 --name recv1 --lb --slots '1-2' -- cat &"
"$UDPLBD" dataplane recv \
    --address 127.0.0.1 \
    --port 20001 \
    --name recv1 \
    --slots "1-2" \
    -- cat > /tmp/recv1-output.txt 2>&1 &
RECV1_PID=$!
echo "Receiver 1 started (PID $RECV1_PID) - listening for slot 1"

show_cmd "udplbd dataplane recv -a 127.0.0.1 -p 20002 --name recv2 --lb --slots '2-3' -- cat &"
"$UDPLBD" dataplane recv \
    --address 127.0.0.1 \
    --port 20002 \
    --name recv2 \
    --slots "2-3" \
    -- cat > /tmp/recv2-output.txt 2>&1 &
RECV2_PID=$!
echo "Receiver 2 started (PID $RECV2_PID) - listening for slot 2"

echo ""
explain "Waiting for receivers to register with the control plane..."
sleep 3
wait_for_enter

# Step 4: Show overview
step "Step 4: View Load Balancer State"

explain "Let's check the current state using the Overview gRPC RPC."
explain "This shows all registered workers and their slot assignments."
echo ""
show_cmd "udplbd client overview"
echo ""
"$UDPLBD" client overview
wait_for_enter

# Step 5: Send events
step "Step 5: Send Events to Specific Slots"

explain "Now we'll send 4 events:"
explain "  - Events 1 & 2: sent with --slot 1 (tick=1)"
explain "  - Events 3 & 4: sent with --slot 2 (tick=2)"
explain ""
explain "The --slot option sets the 'tick' field in the LB header."
explain "In explicit mode, the load balancer uses tick as the slot index"
explain "to route packets to the correct receiver."
explain ""
explain "The data plane sends UDP packets with:"
explain "  - LB Header: magic='LB', version=2, tick=<slot>"
explain "  - Reassembly Header: data_id, offset, length, tick"
explain "  - Payload: the actual event data"
wait_for_enter

echo ""
explain "Sending event 1 to slot 1..."
show_cmd "echo 'Event 1 for slot 1' | udplbd dataplane send - --slot 1"
echo "Event 1 for slot 1" | "$UDPLBD" dataplane send - --slot 1
echo ""

explain "Sending event 2 to slot 1..."
show_cmd "echo 'Event 2 for slot 1' | udplbd dataplane send - --slot 1"
echo "Event 2 for slot 1" | "$UDPLBD" dataplane send - --slot 1
echo ""

explain "Sending event 3 to slot 2..."
show_cmd "echo 'Event 3 for slot 2' | udplbd dataplane send - --slot 2"
echo "Event 3 for slot 2" | "$UDPLBD" dataplane send - --slot 2
echo ""

explain "Sending event 4 to slot 2..."
show_cmd "echo 'Event 4 for slot 2' | udplbd dataplane send - --slot 2"
echo "Event 4 for slot 2" | "$UDPLBD" dataplane send - --slot 2
echo ""

explain "Waiting for events to be processed..."
sleep 2
wait_for_enter

# Step 6: Show results
step "Step 6: Results"

explain "Let's see what each receiver got:"
echo ""
echo -e "${YELLOW}Receiver 1 output (slot 1 - should have events 1 and 2):${NC}"
echo "─────────────────────────────────────────────────────"
cat /tmp/recv1-output.txt 2>/dev/null || echo "(no output)"
echo ""
echo -e "${YELLOW}Receiver 2 output (slot 2 - should have events 3 and 4):${NC}"
echo "─────────────────────────────────────────────────────"
cat /tmp/recv2-output.txt 2>/dev/null || echo "(no output)"
echo ""

explain "If the routing worked correctly:"
explain "  - Receiver 1 should have received events 1 and 2"
explain "  - Receiver 2 should have received events 3 and 4"
wait_for_enter

# Cleanup happens via trap
