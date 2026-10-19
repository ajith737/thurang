#!/usr/bin/env bash
# End-to-end test on Linux using network namespaces. Run as root:
#   cargo build && sudo tests/netns.sh
#
#   cli (192.168.50.2) --LAN-- srv (192.168.50.1 | 10.99.0.1) --WAN-- inet (10.99.0.2, 203.0.113.10)
#
# cli has no default route, so reaching 203.0.113.10 proves the exit node works.
set -euo pipefail

BIN=${BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/debug/thurang}
WORK=$(mktemp -d)
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; exit 1; }

cleanup() {
    set +e
    [[ -n "${CLI_PID:-}" ]] && kill -INT "$CLI_PID" 2>/dev/null && wait "$CLI_PID"
    [[ -n "${SRV_PID:-}" ]] && kill -INT "$SRV_PID" 2>/dev/null && wait "$SRV_PID"
    for ns in cli srv inet; do ip netns del "$ns" 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT

for ns in cli srv inet; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip link add veth-cli netns cli type veth peer name veth-lan netns srv
ip link add veth-wan netns srv type veth peer name veth-inet netns inet
ip -n cli addr add 192.168.50.2/24 dev veth-cli && ip -n cli link set veth-cli up
ip -n srv addr add 192.168.50.1/24 dev veth-lan && ip -n srv link set veth-lan up
ip -n srv addr add 10.99.0.1/24 dev veth-wan && ip -n srv link set veth-wan up
ip -n srv route add default via 10.99.0.2
ip -n inet addr add 10.99.0.2/24 dev veth-inet && ip -n inet link set veth-inet up
ip -n inet addr add 203.0.113.10/32 dev lo

S="env THURANG_HOME=$WORK/srv $BIN"
C="env THURANG_HOME=$WORK/cli $BIN"

ip netns exec cli ping -c1 -W1 203.0.113.10 >/dev/null 2>&1 && fail "internet reachable without tunnel"

ip netns exec srv $S server init --exit-node --dns 10.99.0.2 --no-mdns --egress-interface veth-wan
ip netns exec srv $S server up > "$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 2

ip netns exec cli $C join 192.168.50.1 --otp 00000000 --name bad 2>/dev/null && fail "join with no active OTP"
CODE=$(ip netns exec srv $S otp | head -1 | tr -dc 0-9)
[[ ${#CODE} -eq 8 ]] || fail "otp output"
WRONG=$(printf '%08d' $(( (10#$CODE + 1) % 100000000 )))
ip netns exec cli $C join 192.168.50.1 --otp "$WRONG" --name bad 2>/dev/null && fail "join with wrong OTP"
pass "wrong OTP rejected"
ip netns exec cli $C join 192.168.50.1 --otp "$CODE" --name cli || fail "join"
pass "paired"
ip netns exec cli $C join 192.168.50.1 --otp "$CODE" --name again 2>/dev/null && fail "OTP reused"
pass "OTP is single-use"

ip netns exec cli $C up --foreground --exit-node > "$WORK/cli.log" 2>&1 &
CLI_PID=$!
for _ in $(seq 20); do grep -q "Ctrl-C" "$WORK/cli.log" && break; sleep 0.5; done
cat "$WORK/cli.log"

ip netns exec cli ping -c2 -W2 100.64.0.1 >/dev/null || fail "ping server tunnel IP"
pass "tunnel up"
ip netns exec cli ping -c2 -W2 203.0.113.10 >/dev/null || fail "exit node"
pass "exit node routes internet traffic"

if command -v dig >/dev/null; then
    [[ $(ip netns exec cli dig +short +time=2 @100.64.0.1 cli.thurang) == "100.64.0.2" ]] || fail "magic DNS"
    pass "peer name resolves via server DNS"
fi

ip netns exec srv $S peers | grep -q "^cli " || fail "peers listing"
pass "server lists peer"

kill -INT "$CLI_PID"; wait "$CLI_PID"; CLI_PID=
ip -n cli route | grep -q "0.0.0.0/1" && fail "routes not cleaned up"
ip netns exec cli ping -c1 -W1 203.0.113.10 >/dev/null 2>&1 && fail "still routed after down"
pass "client cleaned up routes"

ip netns exec srv $S revoke cli >/dev/null
pass "revoke"
kill -INT "$SRV_PID"; wait "$SRV_PID"; SRV_PID=
ip netns exec srv iptables -t nat -S | grep -q thurang && fail "NAT rules left behind"
pass "server cleaned up NAT"
echo "all tests passed"
