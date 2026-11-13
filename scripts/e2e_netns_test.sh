#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This end-to-end test must be run on Linux with root privileges."
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Please run as root (needed for ip netns, /dev/net/tun, CAP_NET_RAW)."
    exit 1
fi

BIN="${1:-./target/release/easygre}"
if [[ ! -x "$BIN" ]]; then
    echo "Building release binary..."
    cargo build --release
    BIN="./target/release/easygre"
fi

NS_A="easygre_ns_a"
NS_B="easygre_ns_b"
PID_A=""
PID_B=""
PID_A2=""
PID_A3=""
STATUS_A="/tmp/easygre_e2e_a.status"
STATUS_B="/tmp/easygre_e2e_b.status"

assert_route_absent() {
    local ns="$1"
    local pattern="$2"
    if ip netns exec "$ns" ip route show | grep -q "$pattern"; then
        echo "FAIL: unexpected route matching '$pattern' still present in $ns:"
        ip netns exec "$ns" ip route show
        exit 1
    fi
}

assert_route_present() {
    local ns="$1"
    local pattern="$2"
    if ! ip netns exec "$ns" ip route show | grep -q "$pattern"; then
        echo "FAIL: expected route matching '$pattern' missing in $ns:"
        ip netns exec "$ns" ip route show
        exit 1
    fi
}

cleanup() {
    set +e
    [[ -n "$PID_A" ]] && kill "$PID_A" 2>/dev/null && wait "$PID_A" 2>/dev/null
    [[ -n "$PID_A2" ]] && kill "$PID_A2" 2>/dev/null && wait "$PID_A2" 2>/dev/null
    [[ -n "$PID_A3" ]] && kill "$PID_A3" 2>/dev/null && wait "$PID_A3" 2>/dev/null
    [[ -n "$PID_B" ]] && kill "$PID_B" 2>/dev/null && wait "$PID_B" 2>/dev/null
    ip netns del "$NS_A" 2>/dev/null
    ip netns del "$NS_B" 2>/dev/null
    rm -rf "/etc/netns/$NS_A" "/etc/netns/$NS_B" 2>/dev/null
    rm -f "$STATUS_A" "$STATUS_B" /tmp/easygre_inst*.status /tmp/easygre_e2e_*.log
}
trap cleanup EXIT

ip netns del "$NS_A" 2>/dev/null || true
ip netns del "$NS_B" 2>/dev/null || true

ip netns add "$NS_A"
ip netns add "$NS_B"

ip link add veth-a type veth peer name veth-b
ip link set veth-a netns "$NS_A"
ip link set veth-b netns "$NS_B"

ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_A" ip link set veth-a mtu 1500 up
ip netns exec "$NS_A" ip addr add 192.0.2.1/29 dev veth-a
ip netns exec "$NS_A" ip addr add 192.0.2.3/29 dev veth-a
# Install a host metric-0 default route in NS_A to verify EasyGRE never clobbers it
ip netns exec "$NS_A" ip route add default via 192.0.2.2 dev veth-a

ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_B" ip link set veth-b mtu 1500 up
ip netns exec "$NS_B" ip addr add 192.0.2.2/29 dev veth-b
ip netns exec "$NS_B" ip addr add 192.0.2.6/29 dev veth-b

mkdir -p "/etc/netns/$NS_A"
echo "192.0.2.2 peer.gre.test" >"/etc/netns/$NS_A/hosts"

ip netns exec "$NS_A" "$BIN" \
    --name gre-a \
    --local 192.0.2.1 \
    --remote peer.gre.test \
    --addr 172.16.1.1/30,fd00:1::1/64 \
    --route 0.0.0.0/0 \
    --dns-refresh 5s \
    --keepalive 1s,3 \
    --status-file "$STATUS_A" >/tmp/easygre_e2e_a.log 2>&1 &
PID_A=$!

ip netns exec "$NS_B" "$BIN" \
    --name gre-b \
    --local 192.0.2.2 \
    --remote 192.0.2.1 \
    --addr 172.16.1.2/30,fd00:1::2/64 \
    --keepalive 1s,3 \
    --status-file "$STATUS_B" >/tmp/easygre_e2e_b.log 2>&1 &
PID_B=$!

echo "[1/11] Waiting for keepalive handshake & verifying /0 split routes..."
for _ in $(seq 1 20); do
    if ip netns exec "$NS_A" ip link show gre-a | grep -q "LOWER_UP" \
        && ip netns exec "$NS_B" ip link show gre-b | grep -q "LOWER_UP"; then
        break
    fi
    sleep 0.3
done

ip netns exec "$NS_A" ip link show gre-a | grep -q "mtu 1476"
ip netns exec "$NS_A" ip link show gre-a | grep -q "LOWER_UP"
ip netns exec "$NS_A" ip route show | grep -q "0.0.0.0/1 dev gre-a"
ip netns exec "$NS_A" ip route show | grep -q "128.0.0.0/1 dev gre-a"
ip netns exec "$NS_A" ip route show | grep -q "192.0.2.2 .*dev veth-a"
ip netns exec "$NS_A" ip route show | grep -q "default via 192.0.2.2 dev veth-a"
"$BIN" healthcheck --status-file "$STATUS_A"

echo "[2/11] Testing IPv4 & IPv6 connectivity over GRE..."
ip netns exec "$NS_A" ping -c 3 -W 1 172.16.1.2
ip netns exec "$NS_A" ping -6 -c 3 -W 1 fd00:1::2

echo "[3/11] Testing keepalive timeout drops carrier even under spoofed PT=0x0000 replies..."
kill "$PID_B"
wait "$PID_B" 2>/dev/null || true
PID_B=""

if command -v python3 >/dev/null 2>&1; then
    for _ in 1 2 3 4; do
        ip netns exec "$NS_B" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 47)
s.bind(("192.0.2.2", 0))
s.sendto(b"\x00\x00\x00\x00\x11\x22\x33\x44", ("192.0.2.1", 0))
'
        sleep 0.4
    done
fi

for _ in $(seq 1 25); do
    if ! ip netns exec "$NS_A" ip link show gre-a | grep -q "LOWER_UP"; then
        break
    fi
    sleep 0.3
done
if ip netns exec "$NS_A" ip link show gre-a | grep -q "LOWER_UP"; then
    echo "FAIL: carrier did not drop after peer went down"
    cat /tmp/easygre_e2e_a.log
    exit 1
fi
if command -v python3 >/dev/null 2>&1; then
    grep -v "ka_drop=0" "$STATUS_A" | grep -q "ka_drop="
fi
if "$BIN" healthcheck --status-file "$STATUS_A" >/dev/null 2>&1; then
    echo "FAIL: healthcheck should fail when all tunnels are down"
    cat "$STATUS_A"
    exit 1
fi

echo "[4/11] Testing keepalive auto-recovery..."
ip netns exec "$NS_B" "$BIN" \
    --name gre-b \
    --local 192.0.2.2 \
    --remote 192.0.2.1 \
    --addr 172.16.1.2/30,fd00:1::2/64 \
    --keepalive 1s,3 \
    --status-file "$STATUS_B" >/tmp/easygre_e2e_b.log 2>&1 &
PID_B=$!

for _ in $(seq 1 20); do
    if ip netns exec "$NS_A" ip link show gre-a | grep -q "LOWER_UP"; then
        break
    fi
    sleep 0.3
done
ip netns exec "$NS_A" ip link show gre-a | grep -q "LOWER_UP"

echo "[5/11] Testing DDNS remote IP switch under 0.0.0.0/0 without routing loop..."
kill "$PID_B"
wait "$PID_B" 2>/dev/null || true
PID_B=""
ip netns exec "$NS_B" "$BIN" \
    --name gre-b \
    --local 192.0.2.6 \
    --remote 192.0.2.1 \
    --addr 172.16.1.2/30,fd00:1::2/64 \
    --keepalive 1s,3 \
    --status-file "$STATUS_B" >/tmp/easygre_e2e_b.log 2>&1 &
PID_B=$!
echo "192.0.2.6 peer.gre.test" >"/etc/netns/$NS_A/hosts"

for _ in $(seq 1 30); do
    if ip netns exec "$NS_A" ip route show | grep -q "192.0.2.6 .*dev veth-a"; then
        break
    fi
    sleep 0.3
done
ip netns exec "$NS_A" ip route show | grep -q "192.0.2.6 .*dev veth-a"
assert_route_absent "$NS_A" "192.0.2.6 .*dev gre-a"
assert_route_absent "$NS_A" "^192.0.2.2 "
for _ in $(seq 1 20); do
    if ip netns exec "$NS_A" ip link show gre-a | grep -q "LOWER_UP"; then
        break
    fi
    sleep 0.3
done
ip netns exec "$NS_A" ping -c 2 -W 1 172.16.1.2

echo "[6/11] Verifying host default route remains intact after daemon shutdown..."
kill "$PID_A"
wait "$PID_A" 2>/dev/null || true
PID_A=""
ip netns exec "$NS_A" ip route show | grep -q "default via 192.0.2.2 dev veth-a"
assert_route_absent "$NS_A" "^192.0.2.6 "

echo "[7/11] Testing dont-fragment=inherit ICMP Packet Too Big feedback..."
ip netns exec "$NS_A" ip link set veth-a mtu 1400
ip netns exec "$NS_B" ip link set veth-b mtu 1400
ip netns exec "$NS_A" "$BIN" \
    --name gre-a \
    --local 192.0.2.1 \
    --remote 192.0.2.6 \
    --addr 172.16.1.1/30 \
    --mtu 1476 \
    --dont-fragment inherit \
    --tx-mode raw \
    --keepalive 1s,3 \
    --status-file "$STATUS_A" >/tmp/easygre_e2e_a.log 2>&1 &
PID_A=$!
for _ in $(seq 1 20); do
    if ip netns exec "$NS_A" ip link show gre-a | grep -q "LOWER_UP"; then
        break
    fi
    sleep 0.3
done
ip netns exec "$NS_A" ping -c 2 -W 1 -M do -s 1420 172.16.1.2 || true
ip netns exec "$NS_A" ip route get 172.16.1.2 | grep -q "mtu 1376"
kill "$PID_A"; wait "$PID_A" 2>/dev/null || true; PID_A=""
kill "$PID_B"; wait "$PID_B" 2>/dev/null || true; PID_B=""

echo "[8/11] Testing multi-instance route isolation, sibling TUN exclusion & crashed-slot cleanup..."
ip netns exec "$NS_A" ip link set veth-a mtu 1500
ip netns exec "$NS_B" ip link set veth-b mtu 1500
rm -f /tmp/easygre_inst1.status /tmp/easygre_inst2.status /tmp/easygre_inst3.status

# Instance 1: live container with /0 split routes and 192.0.2.2/32 bypass
ip netns exec "$NS_A" "$BIN" \
    --name gre-inst1 \
    --local 192.0.2.1 \
    --remote 192.0.2.2 \
    --addr 172.16.1.1/30 \
    --route 0.0.0.0/0 \
    --keepalive off \
    --status-file /tmp/easygre_inst1.status >/tmp/easygre_e2e_i1.log 2>&1 &
PID_A=$!
sleep 0.4
ip netns exec "$NS_A" ip route show | grep -q "0.0.0.0/1 dev gre-inst1"
ip netns exec "$NS_A" ip route show | grep -q "192.0.2.2.*dev veth-a.*proto 198"

# Instance 3: starts and gets SIGKILLed (with its status file vanished, simulating isolated container crash)
ip netns exec "$NS_A" "$BIN" \
    --name gre-inst3 \
    --local 192.0.2.1 \
    --remote 192.0.2.5 \
    --addr 172.16.3.1/30 \
    --route 192.0.2.4/30 \
    --keepalive off \
    --status-file /tmp/easygre_inst3.status >/tmp/easygre_e2e_i3.log 2>&1 &
PID_A3=$!
sleep 0.4
ip netns exec "$NS_A" ip route show | grep -q "192.0.2.5.*dev veth-a.*proto 198"
kill -9 "$PID_A3"
wait "$PID_A3" 2>/dev/null || true
PID_A3=""
rm -f /tmp/easygre_inst3.status
ip netns exec "$NS_A" ip route show | grep -q "192.0.2.5.*dev veth-a.*proto 198"

# Instance 2: starts with a non-existent status file; MUST keep Instance 1's routes AND reclaim dead Instance 3's bypass!
# Also targets external 203.0.113.99 while Instance 1 holds 0.0.0.0/1 + 128.0.0.0/1, verifying physical NIC selection!
ip netns exec "$NS_A" "$BIN" \
    --name gre-inst2 \
    --local 192.0.2.1 \
    --remote 203.0.113.99 \
    --addr 172.16.2.1/30 \
    --route 203.0.113.0/24 \
    --keepalive off \
    --status-file /tmp/easygre_inst2.status >/tmp/easygre_e2e_i2.log 2>&1 &
PID_A2=$!
sleep 0.5
assert_route_present "$NS_A" "0.0.0.0/1 dev gre-inst1"
assert_route_present "$NS_A" "128.0.0.0/1 dev gre-inst1"
assert_route_present "$NS_A" "192.0.2.2.*dev veth-a.*proto 198"
assert_route_present "$NS_A" "203.0.113.99 via 192.0.2.2 dev veth-a proto 198"
assert_route_absent "$NS_A" "203.0.113.99.*dev gre-inst1"
assert_route_absent "$NS_A" "^192.0.2.5 "

# Stopping Instance 2 removes only 203.0.113.99/32 while Instance 1 stays completely untouched
kill "$PID_A2"; wait "$PID_A2" 2>/dev/null || true; PID_A2=""
assert_route_absent "$NS_A" "^203.0.113.99 "
assert_route_present "$NS_A" "0.0.0.0/1 dev gre-inst1"
assert_route_present "$NS_A" "192.0.2.2.*dev veth-a.*proto 198"

echo "[9/11] Testing cross-instance same /32 independent metric coexistence..."
ip netns exec "$NS_A" "$BIN" \
    --name gre-inst2 \
    --local 192.0.2.3 \
    --remote 192.0.2.2 \
    --addr 172.16.2.1/30 \
    --route 192.0.2.0/30 \
    --keepalive off \
    --status-file /tmp/easygre_inst2.status >/tmp/easygre_e2e_i2.log 2>&1 &
PID_A2=$!
sleep 0.4
assert_route_present "$NS_A" "192.0.2.2.*dev veth-a.*proto 198.*metric 19801"
assert_route_present "$NS_A" "192.0.2.2.*dev veth-a.*proto 198.*metric 19802"
kill "$PID_A2"; wait "$PID_A2" 2>/dev/null || true; PID_A2=""
assert_route_present "$NS_A" "192.0.2.2.*dev veth-a.*proto 198.*metric 19801"
assert_route_absent "$NS_A" "metric 19802"
kill "$PID_A"; wait "$PID_A" 2>/dev/null || true; PID_A=""
assert_route_absent "$NS_A" "^192.0.2.2 "

echo "[10/11] Testing in-process /32 refcount & conflicting next-hop rejection..."
echo "192.0.2.2 shared.gre.test" >"/etc/netns/$NS_A/hosts"
ip netns exec "$NS_A" "$BIN" \
    --tunnel "name=t1;local=192.0.2.1;remote=192.0.2.2;route=0.0.0.0/0;keepalive=off" \
    --tunnel "name=t2;local=192.0.2.3;remote=shared.gre.test;route=10.200.0.0/24;dns-refresh=5s;keepalive=off" \
    --status-file /tmp/easygre_inst1.status >/tmp/easygre_e2e_i1.log 2>&1 &
PID_A=$!
sleep 0.4
assert_route_present "$NS_A" "192.0.2.2.*dev veth-a.*proto 198"
echo "192.0.2.6 shared.gre.test" >"/etc/netns/$NS_A/hosts"
for _ in $(seq 1 25); do
    if ip netns exec "$NS_A" ip route show | grep -q "192.0.2.6.*dev veth-a.*proto 198"; then
        break
    fi
    sleep 0.3
done
assert_route_present "$NS_A" "192.0.2.6.*dev veth-a.*proto 198"
assert_route_present "$NS_A" "192.0.2.2.*dev veth-a.*proto 198"
kill "$PID_A"; wait "$PID_A" 2>/dev/null || true; PID_A=""

# Second veth leg for conflicting next-hop & ECMP tests
ip link add veth-c type veth peer name veth-d
ip link set veth-c netns "$NS_A"
ip link set veth-d netns "$NS_B"
ip netns exec "$NS_A" ip link set veth-c mtu 1500 up
ip netns exec "$NS_B" ip link set veth-d mtu 1500 up
ip netns exec "$NS_A" ip addr add 198.51.100.1/29 dev veth-c
ip netns exec "$NS_B" ip addr add 198.51.100.2/29 dev veth-d

# Policy rule steering local=198.51.100.1 out veth-c while local=192.0.2.1 uses veth-a toward 203.0.113.77:
# Single process with two tunnels demanding conflicting /32 physical next-hops for 203.0.113.77 MUST fail closed!
ip netns exec "$NS_A" ip route add default via 198.51.100.2 dev veth-c table 100
ip netns exec "$NS_A" ip rule add from 198.51.100.1 lookup 100
if ip netns exec "$NS_A" "$BIN" \
    --tunnel "name=t1;local=192.0.2.1;remote=203.0.113.77;route=0.0.0.0/0;keepalive=off" \
    --tunnel "name=t2;local=198.51.100.1;remote=203.0.113.77;route=10.201.0.0/24;keepalive=off" \
    --status-file /tmp/easygre_inst1.status >/tmp/easygre_e2e_conflict.log 2>&1; then
    echo "FAIL: expected conflicting /32 bypass next-hop in same process to be rejected"
    exit 1
fi
grep -q "conflicting /32 bypass route" /tmp/easygre_e2e_conflict.log
ip netns exec "$NS_A" ip rule del from 198.51.100.1 lookup 100
ip netns exec "$NS_A" ip route flush table 100
assert_route_absent "$NS_A" "^203.0.113.77 "

echo "[11/11] Testing ECMP RTA_MULTIPATH default route + DDNS switch..."
ip netns exec "$NS_A" ip route replace default \
    nexthop via 192.0.2.2 dev veth-a weight 1 \
    nexthop via 198.51.100.2 dev veth-c weight 1
echo "203.0.113.10 ecmp.gre.test" >"/etc/netns/$NS_A/hosts"
ip netns exec "$NS_A" "$BIN" \
    --name gre-ecmp \
    --remote ecmp.gre.test \
    --route 0.0.0.0/0 \
    --dns-refresh 5s \
    --keepalive off \
    --status-file /tmp/easygre_inst1.status >/tmp/easygre_e2e_ecmp.log 2>&1 &
PID_A=$!
sleep 0.4
assert_route_present "$NS_A" "^203.0.113.10 via .* dev veth-[ac] proto 198"
echo "203.0.113.20 ecmp.gre.test" >"/etc/netns/$NS_A/hosts"
for _ in $(seq 1 25); do
    if ip netns exec "$NS_A" ip route show | grep -q "^203.0.113.20 "; then
        break
    fi
    sleep 0.3
done
assert_route_present "$NS_A" "^203.0.113.20 via .* dev veth-[ac] proto 198"
assert_route_absent "$NS_A" "203.0.113.20.*dev gre-ecmp"
assert_route_absent "$NS_A" "^203.0.113.10 "

echo "PASS: EasyGRE Linux end-to-end verification succeeded."
