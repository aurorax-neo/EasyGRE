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
NS_OUT="easygre_ns_out"
NS_NAT="easygre_ns_nat"
NS_GATE="easygre_ns_gate"
NS_LAN="easygre_ns_lan"
NS_GWA="easygre_ns_gwa"
NS_EXB="easygre_ns_exb"
NS_WAN="easygre_ns_wan"
PID_A=""
PID_B=""
PID_A2=""
PID_A3=""
PID_SRV1=""
PID_SRV2=""
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
    [[ -n "$PID_SRV1" ]] && kill "$PID_SRV1" 2>/dev/null && wait "$PID_SRV1" 2>/dev/null
    [[ -n "$PID_SRV2" ]] && kill "$PID_SRV2" 2>/dev/null && wait "$PID_SRV2" 2>/dev/null
    for ns in "$NS_A" "$NS_B" "$NS_OUT" "$NS_NAT" "$NS_GATE" "$NS_LAN" "$NS_GWA" "$NS_EXB" "$NS_WAN"; do
        ip netns del "$ns" 2>/dev/null
        rm -rf "/etc/netns/$ns" 2>/dev/null
    done
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

echo "[1/13] Waiting for keepalive handshake & verifying /0 split routes..."
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

echo "[2/13] Testing IPv4 & IPv6 connectivity over GRE..."
ip netns exec "$NS_A" ping -c 3 -W 1 172.16.1.2
ip netns exec "$NS_A" ping -6 -c 3 -W 1 fd00:1::2

echo "[3/13] Testing keepalive timeout drops carrier even under spoofed PT=0x0000 replies..."
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

echo "[4/13] Testing keepalive auto-recovery..."
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

echo "[5/13] Testing DDNS remote IP switch under 0.0.0.0/0 without routing loop..."
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

echo "[6/13] Verifying host default route remains intact after daemon shutdown..."
kill "$PID_A"
wait "$PID_A" 2>/dev/null || true
PID_A=""
ip netns exec "$NS_A" ip route show | grep -q "default via 192.0.2.2 dev veth-a"
assert_route_absent "$NS_A" "^192.0.2.6 "

echo "[7/13] Testing dont-fragment=inherit ICMP Packet Too Big feedback..."
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

echo "[8/13] Testing multi-instance route isolation, sibling TUN exclusion & crashed-slot cleanup..."
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

echo "[9/13] Testing cross-instance same /32 independent metric coexistence..."
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

echo "[10/13] Testing in-process /32 refcount & conflicting next-hop rejection..."
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

echo "[11/13] Testing ECMP RTA_MULTIPATH default route + DDNS switch..."
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
kill "$PID_A"; wait "$PID_A" 2>/dev/null || true; PID_A=""

echo "[12/13] Testing Keepalive against 1:1 NAT + MASQUERADE + Linux kernel ip_gre peer..."
if command -v iptables >/dev/null 2>&1 && ip netns add "$NS_OUT" 2>/dev/null; then
    ip netns del "$NS_NAT" 2>/dev/null || true
    ip netns del "$NS_GATE" 2>/dev/null || true
    ip netns add "$NS_NAT"
    ip netns add "$NS_GATE"

    ip link add veth-out type veth peer name veth-nat-w
    ip link add veth-nat-l type veth peer name veth-gate
    ip link set veth-out netns "$NS_OUT"
    ip link set veth-nat-w netns "$NS_NAT"
    ip link set veth-nat-l netns "$NS_NAT"
    ip link set veth-gate netns "$NS_GATE"

    ip netns exec "$NS_OUT" ip link set lo up
    ip netns exec "$NS_OUT" ip link set veth-out up
    ip netns exec "$NS_OUT" ip addr add 23.94.104.214/30 dev veth-out
    ip netns exec "$NS_OUT" ip route add default via 23.94.104.213 dev veth-out

    ip netns exec "$NS_NAT" ip link set lo up
    ip netns exec "$NS_NAT" ip link set veth-nat-w up
    ip netns exec "$NS_NAT" ip link set veth-nat-l up
    ip netns exec "$NS_NAT" ip addr add 23.94.104.213/30 dev veth-nat-w
    ip netns exec "$NS_NAT" ip addr add 106.74.21.21/32 dev veth-nat-w
    ip netns exec "$NS_NAT" ip addr add 10.12.0.1/24 dev veth-nat-l
    ip netns exec "$NS_NAT" sysctl -qw net.ipv4.ip_forward=1
    ip netns exec "$NS_NAT" iptables -t nat -A PREROUTING -d 106.74.21.21 -j DNAT --to-destination 10.12.0.41
    ip netns exec "$NS_NAT" iptables -t nat -A POSTROUTING -s 10.12.0.41 -o veth-nat-w -j SNAT --to-source 106.74.21.21

    ip netns exec "$NS_GATE" ip link set lo up
    ip netns exec "$NS_GATE" ip link set veth-gate up
    ip netns exec "$NS_GATE" ip addr add 10.12.0.41/24 dev veth-gate
    ip netns exec "$NS_GATE" ip route add default via 10.12.0.1 dev veth-gate
    ip netns exec "$NS_GATE" sysctl -qw net.ipv4.ip_forward=1
    # Reproduce CUCLOUD srcnat masquerade on gate-240 that drops GRE-in-GRE bounce packets!
    ip netns exec "$NS_GATE" iptables -t nat -A POSTROUTING -o veth-gate -j MASQUERADE

    modprobe ip_gre 2>/dev/null || true
    if ip netns exec "$NS_GATE" ip tunnel add gre-k mode gre local 10.12.0.41 remote 23.94.104.214 ttl 64 2>/dev/null; then
        ip netns exec "$NS_GATE" ip link set gre-k up
        ip netns exec "$NS_GATE" ip addr add 172.16.240.2/30 dev gre-k
        ip netns exec "$NS_GATE" ip addr add fd00:240::2/126 dev gre-k nodad
        # Seed outer GRE conntrack tuple (10.12.0.41, 23.94.104.214, proto=47) on gate-240
        ip netns exec "$NS_GATE" ping -c 1 -W 1 172.16.240.1 >/dev/null 2>&1 || true

        ip netns exec "$NS_OUT" "$BIN" \
            --name gre-out \
            --local 23.94.104.214 \
            --remote 106.74.21.21 \
            --addr 172.16.240.1/30,fd00:240::1/126 \
            --keepalive 1s,3 \
            --status-file "$STATUS_A" >/tmp/easygre_e2e_ka_nat1.log 2>&1 &
        PID_A=$!

        for _ in $(seq 1 25); do
            if ip netns exec "$NS_OUT" ip link show gre-out | grep -q "LOWER_UP"; then
                break
            fi
            sleep 0.3
        done
        ip netns exec "$NS_OUT" ip link show gre-out | grep -q "LOWER_UP"
        ip netns exec "$NS_OUT" ping -c 2 -W 1 172.16.240.2
        ip netns exec "$NS_OUT" ping -6 -c 2 -W 1 fd00:240::2
        # Ensure tunnel remains UP across multiple 1s intervals (no carrier flap under MASQUERADE)
        sleep 3.5
        ip netns exec "$NS_OUT" ip link show gre-out | grep -q "LOWER_UP"
        "$BIN" healthcheck --status-file "$STATUS_A"

        # Verify carrier drops cleanly when kernel ip_gre peer goes down
        ip netns exec "$NS_GATE" ip link set gre-k down
        for _ in $(seq 1 25); do
            if ! ip netns exec "$NS_OUT" ip link show gre-out | grep -q "LOWER_UP"; then
                break
            fi
            sleep 0.3
        done
        if ip netns exec "$NS_OUT" ip link show gre-out | grep -q "LOWER_UP"; then
            echo "FAIL: carrier did not drop when NATed ip_gre peer went down"
            cat /tmp/easygre_e2e_ka_nat1.log
            exit 1
        fi
        kill "$PID_A"; wait "$PID_A" 2>/dev/null || true; PID_A=""

        # Sub-case 12b: EasyGRE with no --addr (unknown peer /24 IP on kernel ip_gre behind 1:1 NAT + MASQUERADE -> UDP-in-GRE fallback)
        ip netns exec "$NS_GATE" ip addr flush dev gre-k
        ip netns exec "$NS_GATE" ip addr add 172.16.241.99/24 dev gre-k
        ip netns exec "$NS_GATE" ip link set gre-k up
        ip netns exec "$NS_OUT" "$BIN" \
            --name gre-out-unnum \
            --local 23.94.104.214 \
            --remote 106.74.21.21 \
            --keepalive 1s,3 \
            --status-file "$STATUS_A" >/tmp/easygre_e2e_ka_nat2.log 2>&1 &
        PID_A=$!
        for _ in $(seq 1 25); do
            if ip netns exec "$NS_OUT" ip link show gre-out-unnum | grep -q "LOWER_UP"; then
                break
            fi
            sleep 0.3
        done
        ip netns exec "$NS_OUT" ip link show gre-out-unnum | grep -q "LOWER_UP"
        grep -q "mode=udp-in-gre" /tmp/easygre_e2e_ka_nat2.log
        sleep 3.5
        ip netns exec "$NS_OUT" ip link show gre-out-unnum | grep -q "LOWER_UP"
        kill "$PID_A"; wait "$PID_A" 2>/dev/null || true; PID_A=""
    else
        echo "SKIP: kernel ip_gre module unavailable in test host; skipping kernel ip_gre sub-check"
    fi
fi

echo "[13/13] Testing pure user-space NAT (--nat out, --nat exit, --dnat) with zero netfilter rules..."
for ns in "$NS_LAN" "$NS_GWA" "$NS_EXB" "$NS_WAN"; do
    ip netns del "$ns" 2>/dev/null || true
    ip netns add "$ns"
    ip netns exec "$ns" ip link set lo up
done

ip link add veth-lan type veth peer name veth-gwa-lan
ip link add veth-gwa-u type veth peer name veth-exb-u
ip link add veth-exb-w type veth peer name veth-wan

ip link set veth-lan netns "$NS_LAN"
ip link set veth-gwa-lan netns "$NS_GWA"
ip link set veth-gwa-u netns "$NS_GWA"
ip link set veth-exb-u netns "$NS_EXB"
ip link set veth-exb-w netns "$NS_EXB"
ip link set veth-wan netns "$NS_WAN"

ip netns exec "$NS_LAN" ip link set veth-lan up
ip netns exec "$NS_LAN" ip addr add 192.168.88.10/24 dev veth-lan
ip netns exec "$NS_LAN" ip addr add fd88::10/64 dev veth-lan nodad
ip netns exec "$NS_LAN" ip route add default via 192.168.88.1 dev veth-lan
ip netns exec "$NS_LAN" ip -6 route add default via fd88::1 dev veth-lan

ip netns exec "$NS_GWA" ip link set veth-gwa-lan up
ip netns exec "$NS_GWA" ip link set veth-gwa-u up
ip netns exec "$NS_GWA" ip addr add 192.168.88.1/24 dev veth-gwa-lan
ip netns exec "$NS_GWA" ip addr add fd88::1/64 dev veth-gwa-lan nodad
ip netns exec "$NS_GWA" ip addr add 192.0.2.101/24 dev veth-gwa-u

ip netns exec "$NS_EXB" ip link set veth-exb-u up
ip netns exec "$NS_EXB" ip link set veth-exb-w up
ip netns exec "$NS_EXB" ip addr add 192.0.2.102/24 dev veth-exb-u
ip netns exec "$NS_EXB" ip addr add 198.51.100.1/24 dev veth-exb-w
ip netns exec "$NS_EXB" ip addr add 2001:db8:99::1/64 dev veth-exb-w nodad

ip netns exec "$NS_WAN" ip link set veth-wan up
ip netns exec "$NS_WAN" ip addr add 198.51.100.80/24 dev veth-wan
ip netns exec "$NS_WAN" ip addr add 2001:db8:99::80/64 dev veth-wan nodad
ip netns exec "$NS_WAN" ip route add default via 198.51.100.1 dev veth-wan
ip netns exec "$NS_WAN" ip -6 route add default via 2001:db8:99::1 dev veth-wan

ip netns exec "$NS_GWA" "$BIN" \
    --name gre-nat-a \
    --local 192.0.2.101 \
    --remote 192.0.2.102 \
    --addr 10.99.0.2/30,fd99::2/126 \
    --nat out \
    --route 198.51.100.0/24 \
    --route 2001:db8:99::/64 \
    --keepalive 1s,3 \
    --status-file "$STATUS_A" >/tmp/easygre_e2e_nat_a.log 2>&1 &
PID_A=$!

ip netns exec "$NS_EXB" "$BIN" \
    --name gre-nat-b \
    --local 192.0.2.102 \
    --remote 192.0.2.101 \
    --addr 10.99.0.1/30,fd99::1/126 \
    --nat exit \
    --dnat "tcp/18080->10.99.0.2:8080,udp/18081->10.99.0.2:8081" \
    --keepalive 1s,3 \
    --status-file "$STATUS_B" >/tmp/easygre_e2e_nat_b.log 2>&1 &
PID_B=$!

for _ in $(seq 1 25); do
    if ip netns exec "$NS_GWA" ip link show gre-nat-a | grep -q "LOWER_UP" \
        && ip netns exec "$NS_EXB" ip link show gre-nat-b | grep -q "LOWER_UP"; then
        break
    fi
    sleep 0.3
done
ip netns exec "$NS_GWA" ip link show gre-nat-a | grep -q "LOWER_UP"
ip netns exec "$NS_EXB" ip link show gre-nat-b | grep -q "LOWER_UP"

# 13a: --nat out allows unrouted LAN (192.168.88.10 / fd88::10) to reach peer tunnel IP (10.99.0.1 / fd99::1)
ip netns exec "$NS_LAN" ping -c 2 -W 1 10.99.0.1
ip netns exec "$NS_LAN" ping -6 -c 2 -W 1 fd99::1

# 13b: --nat out + --nat exit allows NS_LAN and NS_GWA to reach external WAN (198.51.100.80 / 2001:db8:99::80)
ip netns exec "$NS_LAN" ping -c 2 -W 1 198.51.100.80
ip netns exec "$NS_LAN" ping -6 -c 2 -W 1 2001:db8:99::80

if command -v python3 >/dev/null 2>&1; then
    # Start dual-stack TCP + UDP echo server on WAN host (198.51.100.80 / 2001:db8:99::80)
    ip netns exec "$NS_WAN" python3 -c '
import selectors, socket, threading

def tcp_srv(fam, addr):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, 9000))
    s.listen(16)
    while True:
        c, _ = s.accept()
        def run(conn):
            try:
                while True:
                    d = conn.recv(32768)
                    if not d:
                        break
                    conn.sendall(d)
            finally:
                conn.close()
        threading.Thread(target=run, args=(c,), daemon=True).start()

def udp_srv(fam, addr):
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.bind((addr, 9001))
    while True:
        d, peer = s.recvfrom(4096)
        s.sendto(b"WAN:" + d, peer)

for fam, ip in [(socket.AF_INET, "198.51.100.80"), (socket.AF_INET6, "2001:db8:99::80")]:
    threading.Thread(target=tcp_srv, args=(fam, ip), daemon=True).start()
    threading.Thread(target=udp_srv, args=(fam, ip), daemon=True).start()
threading.Event().wait()
' &
    PID_SRV1=$!

    # Start TCP + UDP target services inside NS_GWA (10.99.0.2:8080 & 8081) for --dnat verification
    ip netns exec "$NS_GWA" python3 -c '
import socket, threading

def tcp_srv():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.99.0.2", 8080))
    s.listen(8)
    while True:
        c, _ = s.accept()
        d = c.recv(4096)
        c.sendall(b"DNAT_TCP:" + d)
        c.close()

def udp_srv():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("10.99.0.2", 8081))
    while True:
        d, p = s.recvfrom(4096)
        s.sendto(b"DNAT_UDP:" + d, p)

threading.Thread(target=tcp_srv, daemon=True).start()
threading.Thread(target=udp_srv, daemon=True).start()
threading.Event().wait()
' &
    PID_SRV2=$!
    sleep 0.4

    # Verify 128 KB TCP + UDP over IPv4 & IPv6 from NS_LAN through (--nat out -> GRE -> --nat exit -> WAN)
    ip netns exec "$NS_LAN" python3 -c '
import socket

payload = (b"EasyGRE-UserSpace-NAT-TSO-Test!" * 4096)
for fam, host in [(socket.AF_INET, "198.51.100.80"), (socket.AF_INET6, "2001:db8:99::80")]:
    with socket.socket(fam, socket.SOCK_STREAM) as s:
        s.settimeout(5.0)
        s.connect((host, 9000))
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
        got = bytearray()
        while len(got) < len(payload):
            chunk = s.recv(32768)
            if not chunk:
                break
            got.extend(chunk)
        assert bytes(got) == payload, f"TCP mismatch for {host}: {len(got)} != {len(payload)}"

    with socket.socket(fam, socket.SOCK_DGRAM) as u:
        u.settimeout(3.0)
        u.sendto(b"ping-udp", (host, 9001))
        resp, _ = u.recvfrom(1024)
        assert resp == b"WAN:ping-udp", f"UDP mismatch for {host}: {resp!r}"
'

    # 13c: Verify external WAN host connecting to --dnat TCP 18080 & UDP 18081 on NS_EXB reaches NS_GWA
    ip netns exec "$NS_WAN" python3 -c '
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.settimeout(3.0)
    s.connect(("198.51.100.1", 18080))
    s.sendall(b"hello-tun")
    assert s.recv(1024) == b"DNAT_TCP:hello-tun"

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
    u.settimeout(3.0)
    u.sendto(b"hello-dgram", ("198.51.100.1", 18081))
    resp, _ = u.recvfrom(1024)
    assert resp == b"DNAT_UDP:hello-dgram", f"unexpected DNAT UDP reply: {resp!r}"
'
fi

echo "PASS: EasyGRE Linux end-to-end verification succeeded."
