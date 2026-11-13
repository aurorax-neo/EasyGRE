#!/usr/bin/env bash
set -euo pipefail

# Long-duration stability, leak & DDNS live-switch soak test for EasyGRE.
# Usage:
#   sudo SOAK_DURATION_SECS=86400 ./scripts/soak_test.sh [path/to/easygre]

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "soak_test.sh requires Linux with root privileges."
    exit 1
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "Please run soak_test.sh as root."
    exit 1
fi

BIN="${1:-./target/release/easygre}"
if [[ ! -x "$BIN" ]]; then
    cargo build --release
    BIN="./target/release/easygre"
fi

SOAK_DURATION_SECS="${SOAK_DURATION_SECS:-86400}"
SAMPLE_INTERVAL_SECS="${SAMPLE_INTERVAL_SECS:-15}"
MAX_RSS_GROWTH_KB="${MAX_RSS_GROWTH_KB:-32768}"
UDP_RATE="${UDP_RATE:-400M}"

NS_A="easygre_soak_a"
NS_B="easygre_soak_b"
STATUS_A="/tmp/easygre_soak_a.status"
STATUS_B="/tmp/easygre_soak_b.status"
LOG_A="/tmp/easygre_soak_a.log"
LOG_B="/tmp/easygre_soak_b.log"
PID_A=""
PID_B=""
PID_IPERF_SRV=""
PID_TCP_LOAD=""

cleanup() {
    set +e
    for p in "$PID_TCP_LOAD" "$PID_IPERF_SRV"; do
        [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null && wait "$p" 2>/dev/null
    done
    for p in "$PID_A" "$PID_B"; do
        [[ -n "$p" ]] && kill "$p" 2>/dev/null && wait "$p" 2>/dev/null
    done
    ip netns del "$NS_A" 2>/dev/null
    ip netns del "$NS_B" 2>/dev/null
    rm -rf "/etc/netns/$NS_A" "/etc/netns/$NS_B" 2>/dev/null
    rm -f "$STATUS_A" "$STATUS_B" "$LOG_A" "$LOG_B" /tmp/easygre_soak_iperf*.log
}
trap cleanup EXIT

ip netns del "$NS_A" 2>/dev/null || true
ip netns del "$NS_B" 2>/dev/null || true
ip netns add "$NS_A"
ip netns add "$NS_B"

ip link add veth-sa type veth peer name veth-sb
ip link set veth-sa netns "$NS_A"
ip link set veth-sb netns "$NS_B"

ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_A" ip link set veth-sa mtu 1500 up
ip netns exec "$NS_A" ip addr add 192.0.2.1/29 dev veth-sa
ip netns exec "$NS_A" ip route add default via 192.0.2.2 dev veth-sa

ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_B" ip link set veth-sb mtu 1500 up
ip netns exec "$NS_B" ip addr add 192.0.2.2/29 dev veth-sb
ip netns exec "$NS_B" ip addr add 192.0.2.6/29 dev veth-sb

mkdir -p "/etc/netns/$NS_A"
echo "192.0.2.2 soak-peer.gre.test" >"/etc/netns/$NS_A/hosts"

start_peer_b() {
    local bind_ip="$1"
    if [[ -n "$PID_B" ]]; then
        kill "$PID_B" 2>/dev/null || true
        wait "$PID_B" 2>/dev/null || true
    fi
    ip netns exec "$NS_B" "$BIN" \
        --name gre-soak-b \
        --local "$bind_ip" \
        --remote 192.0.2.1 \
        --addr 172.16.99.2/30,fd00:99::2/64 \
        --keepalive 1s,5 \
        --status-file "$STATUS_B" >>"$LOG_B" 2>&1 &
    PID_B=$!
}

ip netns exec "$NS_A" "$BIN" \
    --name gre-soak-a \
    --local 192.0.2.1 \
    --remote soak-peer.gre.test \
    --addr 172.16.99.1/30,fd00:99::1/64 \
    --route 0.0.0.0/0 \
    --dns-refresh 5s \
    --keepalive 1s,5 \
    --status-file "$STATUS_A" >"$LOG_A" 2>&1 &
PID_A=$!

CURRENT_B_IP="192.0.2.2"
start_peer_b "$CURRENT_B_IP"

for _ in $(seq 1 30); do
    if ip netns exec "$NS_A" ip link show gre-soak-a | grep -q "LOWER_UP" \
        && ip netns exec "$NS_B" ip link show gre-soak-b | grep -q "LOWER_UP"; then
        break
    fi
    sleep 0.3
done
"$BIN" healthcheck --status-file "$STATUS_A" >/dev/null
"$BIN" healthcheck --status-file "$STATUS_B" >/dev/null

read_rss_kb() {
    awk '/^VmRSS:/{print $2}' "/proc/$1/status"
}
read_fd_count() {
    ls -1 "/proc/$1/fd" | wc -l | tr -d ' '
}

# Warm up ring/buffers briefly before recording baseline RSS/fd
ip netns exec "$NS_A" ping -c 4 -i 0.1 -W 1 172.16.99.2 >/dev/null
ip netns exec "$NS_A" ping -6 -c 4 -i 0.1 -W 1 fd00:99::2 >/dev/null

start_iperf_srv() {
    if [[ -n "$PID_IPERF_SRV" ]]; then
        kill -9 "$PID_IPERF_SRV" 2>/dev/null || true
        wait "$PID_IPERF_SRV" 2>/dev/null || true
    fi
    ip netns exec "$NS_B" iperf3 -s >/tmp/easygre_soak_iperf_srv.log 2>&1 &
    PID_IPERF_SRV=$!
    sleep 0.2
}

HAVE_IPERF3=0
if command -v iperf3 >/dev/null 2>&1; then
    HAVE_IPERF3=1
    start_iperf_srv
    timeout -k 2 8 ip netns exec "$NS_A" iperf3 -c 172.16.99.2 --connect-timeout 3000 -P 4 -t 2 >/dev/null || start_iperf_srv
fi

BASE_RSS_KB="$(read_rss_kb "$PID_A")"
BASE_FD="$(read_fd_count "$PID_A")"
START_TS="$(date +%s)"
END_TS=$((START_TS + SOAK_DURATION_SECS))
CYCLE=0

echo "[soak] started pid=$PID_A duration=${SOAK_DURATION_SECS}s baseline_rss=${BASE_RSS_KB}kB baseline_fd=${BASE_FD} iperf3=${HAVE_IPERF3}"

while [[ "$(date +%s)" -lt "$END_TS" ]]; do
    CYCLE=$((CYCLE + 1))
    REM=$((END_TS - $(date +%s)))
    WIN="$SAMPLE_INTERVAL_SECS"
    [[ "$REM" -lt "$WIN" ]] && WIN="$REM"
    [[ "$WIN" -le 0 ]] && break

    if [[ "$HAVE_IPERF3" -eq 1 && "$WIN" -ge 3 ]]; then
        TCP_TIME=$((WIN - 1))
        [[ "$TCP_TIME" -gt 10 ]] && TCP_TIME=10
        if ! timeout -k 2 $((TCP_TIME + 6)) ip netns exec "$NS_A" iperf3 -c 172.16.99.2 --connect-timeout 3000 -P 4 -t "$TCP_TIME" >/tmp/easygre_soak_iperf_tcp.log 2>&1; then
            start_iperf_srv
        fi
        if ! timeout -k 2 8 ip netns exec "$NS_A" iperf3 -c 172.16.99.2 --connect-timeout 3000 -u -b "$UDP_RATE" -t 2 >/tmp/easygre_soak_iperf_udp.log 2>&1; then
            start_iperf_srv
        fi
    else
        ip netns exec "$NS_A" ping -c 10 -i 0.1 -W 1 172.16.99.2 >/dev/null
        ip netns exec "$NS_A" ping -6 -c 10 -i 0.1 -W 1 fd00:99::2 >/dev/null
        sleep 1
    fi

    # Exercise live DDNS remote IP rotation every 2 cycles
    if (( CYCLE % 2 == 0 )); then
        if [[ "$CURRENT_B_IP" == "192.0.2.2" ]]; then
            CURRENT_B_IP="192.0.2.6"
        else
            CURRENT_B_IP="192.0.2.2"
        fi
        start_peer_b "$CURRENT_B_IP"
        echo "$CURRENT_B_IP soak-peer.gre.test" >"/etc/netns/$NS_A/hosts"
        for _ in $(seq 1 30); do
            if grep -q "remote_ip=${CURRENT_B_IP}" "$STATUS_A" \
                && ip netns exec "$NS_A" ip link show gre-soak-a | grep -q "LOWER_UP"; then
                break
            fi
            sleep 0.3
        done
        ip netns exec "$NS_A" ping -c 2 -W 1 172.16.99.2 >/dev/null
    fi

    if ! kill -0 "$PID_A" 2>/dev/null; then
        echo "FAIL: easygre daemon exited unexpectedly during soak"
        cat "$LOG_A"
        exit 1
    fi

    CUR_RSS_KB="$(read_rss_kb "$PID_A")"
    CUR_FD="$(read_fd_count "$PID_A")"
    ELAPSED=$(( $(date +%s) - START_TS ))
    "$BIN" healthcheck --status-file "$STATUS_A" >/dev/null

    echo "[soak] t=${ELAPSED}s cycle=${CYCLE} peer=${CURRENT_B_IP} rss=${CUR_RSS_KB}kB fd=${CUR_FD}"

    if (( CUR_FD > BASE_FD + 2 )); then
        echo "FAIL: fd leak detected (baseline=${BASE_FD}, current=${CUR_FD})"
        ls -l "/proc/$PID_A/fd"
        exit 1
    fi
    if (( CUR_RSS_KB > BASE_RSS_KB + MAX_RSS_GROWTH_KB )); then
        echo "FAIL: RSS exceeded growth budget (baseline=${BASE_RSS_KB}kB, current=${CUR_RSS_KB}kB)"
        exit 1
    fi
done

FINAL_RSS_KB="$(read_rss_kb "$PID_A")"
FINAL_FD="$(read_fd_count "$PID_A")"
STATUS_LINE="$(grep $'^tunnel\t' "$STATUS_A")"
echo "[soak] final status: $STATUS_LINE"

for metric in tx_drop=0 rx_drop=0 rx_trunc=0 ka_drop=0; do
    if ! grep -q "$metric" <<<"$STATUS_LINE"; then
        echo "FAIL: expected $metric in final status, got: $STATUS_LINE"
        exit 1
    fi
done

echo "PASS: soak test completed (${SOAK_DURATION_SECS}s, rss ${BASE_RSS_KB}kB -> ${FINAL_RSS_KB}kB, fd ${BASE_FD} -> ${FINAL_FD})."
