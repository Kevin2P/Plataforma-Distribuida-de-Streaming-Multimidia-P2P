#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "uso: sudo $0 [repeticoes]" >&2
    exit 1
fi
cd "$(dirname "$0")/.."
NS=streamp2p-loss
REPS=${1:-2}
OUT=results/loss_netem.csv
RUN_AS=${SUDO_USER:-root}

ip netns add "$NS"
trap 'ip netns del "$NS"' EXIT
ip netns exec "$NS" ip link set dev lo up mtu 1500
ip netns exec "$NS" ethtool -K lo tso off gso off
ip netns exec "$NS" tc qdisc add dev lo root netem loss 0%
rm -f "$OUT"
for p in 0 2 5 10 20 30; do
    echo "perda de $p%"
    ip netns exec "$NS" tc qdisc change dev lo root netem loss "$p%"
    ip netns exec "$NS" sudo -u "$RUN_AS" python3 scripts/run_netem.py "$p" "$OUT" "$REPS"
done
echo "resultados em $OUT"
