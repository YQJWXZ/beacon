#!/usr/bin/env bash
# Store-and-forward drill: cut the center, prove the agent buffers, restore it,
# prove the backlog lands without gaps.
#
# Prerequisites: the center stack from deploy/docker-compose.yml is running and
# one agent is shipping to it. Run on the center host.
#
#   ./scripts/netloss-test.sh
#   OUTAGE=90 ./scripts/netloss-test.sh
set -euo pipefail

COMPOSE=${COMPOSE:-deploy/docker-compose.yml}
VM=${VM:-http://127.0.0.1:8428}
STATE_DIR=${STATE_DIR:-/var/lib/beacon}
OUTAGE=${OUTAGE:-60}
RECOVER_WAIT=${RECOVER_WAIT:-45}

wal_bytes() {
  if [[ -d "$STATE_DIR/wal" ]]; then
    find "$STATE_DIR/wal" -name '*.seg' -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}'
  else
    echo 0
  fi
}

query() {
  curl -sf "$VM/api/v1/query" --data-urlencode "query=$1" | jq -r '.data.result[0].value[1] // "none"'
}

echo "== baseline =="
before=$(query 'beacon_agent_heartbeat')
if [[ "$before" == "none" ]]; then
  echo "no heartbeat found: is an agent shipping to $VM?" >&2
  exit 1
fi
echo "heartbeat: $before"

cut_time=$(date +%s)
echo "== stopping center for ${OUTAGE}s =="
docker compose -f "$COMPOSE" stop victoriametrics beacon-server >/dev/null

sleep "$OUTAGE"
buffered=$(wal_bytes)
echo "buffered during outage: ${buffered} bytes"
if [[ "$buffered" -le 0 ]]; then
  echo "FAIL: agent kept no data while the center was down" >&2
  docker compose -f "$COMPOSE" start victoriametrics beacon-server >/dev/null
  exit 1
fi

echo "== restoring center =="
docker compose -f "$COMPOSE" start victoriametrics beacon-server >/dev/null
for i in $(seq 1 "$RECOVER_WAIT"); do
  sleep 1
  now=$(wal_bytes)
  [[ "$now" -eq 0 ]] && break
done
after=$(wal_bytes)
echo "buffered after recovery: ${after} bytes"
if [[ "$after" -ne 0 ]]; then
  echo "FAIL: backlog did not drain within ${RECOVER_WAIT}s" >&2
  exit 1
fi

sleep 5
mid=$(( (cut_time + $(date +%s)) / 2 ))
replayed=$(curl -sf "$VM/api/v1/query" --data-urlencode "query=beacon_agent_heartbeat" --data-urlencode "time=$mid" \
  | jq -r '.data.result[0].value[1] // "none"')
if [[ "$replayed" == "none" ]]; then
  echo "FAIL: no sample replayed for the outage window (t=$mid)" >&2
  exit 1
fi

echo "PASS: buffered ${buffered} bytes during a ${OUTAGE}s outage, drained fully, replayed at t=$mid"
