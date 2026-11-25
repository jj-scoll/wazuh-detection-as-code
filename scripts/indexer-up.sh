#!/usr/bin/env bash
# Start a throwaway single-node Wazuh 5.0 indexer (the engine runs inside it)
# for the parity suite, and write connection settings to .wazuh/env.
#
# The admin password is random per run and only lives in .wazuh/ (gitignored).
# TLS stays on: the client trusts the container's own root CA.
#
# Usage: scripts/indexer-up.sh            # start (replaces any previous one)
#        scripts/indexer-up.sh down       # remove the container
set -euo pipefail

image="${WAZUH_INDEXER_IMAGE:-wazuh/wazuh-indexer:5.0.0-rc2}"
name="${WAZUH_INDEXER_CONTAINER:-dac-wazuh-indexer}"
port="${WAZUH_INDEXER_PORT:-19200}"
state="$(cd "$(dirname "$0")/.." && pwd)/.wazuh"

if [[ "${1:-}" == "down" ]]; then
  docker rm -f "$name" >/dev/null 2>&1 || true
  echo "removed $name"
  exit 0
fi

mkdir -p "$state"
rand_hex() { od -An -N12 -tx1 /dev/urandom | tr -d " \n"; }
password="Dac-$(rand_hex)-A1"
docker rm -f "$name" >/dev/null 2>&1 || true

# bootstrap.memory_lock=false: CI runners (and rootless Docker) can't raise
# RLIMIT_MEMLOCK, and the image enables memory locking by default.
docker run -d --name "$name" -p "127.0.0.1:${port}:9200" \
  -e bootstrap.memory_lock=false \
  -e OPENSEARCH_JAVA_OPTS="-Xms1g -Xmx1g" \
  -e WAZUH_INDEXER_ADMIN_PASSWORD="$password" \
  -e WAZUH_INDEXER_KIBANASERVER_PASSWORD="Dac-$(rand_hex)-K1" \
  -e WAZUH_INDEXER_MANAGER_PASSWORD="Dac-$(rand_hex)-M1" \
  "$image" >/dev/null

url="https://127.0.0.1:${port}"
wait_for() { # wait_for <description> <seconds> <command...>
  local what="$1" secs="$2"; shift 2
  for ((i = 0; i < secs; i += 3)); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    if [[ "$(docker inspect -f '{{.State.Status}}' "$name")" != running ]]; then
      docker logs --tail 30 "$name" >&2
      echo "indexer container exited while waiting for: $what" >&2
      return 1
    fi
    sleep 3
  done
  echo "timed out after ${secs}s waiting for: $what" >&2
  return 1
}

# The image issues its certificates on first start; copy the CA out once it exists.
wait_for "certificates" 120 docker exec "$name" test -s /usr/share/wazuh-indexer/config/certs/root-ca.pem
docker cp -q "$name:/usr/share/wazuh-indexer/config/certs/root-ca.pem" "$state/root-ca.pem"

# HTTP up (503 "Security not initialized" is fine at this point).
wait_for "HTTPS listener" 180 curl -s --cacert "$state/root-ca.pem" -o /dev/null "$url"

# The security index is not created automatically in this image. The init
# script expects the package layout (/etc/wazuh-indexer), so point it there.
docker exec "$name" sh -c 'ln -sfn /usr/share/wazuh-indexer/config /etc/wazuh-indexer &&
  bash /usr/share/wazuh-indexer/bin/indexer-security-init.sh' >/dev/null

cluster_ready() {
  curl -sf --cacert "$state/root-ca.pem" -u "admin:${password}" \
    "$url/_cluster/health?wait_for_status=yellow&timeout=5s" | grep -Eq '"status":"(green|yellow)"'
}
wait_for "cluster health" 120 cluster_ready

umask 077
cat > "$state/env" <<EOF
WAZUH_INDEXER_URL=$url
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=$password
WAZUH_INDEXER_CA=$state/root-ca.pem
EOF
echo "indexer $image ready at $url; settings in .wazuh/env"
