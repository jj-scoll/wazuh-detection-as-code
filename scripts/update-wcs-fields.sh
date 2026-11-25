#!/usr/bin/env bash
# Regenerate schema/wcs-fields.txt (field name + type) from the Wazuh Common
# Schema published in wazuh/wazuh-indexer-plugins at the given tag.
# Usage: scripts/update-wcs-fields.sh v5.0.0-rc2
set -euo pipefail

tag="${1:?usage: $0 <wazuh-indexer-plugins tag, e.g. v5.0.0-rc2>}"
path="wcs/stateless/events/main/docs/fields.csv"
url="https://raw.githubusercontent.com/wazuh/wazuh-indexer-plugins/${tag}/${path}"
out="$(dirname "$0")/../schema/wcs-fields.txt"

csv="$(mktemp)"
trap 'rm -f "$csv"' EXIT
curl -fsSL "$url" -o "$csv"

# Columns 1-5 (ECS_Version,Indexed,Field_Set,Field,Type) never contain commas;
# only later columns are quoted.
{
  echo "# Wazuh Common Schema (WCS) event fields, name and type only."
  echo "# Source: wazuh/wazuh-indexer-plugins@${tag} ${path}"
  echo "# sha256 of source: $(sha256sum "$csv" | cut -c1-64)"
  echo "# Regenerate: scripts/update-wcs-fields.sh ${tag}"
  awk -F, 'NR > 1 { print $4, $5 }' "$csv" | sort -u
} > "$out"
echo "wrote $(grep -vc '^#' "$out") fields to $out"
