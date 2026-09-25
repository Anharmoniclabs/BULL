#!/bin/bash
# BULL production adapter: installs the transparent egress gateway.
# Run INSIDE the MicroVM guest (or any Linux host that should have
# system-wide agent egress control). Requires root.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GW_USER="bullgw"
GW_GROUP="bullgw"
CONF_DIR="/etc/bull"
STATE_DIR="/var/lib/bull"

[[ $EUID -eq 0 ]] || { echo "must run as root (sudo)" >&2; exit 1; }
command -v nft >/dev/null || { echo "nft (nftables) not installed" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 not installed" >&2; exit 1; }

echo "[1/6] creating service user ${GW_USER} (the only egress-capable identity)"
if ! id "${GW_USER}" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${GW_USER}"
fi

echo "[2/6] installing gateway modules"
python3 -m pip install --quiet "${REPO_ROOT}" || {
    echo "pip install failed; falling back to copying sources" >&2
    mkdir -p /usr/lib/python3/dist-packages/
    cp -r "${REPO_ROOT}/src/bulldog" /usr/lib/python3/dist-packages/
}

echo "[3/6] installing configuration (${CONF_DIR})"
mkdir -p "${CONF_DIR}" "${STATE_DIR}"
chmod 700 "${STATE_DIR}"; chown "${GW_USER}:${GW_GROUP}" "${STATE_DIR}"
if [[ ! -f "${CONF_DIR}/egress_policy.json" ]]; then
    cat > "${CONF_DIR}/egress_policy.json" <<'EOF'
{
  "hosts": {
    "api.example.com": { "methods": ["GET"], "paths": ["/v1/"] }
  }
}
EOF
    echo "wrote template ${CONF_DIR}/egress_policy.json - EDIT IT (empty allowlist = deny all egress, by design)"
fi
chmod 600 "${CONF_DIR}/egress_policy.json"; chown root:"${GW_GROUP}" "${CONF_DIR}/egress_policy.json"

echo "[4/6] validating and loading nftables ruleset (fail-closed)"
nft -c -f "${REPO_ROOT}/deploy/egress_redirect.nft"
nft -f "${REPO_ROOT}/deploy/egress_redirect.nft"

echo "[5/6] installing systemd units"
install -m 644 "${REPO_ROOT}/deploy/bull-egress-gateway.service" /etc/systemd/system/
cat > /etc/systemd/system/bull-egress-redirect.service <<'EOF'
[Unit]
Description=BULL egress nftables redirect (fail-closed)
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f REPO_ROOT/deploy/egress_redirect.nft
ExecStop=/usr/sbin/nft delete table inet bull_egress
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
sed -i "s|REPO_ROOT|${REPO_ROOT}|g" /etc/systemd/system/bull-egress-redirect.service
systemctl daemon-reload
systemctl enable --now bull-egress-redirect.service

echo "[6/6] starting gateway"
systemctl enable --now bull-egress-gateway.service
sleep 1
systemctl --no-pager --lines=5 status bull-egress-gateway.service || true

echo
echo "Installed. Verification from inside the guest:"
echo "  curl -sS https://api.example.com/v1/data   # allowed (if in policy)"
echo "  curl -sS https://evil.example             # must FAIL (connection reset)"
echo "  dig +short example.com                    # must return REFUSED unless allowlisted"
