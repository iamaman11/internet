#!/bin/sh
# One-shot preparation in the EXISTING warp-egress container, no daemon/agent.
set -eu
if [ "$(id -u)" != "1000" ]; then
    echo "GOST_GUARD_UID_MISMATCH" >&2
    exit 1
fi
if ! sudo nft -f /etc/internet/gost-egress-guard.nft; then
    echo "GOST_GUARD_INSTALL_FAILED" >&2
    exit 1
fi
if ! sudo nft list chain inet internet_gost_guard output >/dev/null; then
    echo "GOST_GUARD_READBACK_FAILED" >&2
    exit 1
fi
# Preserve the stock WARP and GOST startup path; no second supervisor.
exec /entrypoint.sh
