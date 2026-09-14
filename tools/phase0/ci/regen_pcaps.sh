#!/usr/bin/env bash
#
# regen_pcaps.sh — regenerate the synthetic corpus captures vendored under
# tools/phase0/ci/pcaps/ (issue #216, F-TEST-009).
#
# The corpus covers at least one synthetic capture per required protocol:
#   DNS        dns_query.pcap   (gen_tcpip_pcap.py --pcap dns_query)
#   TLS        tls.pcap         (gen_tcpip_pcap.py --pcap tls)
#   QUIC       quic.pcap        (gen_tcpip_pcap.py --pcap quic)
#   HTTP/2     http2.pcap       (gen_tcpip_pcap.py --pcap http2)
#   DICOM      dicom.pcap       (gen_tcpip_pcap.py --pcap dicom)
#   syslog     syslog.pcap      (gen_tcpip_pcap.py --pcap syslog)
#   PTP        ptp.pcap         (gen_tcpip_pcap.py --pcap ptp)
#   RADIUS     radius.pcap      (gen_mobile_pcap.py --pcap radius)
#   GTP        gtp.pcap         (gen_mobile_pcap.py --pcap gtp)
#   S1AP       s1ap.pcap        (gen_mobile_pcap.py --pcap s1ap)
#   NGAP       ngap.pcap        (gen_mobile_pcap.py --pcap ngap)
#
# After running this, refresh the classification baseline with
# tools/phase0/capture_baseline.sh --golden ci/golden_pcaps.txt
# --datasets ci/pcaps (see tools/phase0/README.md), and commit the pcaps,
# ci/golden_pcaps.txt and ci/baseline/classification*.txt together.
#
# Usage: tools/phase0/ci/regen_pcaps.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE0="$(cd "${HERE}/.." && pwd)"
OUT="${HERE}/pcaps"

for n in dns_query tls quic http2 dicom syslog ptp; do
    python3 "${PHASE0}/gen_tcpip_pcap.py" --out-dir "${OUT}" --pcap "${n}"
done
for n in radius gtp s1ap ngap; do
    python3 "${PHASE0}/gen_mobile_pcap.py" --out-dir "${OUT}" --pcap "${n}"
done

echo "regenerated synthetic corpus under ${OUT}"
