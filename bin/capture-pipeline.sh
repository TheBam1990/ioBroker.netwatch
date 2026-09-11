#!/bin/sh
set -eu
# Values are supplied as environment variables and always expanded as one quoted
# argument. The command executed by `script -c` is this fixed helper path only.
if [ -n "${NW_CAPTURE_FILTER:-}" ]; then
  tail -f /dev/null | tshark -l -n -i "$NW_INTERFACE" -f "$NW_CAPTURE_FILTER" \
    -w "$NW_CAPTURE_FILE" -P -T fields -E separator=/t -E quote=d \
    -E occurrence=f -e frame.number -e frame.time_epoch -e frame.len \
    -e frame.cap_len -e eth.src -e eth.dst -e ip.src -e ip.dst \
    -e ipv6.src -e ipv6.dst -e tcp.srcport -e tcp.dstport \
    -e udp.srcport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info \
    -e frame.protocols -e data.data >"$NW_EVENT_FILE"
else
  tail -f /dev/null | tshark -l -n -i "$NW_INTERFACE" -w "$NW_CAPTURE_FILE" -P \
    -T fields -E separator=/t -E quote=d -E occurrence=f \
    -e frame.number -e frame.time_epoch -e frame.len -e frame.cap_len \
    -e eth.src -e eth.dst -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst \
    -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
    -e _ws.col.Protocol -e _ws.col.Info -e frame.protocols -e data.data \
    >"$NW_EVENT_FILE"
fi
