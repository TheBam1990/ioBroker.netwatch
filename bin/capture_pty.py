#!/usr/bin/env python3
import os
import pty
import signal

fields = [
    "-T", "fields", "-E", "separator=/t", "-E", "quote=d",
    "-E", "occurrence=f", "-e", "frame.number", "-e", "frame.time_epoch",
    "-e", "frame.len", "-e", "frame.cap_len", "-e", "eth.src", "-e", "eth.dst",
    "-e", "ip.src", "-e", "ip.dst", "-e", "ipv6.src", "-e", "ipv6.dst",
    "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport",
    "-e", "udp.dstport", "-e", "_ws.col.Protocol", "-e", "_ws.col.Info",
    "-e", "frame.protocols", "-e", "data.data",
]
args = ["tshark", "-l", "-n", "-i", os.environ["NW_INTERFACE"],
        "-w", os.environ["NW_CAPTURE_FILE"], "-P"]
capture_filter = os.environ.get("NW_CAPTURE_FILTER", "")
if capture_filter:
    args += ["-f", capture_filter]
args += fields

pid, master = pty.fork()
if pid == 0:
    os.execvp(args[0], args)

def forward(sig, _frame):
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        pass

for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(sig, forward)

with open(os.environ["NW_EVENT_FILE"], "ab", buffering=0) as output:
    while True:
        try:
            data = os.read(master, 65536)
            if not data:
                break
            output.write(data)
        except OSError:
            break

_, status = os.waitpid(pid, 0)
raise SystemExit(os.waitstatus_to_exitcode(status))
