"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseFieldsLine = parseFieldsLine;
const number = (v) => v === "" ? undefined : Number(v);
const first = (v) => v ? String(v).split(",")[0] : undefined;
function parseFieldsLine(line, iface) {
    if (!line.trim()) {
        return null;
    }
    const f = line
        .replace(/\r$/, "")
        .split("\t")
        .map((v) => v.replace(/^"|"$/g, "").replace(/""/g, '"'));
    if (f.length < 14) {
        return null;
    }
    const protocols = (f[16] || "").split(":").filter(Boolean), transport = f[10] || f[11]
        ? "TCP"
        : f[12] || f[13]
            ? "UDP"
            : protocols.includes("icmpv6")
                ? "ICMPv6"
                : protocols.includes("icmp")
                    ? "ICMP"
                    : undefined;
    return {
        id: Number(f[0]),
        timestamp: Number(f[1]) * 1000,
        interface: iface,
        length: Number(f[2]) || 0,
        capturedLength: number(f[3]),
        srcMac: first(f[4]),
        dstMac: first(f[5]),
        srcIp: first(f[6]) || first(f[8]),
        dstIp: first(f[7]) || first(f[9]),
        ipVersion: f[6] || f[7] ? 4 : f[8] || f[9] ? 6 : undefined,
        srcPort: number(first(f[10]) || first(f[12]) || ""),
        dstPort: number(first(f[11]) || first(f[13]) || ""),
        transportProtocol: transport,
        applicationProtocol: f[14] || protocols.at(-1)?.toUpperCase(),
        info: f[15],
        protocols,
        rawHex: f[17]?.replace(/:/g, "") || undefined,
    };
}
//# sourceMappingURL=TsharkParser.js.map