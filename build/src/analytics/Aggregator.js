"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Aggregator = void 0;
class Aggregator {
    conversations = new Map();
    endpoints = new Map();
    devices = new Map();
    protocols = new Map();
    add(p) {
        const proto = (p.applicationProtocol ||
            p.transportProtocol ||
            "OTHER").toUpperCase();
        this.protocols.set(proto, (this.protocols.get(proto) || 0) + 1);
        if (!p.srcIp || !p.dstIp) {
            return;
        }
        this.endpoint(p.srcIp, p.srcMac, p, true, p.length);
        this.endpoint(p.dstIp, p.dstMac, p, false, p.length);
        this.device(p.srcIp, p.srcMac, p.dstIp, p, true);
        this.device(p.dstIp, p.dstMac, p.srcIp, p, false);
        const a = `${p.srcIp}:${p.srcPort || 0}`, b = `${p.dstIp}:${p.dstPort || 0}`, forward = a.localeCompare(b) <= 0, key = `${p.transportProtocol || "IP"}|${forward ? a : b}|${forward ? b : a}`;
        let c = this.conversations.get(key);
        if (!c) {
            c = {
                key,
                protocol: p.transportProtocol || "IP",
                endpointA: forward ? p.srcIp : p.dstIp,
                endpointB: forward ? p.dstIp : p.srcIp,
                portA: forward ? p.srcPort : p.dstPort,
                portB: forward ? p.dstPort : p.srcPort,
                packetsAToB: 0,
                packetsBToA: 0,
                bytesAToB: 0,
                bytesBToA: 0,
                startedAt: p.timestamp,
                lastAt: p.timestamp,
            };
            this.conversations.set(key, c);
        }
        if (forward) {
            c.packetsAToB++;
            c.bytesAToB += p.length;
        }
        else {
            c.packetsBToA++;
            c.bytesBToA += p.length;
        }
        c.lastAt = p.timestamp;
    }
    endpoint(address, mac, p, sent, bytes) {
        let e = this.endpoints.get(address);
        if (!e) {
            e = {
                address,
                mac,
                packetsSent: 0,
                packetsReceived: 0,
                bytesSent: 0,
                bytesReceived: 0,
                protocols: [],
                ports: [],
            };
            this.endpoints.set(address, e);
        }
        if (sent) {
            e.packetsSent++;
            e.bytesSent += bytes;
        }
        else {
            e.packetsReceived++;
            e.bytesReceived += bytes;
        }
        const proto = p.applicationProtocol || p.transportProtocol;
        if (proto && !e.protocols.includes(proto)) {
            e.protocols.push(proto);
        }
        for (const port of [p.srcPort, p.dstPort]) {
            if (port && !e.ports.includes(port)) {
                e.ports.push(port);
            }
        }
    }
    device(address, mac, peer, p, sent) {
        let d = this.devices.get(address);
        if (!d) {
            d = {
                address,
                mac,
                packetsSent: 0,
                packetsReceived: 0,
                bytesSent: 0,
                bytesReceived: 0,
                protocols: [],
                ports: [],
                peers: [],
            };
            this.devices.set(address, d);
        }
        if (sent) {
            d.packetsSent++;
            d.bytesSent += p.length;
        }
        else {
            d.packetsReceived++;
            d.bytesReceived += p.length;
        }
        if (!d.peers.includes(peer)) {
            d.peers.push(peer);
        }
        const proto = p.applicationProtocol || p.transportProtocol;
        if (proto && !d.protocols.includes(proto)) {
            d.protocols.push(proto);
        }
    }
    clear() {
        this.conversations.clear();
        this.endpoints.clear();
        this.devices.clear();
        this.protocols.clear();
    }
    snapshot() {
        return {
            conversations: [...this.conversations.values()],
            endpoints: [...this.endpoints.values()],
            devices: [...this.devices.values()],
            protocols: Object.fromEntries(this.protocols),
        };
    }
}
exports.Aggregator = Aggregator;
//# sourceMappingURL=Aggregator.js.map