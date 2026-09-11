import { describe, it, expect } from "vitest";
import { RingBuffer } from "../src/packets/RingBuffer";
import { parseFieldsLine } from "../src/tshark/TsharkParser";
import {
  resolveCapturePath,
  safeCaptureName,
  validateFilter,
  validateInterface,
} from "../src/security/InputValidator";
import { Aggregator } from "../src/analytics/Aggregator";
describe("security validation", () => {
  it("accepts normal inputs", () => {
    expect(validateInterface("eth0@if12")).toBe("eth0@if12");
    expect(validateFilter("tcp.port == 443 && tls")).toContain("tls");
    expect(safeCaptureName("test-1.pcapng")).toBe("test-1.pcapng");
  });
  it("rejects traversal and control characters", () => {
    expect(() => safeCaptureName("../../etc/passwd")).toThrow();
    expect(() => resolveCapturePath("/tmp/captures", "../x.pcap")).toThrow();
    expect(() => validateFilter("tcp\n-r /etc/passwd")).toThrow();
    expect(() => validateInterface("eth0;id")).toThrow();
  });
});
describe("ring buffer", () => {
  it("stays bounded", () => {
    const b = new RingBuffer<number>(2);
    b.push(1);
    b.push(2);
    b.push(3);
    expect(b.values()).toEqual([2, 3]);
  });
});
describe("tshark parser", () => {
  it("normalizes fast fields", () => {
    const fields = [
      "42",
      "1720000000.125",
      "100",
      "96",
      "aa:bb:cc:dd:ee:ff",
      "11:22:33:44:55:66",
      "192.168.1.2",
      "8.8.8.8",
      "",
      "",
      "52123",
      "443",
      "",
      "",
      "TLSv1.3",
      "Client Hello",
      "eth:ethertype:ip:tcp:tls",
      "",
    ]
      .map((x) => `"${x}"`)
      .join("\t");
    const p = parseFieldsLine(fields, "eth0")!;
    expect(p).toMatchObject({
      id: 42,
      srcIp: "192.168.1.2",
      dstIp: "8.8.8.8",
      srcPort: 52123,
      dstPort: 443,
      transportProtocol: "TCP",
      applicationProtocol: "TLSv1.3",
    });
  });
});
describe("aggregation", () => {
  it("aggregates both directions", () => {
    const a = new Aggregator(),
      base = {
        id: 1,
        timestamp: 1000,
        length: 100,
        srcIp: "1.1.1.1",
        dstIp: "2.2.2.2",
        srcPort: 1,
        dstPort: 2,
        transportProtocol: "TCP",
        protocols: ["ip", "tcp"],
      };
    a.add(base);
    a.add({
      ...base,
      id: 2,
      timestamp: 2000,
      srcIp: "2.2.2.2",
      dstIp: "1.1.1.1",
      srcPort: 2,
      dstPort: 1,
      length: 50,
    });
    const c = a.snapshot().conversations[0];
    expect(c.packetsAToB + c.packetsBToA).toBe(2);
    expect(c.bytesAToB + c.bytesBToA).toBe(150);
    expect(a.snapshot().devices).toHaveLength(2);
  });
});
