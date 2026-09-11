export interface ProtocolLayer {
    name: string;
    fields: unknown;
}
export interface NetworkPacket {
    id: number;
    timestamp: number;
    interface?: string;
    length: number;
    capturedLength?: number;
    srcMac?: string;
    dstMac?: string;
    srcIp?: string;
    dstIp?: string;
    ipVersion?: 4 | 6;
    transportProtocol?: string;
    srcPort?: number;
    dstPort?: number;
    applicationProtocol?: string;
    info?: string;
    protocols: string[];
    rawHex?: string;
}
export interface CaptureSession {
    id: string;
    startedAt: number;
    stoppedAt?: number;
    interface: string;
    captureFilter?: string;
    displayFilter?: string;
    packetCount: number;
    byteCount: number;
    filePath: string;
    status: "running" | "paused" | "stopped" | "error";
}
export interface InterfaceInfo {
    name: string;
    ipv4: string[];
    ipv6: string[];
    mac?: string;
    status: string;
    rxBytes: number;
    txBytes: number;
}
export interface Conversation {
    key: string;
    protocol: string;
    endpointA: string;
    endpointB: string;
    portA?: number;
    portB?: number;
    packetsAToB: number;
    packetsBToA: number;
    bytesAToB: number;
    bytesBToA: number;
    startedAt: number;
    lastAt: number;
}
export interface Endpoint {
    address: string;
    mac?: string;
    packetsSent: number;
    packetsReceived: number;
    bytesSent: number;
    bytesReceived: number;
    protocols: string[];
    ports: number[];
}
export interface Device extends Endpoint {
    peers: string[];
}
export interface DnsRecord {
    timestamp: number;
    client?: string;
    server?: string;
    query?: string;
    queryType?: string;
    response?: string;
    status?: string;
}
export interface MqttRecord {
    timestamp: number;
    broker?: string;
    client?: string;
    messageType?: string;
    topic?: string;
    qos?: string;
    retain?: string;
    payloadSize?: number;
    payload?: string;
}
