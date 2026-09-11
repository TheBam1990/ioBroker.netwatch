import type { Conversation, Device, Endpoint, NetworkPacket } from "../types";
export declare class Aggregator {
    private conversations;
    private endpoints;
    private devices;
    private protocols;
    add(p: NetworkPacket): void;
    private endpoint;
    private device;
    clear(): void;
    snapshot(): {
        conversations: Conversation[];
        endpoints: Endpoint[];
        devices: Device[];
        protocols: Record<string, number>;
    };
}
