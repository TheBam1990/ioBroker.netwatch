import type { NetworkPacket } from "../types";
import type { CaptureManager } from "../capture/CaptureManager";
import type { RingBuffer } from "../packets/RingBuffer";
import type { Aggregator } from "../analytics/Aggregator";
import type { TsharkService } from "../tshark/TsharkService";
export interface ApiOptions {
    host: string;
    port: number;
    username: string;
    password: string;
    webRoot: string;
    captureDirectory: string;
    maxUploadMb: number;
}
export declare class ApiServer {
    private options;
    private capture;
    private packets;
    private aggregator;
    private tshark;
    private dependencies;
    private recheckDependencies;
    private app;
    private server?;
    private wss?;
    private batch;
    private batchTimer?;
    constructor(options: ApiOptions, capture: CaptureManager, packets: RingBuffer<NetworkPacket>, aggregator: Aggregator, tshark: TsharkService, dependencies: () => unknown, recheckDependencies: () => Promise<unknown>);
    private authorized;
    private auth;
    private configure;
    start(): Promise<void>;
    private flush;
    private broadcast;
    stop(): Promise<void>;
}
