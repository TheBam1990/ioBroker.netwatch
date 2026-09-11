import * as utils from "@iobroker/adapter-core";
interface NetwatchConfig {
    captureInterface: string;
    autoStart: boolean;
    memoryPacketLimit: number;
    captureDirectory: string;
    maxCaptureSizeMb: number;
    maxTotalStorageMb: number;
    retentionDays: number;
    webEnabled: boolean;
    webBind: string;
    webPort: number;
    webUsername: string;
    webPassword: string;
    statisticsIntervalSec: number;
}
export declare class Netwatch extends utils.Adapter {
    private packets;
    private aggregator;
    private tshark;
    private capture?;
    private api?;
    private stateTimer?;
    private fileTimer?;
    private deps?;
    private shuttingDown;
    config: NetwatchConfig;
    constructor(options?: Partial<utils.AdapterOptions>);
    private onReady;
    private refreshDependencies;
    private captureDirectory;
    private webPassword;
    private syncStates;
    private enforceStorageLimits;
    private onMessage;
    private onUnload;
}
export {};
