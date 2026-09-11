export interface DependencyStatus {
    available: boolean;
    version?: string;
    error?: string;
}
export interface DependencyReport {
    ready: boolean;
    platform: string;
    tshark: DependencyStatus;
    dumpcap: DependencyStatus;
    capturePermission: DependencyStatus;
    instructions: {
        install: string[];
        permissions: string[];
        verify: string[];
    };
}
export declare function checkBinary(binary: "tshark" | "dumpcap"): Promise<DependencyStatus>;
export declare function checkDependencies(): Promise<DependencyReport>;
export declare function validateDisplayFilter(filter: string): Promise<{
    valid: boolean;
    error?: string;
}>;
