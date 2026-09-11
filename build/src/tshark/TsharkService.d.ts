export declare class TsharkService {
    detail(file: string, id: number): Promise<unknown>;
    hex(file: string, id: number): Promise<string>;
    analyze(file: string, filter?: string, limit?: number): Promise<string>;
    private run;
    fastArgs(): string[];
}
