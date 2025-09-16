import { Request, Response, NextFunction } from 'express';

/**
 * Metric types
 */
export enum MetricType {
    COUNTER = 'counter',
    GAUGE = 'gauge',
    HISTOGRAM = 'histogram',
    TIMER = 'timer'
}

/**
 * Metric interface
 */
export interface Metric {
    name: string;
    type: MetricType;
    value: number;
    labels?: Record<string, string>;
    timestamp: Date;
}

/**
 * Metrics collector configuration
 */
export interface MetricsConfig {
    enableConsoleMetrics?: boolean;
    enableFileMetrics?: boolean;
    metricsFilePath?: string;
    enableRemoteMetrics?: boolean;
    remoteEndpoint?: string;
    collectionInterval?: number; // in milliseconds
    enableRequestMetrics?: boolean;
    enableAuthMetrics?: boolean;
    enablePerformanceMetrics?: boolean;
}

/**
 * Metrics collector class
 */
export class MetricsCollector {
    private config: MetricsConfig;
    private metrics: Map<string, Metric> = new Map();
    private intervalId?: NodeJS.Timeout;
    private fs = require('fs');
    private path = require('path');

    constructor(config: MetricsConfig = {}) {
        this.config = {
            enableConsoleMetrics: true,
            enableFileMetrics: false,
            metricsFilePath: './metrics.log',
            collectionInterval: 60000, // 1 minute
            enableRequestMetrics: true,
            enableAuthMetrics: true,
            enablePerformanceMetrics: true,
            ...config
        };

        if (this.config.collectionInterval) {
            this.startCollection();
        }
    }

    /**
     * Record a metric
     */
    record(name: string, value: number, type: MetricType = MetricType.COUNTER, labels?: Record<string, string>): void {
        const metric: Metric = {
            name,
            type,
            value,
            labels,
            timestamp: new Date()
        };

        this.metrics.set(name, metric);
    }

    /**
     * Increment a counter metric
     */
    increment(name: string, labels?: Record<string, string>): void {
        const existing = this.metrics.get(name);
        const value = existing ? existing.value + 1 : 1;
        this.record(name, value, MetricType.COUNTER, labels);
    }

    /**
     * Set a gauge metric
     */
    gauge(name: string, value: number, labels?: Record<string, string>): void {
        this.record(name, value, MetricType.GAUGE, labels);
    }

    /**
     * Record a histogram metric
     */
    histogram(name: string, value: number, labels?: Record<string, string>): void {
        this.record(name, value, MetricType.HISTOGRAM, labels);
    }

    /**
     * Start a timer and return a function to stop it
     */
    timer(name: string, labels?: Record<string, string>): () => void {
        const startTime = Date.now();
        return () => {
            const duration = Date.now() - startTime;
            this.record(name, duration, MetricType.TIMER, labels);
        };
    }

    /**
     * Get all metrics
     */
    getAllMetrics(): Metric[] {
        return Array.from(this.metrics.values());
    }

    /**
     * Get metrics by name
     */
    getMetric(name: string): Metric | undefined {
        return this.metrics.get(name);
    }

    /**
     * Clear all metrics
     */
    clear(): void {
        this.metrics.clear();
    }

    /**
     * Create Express middleware for automatic request metrics
     */
    createRequestMetricsMiddleware() {
        return (req: Request, res: Response, next: NextFunction) => {
            if (!this.config.enableRequestMetrics) {
                return next();
            }

            const startTime = Date.now();
            const originalSend = res.send;
            const originalJson = res.json;
            const self = this;

            // Override response methods to capture metrics
            res.send = function (body: any) {
                self.recordRequestMetrics(req, res, startTime);
                return originalSend.call(this, body);
            };

            res.json = function (body: any) {
                self.recordRequestMetrics(req, res, startTime);
                return originalJson.call(this, body);
            };

            next();
        };
    }

    /**
     * Record authentication metrics
     */
    recordAuthSuccess(userId: string, method: string): void {
        if (!this.config.enableAuthMetrics) return;

        this.increment('auth_success_total', { method, user_id: userId });
        this.increment('auth_success_by_method', { method });
    }

    recordAuthFailure(method: string, reason: string): void {
        if (!this.config.enableAuthMetrics) return;

        this.increment('auth_failure_total', { method, reason });
        this.increment('auth_failure_by_reason', { reason });
    }

    recordTokenGenerated(tokenType: 'access' | 'refresh', userId: string): void {
        if (!this.config.enableAuthMetrics) return;

        this.increment('tokens_generated_total', { type: tokenType, user_id: userId });
        this.increment('tokens_generated_by_type', { type: tokenType });
    }

    recordTokenVerified(tokenType: 'access' | 'refresh', success: boolean): void {
        if (!this.config.enableAuthMetrics) return;

        this.increment('tokens_verified_total', { type: tokenType, success: success.toString() });
    }

    recordTokenBlacklisted(tokenType: 'access' | 'refresh', userId: string): void {
        if (!this.config.enableAuthMetrics) return;

        this.increment('tokens_blacklisted_total', { type: tokenType, user_id: userId });
    }

    recordPasswordHashed(userId: string): void {
        if (!this.config.enableAuthMetrics) return;

        this.increment('passwords_hashed_total', { user_id: userId });
    }

    recordPasswordVerified(userId: string, success: boolean): void {
        if (!this.config.enableAuthMetrics) return;

        this.increment('passwords_verified_total', { user_id: userId, success: success.toString() });
    }

    recordRateLimitExceeded(endpoint: string, ip: string): void {
        if (!this.config.enableAuthMetrics) return;

        this.increment('rate_limit_exceeded_total', { endpoint, ip });
    }

    recordPermissionDenied(userId: string, permission: string): void {
        if (!this.config.enableAuthMetrics) return;

        this.increment('permission_denied_total', { user_id: userId, permission });
    }

    recordTenantAccess(tenantId: string, userId: string, success: boolean): void {
        if (!this.config.enableAuthMetrics) return;

        this.increment('tenant_access_total', { tenant_id: tenantId, user_id: userId, success: success.toString() });
    }

    // Private methods

    private startCollection(): void {
        this.intervalId = setInterval(() => {
            this.collectAndExport();
        }, this.config.collectionInterval);
    }

    private stopCollection(): void {
        if (this.intervalId) {
            clearInterval(this.intervalId);
            this.intervalId = undefined;
        }
    }

    private collectAndExport(): void {
        const metrics = this.getAllMetrics();

        if (this.config.enableConsoleMetrics) {
            this.exportToConsole(metrics);
        }

        if (this.config.enableFileMetrics) {
            this.exportToFile(metrics);
        }

        if (this.config.enableRemoteMetrics) {
            this.exportToRemote(metrics);
        }
    }

    private exportToConsole(metrics: Metric[]): void {
        console.log('\n=== METRICS ===');
        metrics.forEach(metric => {
            console.log(`${metric.name}: ${metric.value} (${metric.type}) ${metric.labels ? JSON.stringify(metric.labels) : ''}`);
        });
        console.log('===============\n');
    }

    private exportToFile(metrics: Metric[]): void {
        try {
            const timestamp = new Date().toISOString();
            const logEntry = `[${timestamp}] ${JSON.stringify(metrics)}\n`;
            this.fs.appendFileSync(this.config.metricsFilePath!, logEntry);
        } catch (error) {
            console.error('Failed to write metrics to file:', error);
        }
    }

    private async exportToRemote(metrics: Metric[]): Promise<void> {
        try {
            const https = require('https');
            const http = require('http');

            const data = JSON.stringify({ metrics, timestamp: new Date().toISOString() });
            const url = new URL(this.config.remoteEndpoint!);
            const isHttps = url.protocol === 'https:';
            const client = isHttps ? https : http;

            const options = {
                hostname: url.hostname,
                port: url.port || (isHttps ? 443 : 80),
                path: url.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(data)
                }
            };

            const req = client.request(options, (res: any) => {
                // Response handled
            });

            req.on('error', (error: any) => {
                console.error('Failed to send metrics to remote endpoint:', error);
            });

            req.write(data);
            req.end();
        } catch (error) {
            console.error('Failed to send metrics to remote endpoint:', error);
        }
    }

    private recordRequestMetrics(req: Request, res: Response, startTime: number): void {
        const duration = Date.now() - startTime;
        const statusCode = res.statusCode;
        const method = req.method;
        const endpoint = req.path;

        // Record request count
        this.increment('requests_total', { method, endpoint, status: statusCode.toString() });

        // Record request duration
        this.histogram('request_duration_ms', duration, { method, endpoint, status: statusCode.toString() });

        // Record response size if available
        if (res.get('Content-Length')) {
            const contentLength = parseInt(res.get('Content-Length') || '0', 10);
            this.histogram('response_size_bytes', contentLength, { method, endpoint, status: statusCode.toString() });
        }

        // Record error rates
        if (statusCode >= 400) {
            this.increment('errors_total', { method, endpoint, status: statusCode.toString() });
        }

        // Record 5xx errors separately
        if (statusCode >= 500) {
            this.increment('server_errors_total', { method, endpoint, status: statusCode.toString() });
        }
    }

    /**
     * Get metrics summary
     */
    getSummary(): Record<string, any> {
        const metrics = this.getAllMetrics();
        const summary: Record<string, any> = {};

        metrics.forEach(metric => {
            if (!summary[metric.name]) {
                summary[metric.name] = {
                    total: 0,
                    count: 0,
                    average: 0,
                    min: Infinity,
                    max: -Infinity
                };
            }

            const stat = summary[metric.name];
            stat.total += metric.value;
            stat.count++;
            stat.average = stat.total / stat.count;
            stat.min = Math.min(stat.min, metric.value);
            stat.max = Math.max(stat.max, metric.value);
        });

        return summary;
    }

    /**
     * Cleanup
     */
    destroy(): void {
        this.stopCollection();
        this.clear();
    }
}

/**
 * Default metrics collector instance
 */
export const metricsCollector = new MetricsCollector();
