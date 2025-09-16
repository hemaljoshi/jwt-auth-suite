import { Request, Response, NextFunction } from 'express';

/**
 * Security event types
 */
export enum SecurityEventType {
    LOGIN_SUCCESS = 'LOGIN_SUCCESS',
    LOGIN_FAILURE = 'LOGIN_FAILURE',
    LOGOUT = 'LOGOUT',
    TOKEN_GENERATED = 'TOKEN_GENERATED',
    TOKEN_REFRESHED = 'TOKEN_REFRESHED',
    TOKEN_BLACKLISTED = 'TOKEN_BLACKLISTED',
    PASSWORD_CHANGED = 'PASSWORD_CHANGED',
    PASSWORD_RESET_REQUESTED = 'PASSWORD_RESET_REQUESTED',
    RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
    SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
    PERMISSION_DENIED = 'PERMISSION_DENIED',
    INVALID_TOKEN = 'INVALID_TOKEN',
    EXPIRED_TOKEN = 'EXPIRED_TOKEN',
    TENANT_ACCESS_DENIED = 'TENANT_ACCESS_DENIED'
}

/**
 * Security event interface
 */
export interface SecurityEvent {
    type: SecurityEventType;
    userId?: string;
    tenantId?: string;
    ip: string;
    userAgent: string;
    timestamp: Date;
    details: Record<string, any>;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

/**
 * Security logger configuration
 */
export interface SecurityLoggerConfig {
    enableConsoleLogging?: boolean;
    enableFileLogging?: boolean;
    logFilePath?: string;
    enableRemoteLogging?: boolean;
    remoteEndpoint?: string;
    logLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    enableIPFiltering?: boolean;
    allowedIPs?: string[];
    enableUserAgentFiltering?: boolean;
    allowedUserAgents?: string[];
}

/**
 * Security logger class
 */
export class SecurityLogger {
    private config: SecurityLoggerConfig;
    private fs = require('fs');
    private path = require('path');

    constructor(config: SecurityLoggerConfig = {}) {
        this.config = {
            enableConsoleLogging: true,
            enableFileLogging: false,
            logFilePath: './security.log',
            enableRemoteLogging: false,
            logLevel: 'LOW',
            enableIPFiltering: false,
            enableUserAgentFiltering: false,
            ...config
        };
    }

    /**
     * Log a security event
     */
    log(event: Omit<SecurityEvent, 'timestamp'>): void {
        const fullEvent: SecurityEvent = {
            ...event,
            timestamp: new Date()
        };

        // Check if event should be logged based on severity
        if (!this.shouldLogEvent(fullEvent)) {
            return;
        }

        // Check IP filtering
        if (this.config.enableIPFiltering && this.config.allowedIPs) {
            if (!this.config.allowedIPs.includes(fullEvent.ip)) {
                return;
            }
        }

        // Check User Agent filtering
        if (this.config.enableUserAgentFiltering && this.config.allowedUserAgents) {
            if (!this.config.allowedUserAgents.some(ua => fullEvent.userAgent.includes(ua))) {
                return;
            }
        }

        // Console logging
        if (this.config.enableConsoleLogging) {
            this.logToConsole(fullEvent);
        }

        // File logging
        if (this.config.enableFileLogging) {
            this.logToFile(fullEvent);
        }

        // Remote logging
        if (this.config.enableRemoteLogging && this.config.remoteEndpoint) {
            this.logToRemote(fullEvent);
        }
    }

    /**
     * Create Express middleware for automatic security logging
     */
    createMiddleware() {
        return (req: Request, res: Response, next: NextFunction) => {
            const startTime = Date.now();
            const originalSend = res.send;
            const originalJson = res.json;
            const self = this;

            // Override response methods to capture response details
            res.send = function (body: any) {
                self.logResponse(req, res, startTime, body);
                return originalSend.call(this, body);
            };

            res.json = function (body: any) {
                self.logResponse(req, res, startTime, body);
                return originalJson.call(this, body);
            };

            next();
        };
    }

    /**
     * Log authentication success
     */
    logAuthSuccess(userId: string, req: Request, details: Record<string, any> = {}): void {
        this.log({
            type: SecurityEventType.LOGIN_SUCCESS,
            userId,
            ip: this.getClientIP(req),
            userAgent: req.get('User-Agent') || 'unknown',
            details: {
                endpoint: req.path,
                method: req.method,
                ...details
            },
            severity: 'LOW'
        });
    }

    /**
     * Log authentication failure
     */
    logAuthFailure(req: Request, reason: string, details: Record<string, any> = {}): void {
        this.log({
            type: SecurityEventType.LOGIN_FAILURE,
            ip: this.getClientIP(req),
            userAgent: req.get('User-Agent') || 'unknown',
            details: {
                endpoint: req.path,
                method: req.method,
                reason,
                ...details
            },
            severity: 'MEDIUM'
        });
    }

    /**
     * Log token generation
     */
    logTokenGenerated(userId: string, req: Request, tokenType: 'access' | 'refresh' = 'access'): void {
        this.log({
            type: SecurityEventType.TOKEN_GENERATED,
            userId,
            ip: this.getClientIP(req),
            userAgent: req.get('User-Agent') || 'unknown',
            details: {
                tokenType,
                endpoint: req.path,
                method: req.method
            },
            severity: 'LOW'
        });
    }

    /**
     * Log token blacklisting
     */
    logTokenBlacklisted(userId: string, req: Request, reason: string = 'logout'): void {
        this.log({
            type: SecurityEventType.TOKEN_BLACKLISTED,
            userId,
            ip: this.getClientIP(req),
            userAgent: req.get('User-Agent') || 'unknown',
            details: {
                reason,
                endpoint: req.path,
                method: req.method
            },
            severity: 'LOW'
        });
    }

    /**
     * Log permission denied
     */
    logPermissionDenied(userId: string, req: Request, requiredPermission: string): void {
        this.log({
            type: SecurityEventType.PERMISSION_DENIED,
            userId,
            ip: this.getClientIP(req),
            userAgent: req.get('User-Agent') || 'unknown',
            details: {
                requiredPermission,
                endpoint: req.path,
                method: req.method
            },
            severity: 'MEDIUM'
        });
    }

    /**
     * Log suspicious activity
     */
    logSuspiciousActivity(req: Request, reason: string, details: Record<string, any> = {}): void {
        this.log({
            type: SecurityEventType.SUSPICIOUS_ACTIVITY,
            ip: this.getClientIP(req),
            userAgent: req.get('User-Agent') || 'unknown',
            details: {
                reason,
                endpoint: req.path,
                method: req.method,
                ...details
            },
            severity: 'HIGH'
        });
    }

    /**
     * Log rate limit exceeded
     */
    logRateLimitExceeded(req: Request, limit: number, windowMs: number): void {
        this.log({
            type: SecurityEventType.RATE_LIMIT_EXCEEDED,
            ip: this.getClientIP(req),
            userAgent: req.get('User-Agent') || 'unknown',
            details: {
                limit,
                windowMs,
                endpoint: req.path,
                method: req.method
            },
            severity: 'MEDIUM'
        });
    }

    // Private methods

    private shouldLogEvent(event: SecurityEvent): boolean {
        const severityLevels = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
        const configLevel = severityLevels[this.config.logLevel!];
        const eventLevel = severityLevels[event.severity];
        return eventLevel >= configLevel;
    }

    private logToConsole(event: SecurityEvent): void {
        const logEntry = this.formatLogEntry(event);
        console.log(`[SECURITY] ${logEntry}`);
    }

    private logToFile(event: SecurityEvent): void {
        try {
            const logEntry = this.formatLogEntry(event) + '\n';
            this.fs.appendFileSync(this.config.logFilePath!, logEntry);
        } catch (error) {
            console.error('Failed to write to security log file:', error);
        }
    }

    private async logToRemote(event: SecurityEvent): Promise<void> {
        try {
            const https = require('https');
            const http = require('http');

            const data = JSON.stringify(event);
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
                console.error('Failed to send security log to remote endpoint:', error);
            });

            req.write(data);
            req.end();
        } catch (error) {
            console.error('Failed to send security log to remote endpoint:', error);
        }
    }

    private formatLogEntry(event: SecurityEvent): string {
        return `[${event.timestamp.toISOString()}] ${event.type} | ${event.severity} | IP: ${event.ip} | User: ${event.userId || 'N/A'} | ${JSON.stringify(event.details)}`;
    }

    private logResponse(req: Request, res: Response, startTime: number, body: any): void {
        const duration = Date.now() - startTime;
        const statusCode = res.statusCode;

        // Log suspicious responses
        if (statusCode >= 400) {
            this.log({
                type: SecurityEventType.SUSPICIOUS_ACTIVITY,
                ip: this.getClientIP(req),
                userAgent: req.get('User-Agent') || 'unknown',
                details: {
                    endpoint: req.path,
                    method: req.method,
                    statusCode,
                    duration,
                    responseBody: typeof body === 'string' ? body.substring(0, 200) : JSON.stringify(body).substring(0, 200)
                },
                severity: statusCode >= 500 ? 'HIGH' : 'MEDIUM'
            });
        }
    }

    private getClientIP(req: Request): string {
        return req.ip ||
            req.connection.remoteAddress ||
            req.socket.remoteAddress ||
            (req.connection as any)?.socket?.remoteAddress ||
            'unknown';
    }
}

/**
 * Default security logger instance
 */
export const securityLogger = new SecurityLogger();
