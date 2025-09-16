import { Request, Response, NextFunction } from 'express';

/**
 * Rate limiter configuration
 */
export interface RateLimitConfig {
    windowMs: number; // Time window in milliseconds
    maxAttempts: number; // Maximum attempts per window
    keyGenerator?: (req: Request) => string; // Custom key generator
    skipSuccessfulRequests?: boolean; // Skip counting successful requests
    skipFailedRequests?: boolean; // Skip counting failed requests
    message?: string; // Custom error message
    statusCode?: number; // HTTP status code for rate limit exceeded
}

/**
 * Rate limiter storage interface
 */
export interface RateLimitStorage {
    get(key: string): Promise<number | null>;
    set(key: string, value: number, ttlMs: number): Promise<void>;
    increment(key: string, ttlMs: number): Promise<number>;
    reset(key: string): Promise<void>;
}

/**
 * Memory-based rate limiter storage
 */
export class MemoryRateLimitStorage implements RateLimitStorage {
    private store = new Map<string, { count: number; expiresAt: number }>();

    async get(key: string): Promise<number | null> {
        const entry = this.store.get(key);
        if (!entry) return null;

        if (Date.now() > entry.expiresAt) {
            this.store.delete(key);
            return null;
        }

        return entry.count;
    }

    async set(key: string, value: number, ttlMs: number): Promise<void> {
        this.store.set(key, {
            count: value,
            expiresAt: Date.now() + ttlMs
        });
    }

    async increment(key: string, ttlMs: number): Promise<number> {
        const entry = this.store.get(key);
        const now = Date.now();

        if (!entry || now > entry.expiresAt) {
            const newEntry = { count: 1, expiresAt: now + ttlMs };
            this.store.set(key, newEntry);
            return 1;
        }

        entry.count++;
        return entry.count;
    }

    async reset(key: string): Promise<void> {
        this.store.delete(key);
    }
}

/**
 * Redis-based rate limiter storage
 */
export class RedisRateLimitStorage implements RateLimitStorage {
    constructor(private redisClient: any) { }

    async get(key: string): Promise<number | null> {
        const result = await this.redisClient.get(`rate_limit:${key}`);
        return result ? parseInt(result, 10) : null;
    }

    async set(key: string, value: number, ttlMs: number): Promise<void> {
        await this.redisClient.setex(`rate_limit:${key}`, Math.ceil(ttlMs / 1000), value.toString());
    }

    async increment(key: string, ttlMs: number): Promise<number> {
        const multi = this.redisClient.multi();
        multi.incr(`rate_limit:${key}`);
        multi.expire(`rate_limit:${key}`, Math.ceil(ttlMs / 1000));
        const results = await multi.exec();
        return results[0][1];
    }

    async reset(key: string): Promise<void> {
        await this.redisClient.del(`rate_limit:${key}`);
    }
}

/**
 * Rate limiter class
 */
export class RateLimiter {
    private storage: RateLimitStorage;
    private config: RateLimitConfig;

    constructor(config: RateLimitConfig, storage?: RateLimitStorage) {
        this.config = {
            keyGenerator: config.keyGenerator || this.defaultKeyGenerator,
            skipSuccessfulRequests: config.skipSuccessfulRequests || false,
            skipFailedRequests: config.skipFailedRequests || false,
            message: config.message || 'Too many requests, please try again later',
            statusCode: config.statusCode || 429,
            ...config
        };
        this.storage = storage || new MemoryRateLimitStorage();
    }

    /**
     * Create rate limiting middleware
     */
    createMiddleware() {
        return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
            try {
                const key = this.config.keyGenerator!(req);
                const currentCount = await this.storage.increment(key, this.config.windowMs);

                // Set rate limit headers
                res.set({
                    'X-RateLimit-Limit': this.config.maxAttempts.toString(),
                    'X-RateLimit-Remaining': Math.max(0, this.config.maxAttempts - currentCount).toString(),
                    'X-RateLimit-Reset': new Date(Date.now() + this.config.windowMs).toISOString()
                });

                if (currentCount > this.config.maxAttempts) {
                    res.status(this.config.statusCode!).json({
                        error: this.config.message,
                        code: 'RATE_LIMIT_EXCEEDED',
                        retryAfter: Math.ceil(this.config.windowMs / 1000)
                    });
                    return;
                }

                // Store original methods to track success/failure
                const originalSend = res.send;
                const originalJson = res.json;

                // Override response methods to track success/failure
                const self = this;
                res.send = function (body: any) {
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        // Request was successful
                        if (self.config.skipSuccessfulRequests) {
                            self.storage.increment(key, self.config.windowMs).then((count: number) => {
                                if (count > 0) {
                                    self.storage.set(key, count - 1, self.config.windowMs);
                                }
                            });
                        }
                    } else {
                        // Request failed
                        if (self.config.skipFailedRequests) {
                            self.storage.increment(key, self.config.windowMs).then((count: number) => {
                                if (count > 0) {
                                    self.storage.set(key, count - 1, self.config.windowMs);
                                }
                            });
                        }
                    }
                    return originalSend.call(this, body);
                };

                res.json = function (body: any) {
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        // Request was successful
                        if (self.config.skipSuccessfulRequests) {
                            self.storage.increment(key, self.config.windowMs).then((count: number) => {
                                if (count > 0) {
                                    self.storage.set(key, count - 1, self.config.windowMs);
                                }
                            });
                        }
                    } else {
                        // Request failed
                        if (self.config.skipFailedRequests) {
                            self.storage.increment(key, self.config.windowMs).then((count: number) => {
                                if (count > 0) {
                                    self.storage.set(key, count - 1, self.config.windowMs);
                                }
                            });
                        }
                    }
                    return originalJson.call(this, body);
                };

                next();
            } catch (error) {
                // If rate limiting fails, allow the request to proceed
                console.error('Rate limiter error:', error);
                next();
            }
        };
    }

    /**
     * Default key generator (IP + User Agent)
     */
    private defaultKeyGenerator(req: Request): string {
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        const userAgent = req.get('User-Agent') || 'unknown';
        return `rate_limit:${ip}:${userAgent}`;
    }

    /**
     * Reset rate limit for a specific key
     */
    async reset(key: string): Promise<void> {
        await this.storage.reset(key);
    }

    /**
     * Get current count for a key
     */
    async getCount(key: string): Promise<number> {
        return await this.storage.get(key) || 0;
    }
}

/**
 * Predefined rate limiters for common use cases
 */
export class AuthRateLimiters {
    /**
     * Login rate limiter (5 attempts per 15 minutes)
     */
    static loginRateLimiter(storage?: RateLimitStorage): RateLimiter {
        return new RateLimiter({
            windowMs: 15 * 60 * 1000, // 15 minutes
            maxAttempts: 5,
            keyGenerator: (req) => `login:${req.ip || 'unknown'}`,
            skipSuccessfulRequests: true,
            message: 'Too many login attempts, please try again in 15 minutes'
        }, storage);
    }

    /**
     * Password reset rate limiter (3 attempts per hour)
     */
    static passwordResetRateLimiter(storage?: RateLimitStorage): RateLimiter {
        return new RateLimiter({
            windowMs: 60 * 60 * 1000, // 1 hour
            maxAttempts: 3,
            keyGenerator: (req) => `password_reset:${req.ip || 'unknown'}`,
            message: 'Too many password reset attempts, please try again in 1 hour'
        }, storage);
    }

    /**
     * Token refresh rate limiter (10 attempts per minute)
     */
    static tokenRefreshRateLimiter(storage?: RateLimitStorage): RateLimiter {
        return new RateLimiter({
            windowMs: 60 * 1000, // 1 minute
            maxAttempts: 10,
            keyGenerator: (req) => `token_refresh:${req.ip || 'unknown'}`,
            message: 'Too many token refresh attempts, please try again in 1 minute'
        }, storage);
    }

    /**
     * General API rate limiter (100 requests per 15 minutes)
     */
    static apiRateLimiter(storage?: RateLimitStorage): RateLimiter {
        return new RateLimiter({
            windowMs: 15 * 60 * 1000, // 15 minutes
            maxAttempts: 100,
            keyGenerator: (req) => `api:${req.ip || 'unknown'}`,
            message: 'Too many API requests, please try again in 15 minutes'
        }, storage);
    }
}
