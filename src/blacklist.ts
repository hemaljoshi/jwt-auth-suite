import { JWTPayload } from './types';
import { BlacklistAdapter, MemoryBlacklistAdapter, RedisBlacklistAdapter } from './adapters/blacklist-adapter';

/**
 * JWT Blacklist Manager
 * Handles token blacklisting for logout functionality using adapter pattern
 */
export class JWTBlacklist {
    private adapter: BlacklistAdapter;

    constructor(adapter?: BlacklistAdapter) {
        this.adapter = adapter || new MemoryBlacklistAdapter();
    }

    /**
     * Create a blacklist instance with memory storage
     */
    static memory(): JWTBlacklist {
        return new JWTBlacklist(new MemoryBlacklistAdapter());
    }

    /**
     * Create a blacklist instance with Redis storage
     */
    static redis(redisClient: any): JWTBlacklist {
        return new JWTBlacklist(new RedisBlacklistAdapter(redisClient));
    }

    /**
     * Create a blacklist instance with custom adapter
     */
    static custom(adapter: BlacklistAdapter): JWTBlacklist {
        return new JWTBlacklist(adapter);
    }

    /**
     * Blacklist a specific token
     */
    async blacklistToken(token: string, expiry?: number): Promise<void> {
        const jti = this.extractJTI(token);
        const expiresAt = expiry ? new Date(expiry * 1000) : new Date(Date.now() + 3600000);
        await this.adapter.blacklistToken(jti, expiresAt);
    }

    /**
     * Blacklist all tokens for a user (logout from all devices)
     */
    async blacklistUser(userId: string): Promise<void> {
        await this.adapter.blacklistUser(userId);
    }

    /**
     * Check if a token is blacklisted
     */
    async isTokenBlacklisted(token: string): Promise<boolean> {
        const jti = this.extractJTI(token);
        const payload = this.decodeToken(token);

        if (!payload) return false;

        // Check if user is blacklisted
        if (await this.isUserBlacklisted(payload.sub.toString())) {
            return true;
        }

        return await this.adapter.isTokenBlacklisted(jti);
    }

    /**
     * Check if a user is blacklisted
     */
    async isUserBlacklisted(userId: string): Promise<boolean> {
        return await this.adapter.isUserBlacklisted(userId);
    }

    /**
     * Remove token from blacklist (if needed)
     */
    async whitelistToken(token: string): Promise<void> {
        const jti = this.extractJTI(token);
        await this.adapter.whitelistToken(jti);
    }

    /**
     * Remove user from blacklist
     */
    async whitelistUser(userId: string): Promise<void> {
        await this.adapter.whitelistUser(userId);
    }

    /**
     * Clean up expired tokens
     */
    async cleanup(): Promise<void> {
        await this.adapter.cleanupExpiredTokens();
    }

    /**
     * Extract JTI (JWT ID) from token
     */
    private extractJTI(token: string): string {
        try {
            const payload = this.decodeToken(token);
            return payload?.jti || this.hashToken(token);
        } catch {
            return this.hashToken(token);
        }
    }

    /**
     * Decode token without verification (for extracting claims)
     */
    private decodeToken(token: string): JWTPayload | null {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(
                atob(base64)
                    .split('')
                    .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                    .join('')
            );
            return JSON.parse(jsonPayload);
        } catch {
            return null;
        }
    }

    /**
     * Create a hash of the token for blacklisting
     */
    private hashToken(token: string): string {
        // Simple hash function - in production, use crypto.createHash
        let hash = 0;
        for (let i = 0; i < token.length; i++) {
            const char = token.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash.toString(36);
    }

    /**
     * Get blacklist statistics
     */
    async getStats(): Promise<{ tokens: number; users: number }> {
        return await this.adapter.getStats();
    }
}
