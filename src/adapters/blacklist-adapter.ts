/**
 * Blacklist adapter interface
 * Allows custom database implementations for JWT blacklisting
 */
export interface BlacklistAdapter {
    /**
     * Blacklist a specific token
     */
    blacklistToken(jti: string, expiresAt: Date): Promise<void>;

    /**
     * Blacklist all tokens for a user
     */
    blacklistUser(userId: string): Promise<void>;

    /**
     * Check if a token is blacklisted
     */
    isTokenBlacklisted(jti: string): Promise<boolean>;

    /**
     * Check if a user is blacklisted
     */
    isUserBlacklisted(userId: string): Promise<boolean>;

    /**
     * Remove token from blacklist
     */
    whitelistToken(jti: string): Promise<void>;

    /**
     * Remove user from blacklist
     */
    whitelistUser(userId: string): Promise<void>;

    /**
     * Clean up expired tokens
     */
    cleanupExpiredTokens(): Promise<void>;

    /**
     * Get blacklist statistics
     */
    getStats(): Promise<{ tokens: number; users: number }>;
}

/**
 * Memory-based blacklist adapter
 * Stores blacklisted tokens in memory (not persistent)
 */
export class MemoryBlacklistAdapter implements BlacklistAdapter {
    private blacklistedTokens = new Set<string>();
    private blacklistedUsers = new Set<string>();

    async blacklistToken(jti: string, expiresAt: Date): Promise<void> {
        this.blacklistedTokens.add(jti);
    }

    async blacklistUser(userId: string): Promise<void> {
        this.blacklistedUsers.add(userId);
    }

    async isTokenBlacklisted(jti: string): Promise<boolean> {
        return this.blacklistedTokens.has(jti);
    }

    async isUserBlacklisted(userId: string): Promise<boolean> {
        return this.blacklistedUsers.has(userId);
    }

    async whitelistToken(jti: string): Promise<void> {
        this.blacklistedTokens.delete(jti);
    }

    async whitelistUser(userId: string): Promise<void> {
        this.blacklistedUsers.delete(userId);
    }

    async cleanupExpiredTokens(): Promise<void> {
        // Memory cleanup is automatic, but we could implement TTL here
    }

    async getStats(): Promise<{ tokens: number; users: number }> {
        return {
            tokens: this.blacklistedTokens.size,
            users: this.blacklistedUsers.size
        };
    }
}

/**
 * Redis-based blacklist adapter
 * Stores blacklisted tokens in Redis with TTL
 */
export class RedisBlacklistAdapter implements BlacklistAdapter {
    constructor(private redisClient: any) { }

    async blacklistToken(jti: string, expiresAt: Date): Promise<void> {
        const ttl = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
        await this.redisClient.setex(`blacklist:${jti}`, ttl, '1');
    }

    async blacklistUser(userId: string): Promise<void> {
        await this.redisClient.setex(`blacklist:user:${userId}`, 86400, '1'); // 24 hours
    }

    async isTokenBlacklisted(jti: string): Promise<boolean> {
        const result = await this.redisClient.get(`blacklist:${jti}`);
        return result === '1';
    }

    async isUserBlacklisted(userId: string): Promise<boolean> {
        const result = await this.redisClient.get(`blacklist:user:${userId}`);
        return result === '1';
    }

    async whitelistToken(jti: string): Promise<void> {
        await this.redisClient.del(`blacklist:${jti}`);
    }

    async whitelistUser(userId: string): Promise<void> {
        await this.redisClient.del(`blacklist:user:${userId}`);
    }

    async cleanupExpiredTokens(): Promise<void> {
        // Redis handles TTL automatically
    }

    async getStats(): Promise<{ tokens: number; users: number }> {
        const tokenKeys = await this.redisClient.keys('blacklist:*');
        const userKeys = await this.redisClient.keys('blacklist:user:*');
        return {
            tokens: tokenKeys.filter((key: string) => !key.includes('user:')).length,
            users: userKeys.length
        };
    }
}

/**
 * Generic database adapter interface
 * For custom database implementations
 */
export interface DatabaseBlacklistAdapter extends BlacklistAdapter {
    // Additional database-specific methods can be added here
}

/**
 * Prisma adapter for blacklisting
 * Works with Prisma ORM
 */
export class PrismaBlacklistAdapter implements DatabaseBlacklistAdapter {
    constructor(private prisma: any) { }

    async blacklistToken(jti: string, expiresAt: Date): Promise<void> {
        await this.prisma.blacklistedToken.upsert({
            where: { jti },
            update: { expiresAt },
            create: { jti, expiresAt }
        });
    }

    async blacklistUser(userId: string): Promise<void> {
        await this.prisma.blacklistedUser.upsert({
            where: { userId },
            update: { blacklistedAt: new Date() },
            create: { userId, blacklistedAt: new Date() }
        });
    }

    async isTokenBlacklisted(jti: string): Promise<boolean> {
        const token = await this.prisma.blacklistedToken.findFirst({
            where: {
                jti,
                expiresAt: { gt: new Date() }
            }
        });
        return !!token;
    }

    async isUserBlacklisted(userId: string): Promise<boolean> {
        const user = await this.prisma.blacklistedUser.findFirst({
            where: { userId }
        });
        return !!user;
    }

    async whitelistToken(jti: string): Promise<void> {
        await this.prisma.blacklistedToken.delete({
            where: { jti }
        });
    }

    async whitelistUser(userId: string): Promise<void> {
        await this.prisma.blacklistedUser.delete({
            where: { userId }
        });
    }

    async cleanupExpiredTokens(): Promise<void> {
        await this.prisma.blacklistedToken.deleteMany({
            where: {
                expiresAt: { lt: new Date() }
            }
        });
    }

    async getStats(): Promise<{ tokens: number; users: number }> {
        const [tokenCount, userCount] = await Promise.all([
            this.prisma.blacklistedToken.count({
                where: { expiresAt: { gt: new Date() } }
            }),
            this.prisma.blacklistedUser.count()
        ]);

        return {
            tokens: tokenCount,
            users: userCount
        };
    }
}

/**
 * MongoDB adapter for blacklisting
 * Works with MongoDB
 */
export class MongoDBBlacklistAdapter implements DatabaseBlacklistAdapter {
    constructor(private db: any) { }

    async blacklistToken(jti: string, expiresAt: Date): Promise<void> {
        await this.db.collection('blacklisted_tokens').replaceOne(
            { jti },
            { jti, expiresAt },
            { upsert: true }
        );
    }

    async blacklistUser(userId: string): Promise<void> {
        await this.db.collection('blacklisted_users').replaceOne(
            { userId },
            { userId, blacklistedAt: new Date() },
            { upsert: true }
        );
    }

    async isTokenBlacklisted(jti: string): Promise<boolean> {
        const token = await this.db.collection('blacklisted_tokens').findOne({
            jti,
            expiresAt: { $gt: new Date() }
        });
        return !!token;
    }

    async isUserBlacklisted(userId: string): Promise<boolean> {
        const user = await this.db.collection('blacklisted_users').findOne({
            userId
        });
        return !!user;
    }

    async whitelistToken(jti: string): Promise<void> {
        await this.db.collection('blacklisted_tokens').deleteOne({ jti });
    }

    async whitelistUser(userId: string): Promise<void> {
        await this.db.collection('blacklisted_users').deleteOne({ userId });
    }

    async cleanupExpiredTokens(): Promise<void> {
        await this.db.collection('blacklisted_tokens').deleteMany({
            expiresAt: { $lt: new Date() }
        });
    }

    async getStats(): Promise<{ tokens: number; users: number }> {
        const [tokenCount, userCount] = await Promise.all([
            this.db.collection('blacklisted_tokens').countDocuments({
                expiresAt: { $gt: new Date() }
            }),
            this.db.collection('blacklisted_users').countDocuments()
        ]);

        return {
            tokens: tokenCount,
            users: userCount
        };
    }
}

/**
 * Sequelize adapter for blacklisting
 * Works with Sequelize ORM
 */
export class SequelizeBlacklistAdapter implements DatabaseBlacklistAdapter {
    constructor(private sequelize: any, private models: any) { }

    async blacklistToken(jti: string, expiresAt: Date): Promise<void> {
        await this.models.BlacklistedToken.upsert({
            jti,
            expiresAt
        });
    }

    async blacklistUser(userId: string): Promise<void> {
        await this.models.BlacklistedUser.upsert({
            userId,
            blacklistedAt: new Date()
        });
    }

    async isTokenBlacklisted(jti: string): Promise<boolean> {
        const token = await this.models.BlacklistedToken.findOne({
            where: {
                jti,
                expiresAt: { [this.sequelize.Op.gt]: new Date() }
            }
        });
        return !!token;
    }

    async isUserBlacklisted(userId: string): Promise<boolean> {
        const user = await this.models.BlacklistedUser.findOne({
            where: { userId }
        });
        return !!user;
    }

    async whitelistToken(jti: string): Promise<void> {
        await this.models.BlacklistedToken.destroy({
            where: { jti }
        });
    }

    async whitelistUser(userId: string): Promise<void> {
        await this.models.BlacklistedUser.destroy({
            where: { userId }
        });
    }

    async cleanupExpiredTokens(): Promise<void> {
        await this.models.BlacklistedToken.destroy({
            where: {
                expiresAt: { [this.sequelize.Op.lt]: new Date() }
            }
        });
    }

    async getStats(): Promise<{ tokens: number; users: number }> {
        const [tokenCount, userCount] = await Promise.all([
            this.models.BlacklistedToken.count({
                where: { expiresAt: { [this.sequelize.Op.gt]: new Date() } }
            }),
            this.models.BlacklistedUser.count()
        ]);

        return {
            tokens: tokenCount,
            users: userCount
        };
    }
}
