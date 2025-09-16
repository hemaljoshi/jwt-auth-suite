import { JWTPayload, User, I18nConfig, ErrorMessages, ErrorMessageKeys } from './types';
import { TokenManager } from './token';
import { JWTBlacklist } from './blacklist';
import { I18nManager } from './i18n';
import { randomBytes } from 'crypto';

/**
 * Refresh token rotation for enhanced security
 * Implements automatic token rotation and family tracking
 */
export class RefreshTokenManager {
    private tokenManager: TokenManager;
    private blacklist: JWTBlacklist;
    private tokenFamilies: Map<string, TokenFamily> = new Map();
    private storage: 'memory' | 'redis' | 'database';
    private redisClient?: any;
    private dbClient?: any;
    private multiLogin: boolean;
    private i18n: I18nManager;
    private errorMessages: ErrorMessages;

    constructor(
        tokenManager: TokenManager,
        blacklist: JWTBlacklist,
        storage: 'memory' | 'redis' | 'database' = 'memory',
        options?: {
            redisClient?: any;
            dbClient?: any;
            multiLogin?: boolean;
            i18n?: I18nConfig;
            errorMessages?: ErrorMessages;
        }
    ) {
        this.tokenManager = tokenManager;
        this.blacklist = blacklist;
        this.storage = storage;
        this.redisClient = options?.redisClient;
        this.dbClient = options?.dbClient;
        this.multiLogin = options?.multiLogin ?? true; // Default to true for backward compatibility
        this.i18n = new I18nManager(options?.i18n);
        this.errorMessages = options?.errorMessages || {};
    }

    /**
     * Generate refresh token with rotation support
     */
    async generateRefreshToken(
        user: User,
        options: {
            familyId?: string;
            deviceId?: string;
            maxFamilySize?: number;
        } = {}
    ): Promise<RefreshTokenResult> {
        const familyId = options.familyId || this.generateFamilyId();
        const deviceId = options.deviceId || this.generateDeviceId();
        const maxFamilySize = options.maxFamilySize || 5;

        // If multiLogin is disabled, revoke all existing tokens for this user
        if (!this.multiLogin) {
            await this.revokeUserTokens(String(user.id));
        }

        // Check if family exists and is within limits
        const family = await this.getTokenFamily(familyId);
        if (family && family.tokens.length >= maxFamilySize) {
            // Revoke oldest tokens in the family
            await this.revokeOldestTokens(familyId, family.tokens.length - maxFamilySize + 1);
        }

        // Generate new refresh token
        const refreshToken = this.tokenManager.generateRefreshToken({
            sub: user.id,
            email: user.email,
            role: user.role,
            permissions: user.permissions,
            jti: this.generateJTI(),
            familyId: familyId,
            deviceId: deviceId,
            type: 'refresh'
        });

        // Store token in family
        await this.addTokenToFamily(familyId, {
            jti: this.extractJTI(refreshToken),
            token: refreshToken,
            deviceId: deviceId,
            createdAt: new Date(),
            isActive: true
        });

        return {
            refreshToken,
            familyId,
            deviceId,
            expiresAt: this.getTokenExpiry(refreshToken),
            message: this.getMultiLoginMessage()
        };
    }

    /**
     * Rotate refresh token (generate new access + refresh tokens)
     */
    async rotateRefreshToken(
        refreshToken: string,
        user: User
    ): Promise<RefreshTokenResult> {
        // Verify the refresh token
        const payload = this.tokenManager.verifyToken(refreshToken);

        if (payload.type !== 'refresh') {
            throw new Error('Invalid refresh token');
        }

        const familyId = payload.familyId;
        const deviceId = payload.deviceId;

        // Check if token is blacklisted
        if (await this.blacklist.isTokenBlacklisted(refreshToken)) {
            // Revoke entire family (security breach detected)
            await this.revokeTokenFamily(familyId);
            throw new Error('Token family has been compromised');
        }

        // Blacklist the old refresh token
        await this.blacklist.blacklistToken(refreshToken);

        // Generate new access token
        const accessToken = this.tokenManager.generateAccessToken({
            sub: user.id,
            email: user.email,
            role: user.role,
            permissions: user.permissions
        });

        // Generate new refresh token in the same family
        const newRefreshToken = this.tokenManager.generateRefreshToken({
            sub: user.id,
            email: user.email,
            role: user.role,
            permissions: user.permissions,
            jti: this.generateJTI(),
            familyId: familyId,
            deviceId: deviceId,
            type: 'refresh'
        });

        // Update family with new token
        await this.addTokenToFamily(familyId, {
            jti: this.extractJTI(newRefreshToken),
            token: newRefreshToken,
            deviceId: deviceId,
            createdAt: new Date(),
            isActive: true
        });

        return {
            accessToken,
            refreshToken: newRefreshToken,
            familyId,
            deviceId,
            expiresAt: this.getTokenExpiry(newRefreshToken)
        };
    }

    /**
     * Revoke refresh token
     */
    async revokeRefreshToken(refreshToken: string): Promise<void> {
        const payload = this.decodeToken(refreshToken);
        if (payload && payload.familyId) {
            await this.blacklist.blacklistToken(refreshToken);
            await this.removeTokenFromFamily(payload.familyId, this.extractJTI(refreshToken));
        }
    }

    /**
     * Revoke all tokens for a user
     */
    async revokeUserTokens(userId: string): Promise<void> {
        await this.blacklist.blacklistUser(userId);

        // Revoke all token families for this user
        const families = await this.getUserTokenFamilies(userId);
        for (const familyId of families) {
            await this.revokeTokenFamily(familyId);
        }
    }

    /**
     * Revoke all tokens for a specific device
     */
    async revokeDeviceTokens(userId: string, deviceId: string): Promise<void> {
        const families = await this.getUserTokenFamilies(userId);
        for (const familyId of families) {
            const family = await this.getTokenFamily(familyId);
            if (family) {
                const deviceTokens = family.tokens.filter(t => t.deviceId === deviceId);
                for (const token of deviceTokens) {
                    await this.blacklist.blacklistToken(token.token);
                }
                await this.removeTokensFromFamily(familyId, deviceTokens.map(t => t.jti));
            }
        }
    }

    /**
     * Get active tokens for a user
     */
    async getUserActiveTokens(userId: string): Promise<TokenInfo[]> {
        const families = await this.getUserTokenFamilies(userId);
        const activeTokens: TokenInfo[] = [];

        for (const familyId of families) {
            const family = await this.getTokenFamily(familyId);
            if (family) {
                activeTokens.push(...family.tokens.filter(t => t.isActive));
            }
        }

        return activeTokens;
    }

    /**
     * Clean up expired tokens
     */
    async cleanupExpiredTokens(): Promise<void> {
        const allFamilies = await this.getAllTokenFamilies();

        for (const [familyId, family] of allFamilies) {
            const expiredTokens = family.tokens.filter(token => {
                const expiry = this.getTokenExpiry(token.token);
                return expiry && expiry < new Date();
            });

            for (const token of expiredTokens) {
                await this.removeTokenFromFamily(familyId, token.jti);
            }

            // Remove empty families
            if (family.tokens.length === 0) {
                await this.removeTokenFamily(familyId);
            }
        }
    }

    // i18n helper methods

    /**
     * Get localized message for multi-login
     */
    private getMultiLoginMessage(): string {
        if (!this.multiLogin) {
            return this.getErrorMessage(ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT);
        }
        return '';
    }

    /**
     * Get localized error message
     */
    getErrorMessage(key: ErrorMessageKeys, locale?: string): string {
        // Check custom error messages first
        if (this.errorMessages[key]) {
            return this.errorMessages[key]!;
        }

        // Fall back to i18n
        return this.i18n.t(key, locale);
    }

    /**
     * Get localized error message with parameters
     */
    getErrorMessageWithParams(key: ErrorMessageKeys, params: Record<string, string | number>, locale?: string): string {
        // Check custom error messages first
        if (this.errorMessages[key]) {
            let message = this.errorMessages[key]!;
            // Replace placeholders
            Object.keys(params).forEach(param => {
                const placeholder = `{${param}}`;
                message = message.replace(new RegExp(placeholder, 'g'), String(params[param]));
            });
            return message;
        }

        // Fall back to i18n
        return this.i18n.tWithParams(key, params, locale);
    }

    /**
     * Set locale for error messages
     */
    setLocale(locale: string): void {
        this.i18n.setLocale(locale);
    }

    /**
     * Get current locale
     */
    getLocale(): string {
        return this.i18n.getLocale();
    }

    /**
     * Add custom messages for a locale
     */
    addMessages(locale: string, messages: Record<string, string>): void {
        this.i18n.addMessages(locale, messages);
    }

    // Private helper methods

    private async getTokenFamily(familyId: string): Promise<TokenFamily | null> {
        switch (this.storage) {
            case 'memory':
                return this.tokenFamilies.get(familyId) || null;
            case 'redis':
                if (this.redisClient) {
                    const data = await this.redisClient.get(`token_family:${familyId}`);
                    return data ? JSON.parse(data) : null;
                }
                return null;
            case 'database':
                if (this.dbClient) {
                    const result = await this.dbClient.query(
                        'SELECT * FROM token_families WHERE family_id = $1',
                        [familyId]
                    );
                    return result.rows.length > 0 ? result.rows[0] : null;
                }
                return null;
            default:
                return null;
        }
    }

    private async addTokenToFamily(familyId: string, tokenInfo: TokenInfo): Promise<void> {
        let family = await this.getTokenFamily(familyId);

        if (!family) {
            family = {
                familyId,
                userId: tokenInfo.userId || '',
                tokens: [],
                createdAt: new Date()
            };
        }

        family.tokens.push(tokenInfo);
        await this.saveTokenFamily(family);
    }

    private async saveTokenFamily(family: TokenFamily): Promise<void> {
        switch (this.storage) {
            case 'memory':
                this.tokenFamilies.set(family.familyId, family);
                break;
            case 'redis':
                if (this.redisClient) {
                    await this.redisClient.setex(
                        `token_family:${family.familyId}`,
                        86400 * 30, // 30 days
                        JSON.stringify(family)
                    );
                }
                break;
            case 'database':
                if (this.dbClient) {
                    await this.dbClient.query(
                        'INSERT INTO token_families (family_id, user_id, tokens, created_at) VALUES ($1, $2, $3, $4) ON CONFLICT (family_id) DO UPDATE SET tokens = $3',
                        [family.familyId, family.userId, JSON.stringify(family.tokens), family.createdAt]
                    );
                }
                break;
        }
    }

    private async revokeTokenFamily(familyId: string): Promise<void> {
        const family = await this.getTokenFamily(familyId);
        if (family) {
            // Blacklist all tokens in the family
            for (const token of family.tokens) {
                await this.blacklist.blacklistToken(token.token);
            }
            await this.removeTokenFamily(familyId);
        }
    }

    private async removeTokenFamily(familyId: string): Promise<void> {
        switch (this.storage) {
            case 'memory':
                this.tokenFamilies.delete(familyId);
                break;
            case 'redis':
                if (this.redisClient) {
                    await this.redisClient.del(`token_family:${familyId}`);
                }
                break;
            case 'database':
                if (this.dbClient) {
                    await this.dbClient.query('DELETE FROM token_families WHERE family_id = $1', [familyId]);
                }
                break;
        }
    }

    private async getUserTokenFamilies(userId: string): Promise<string[]> {
        // Implementation depends on storage type
        // For now, return empty array
        return [];
    }

    private async getAllTokenFamilies(): Promise<Map<string, TokenFamily>> {
        // Implementation depends on storage type
        return new Map();
    }

    private generateFamilyId(): string {
        return randomBytes(16).toString('hex') + Date.now().toString(36);
    }

    private generateDeviceId(): string {
        return randomBytes(16).toString('hex') + Date.now().toString(36);
    }

    private generateJTI(): string {
        return randomBytes(16).toString('hex') + Date.now().toString(36);
    }

    private extractJTI(token: string): string {
        const payload = this.decodeToken(token);
        return payload?.jti || this.hashToken(token);
    }

    private decodeToken(token: string): any {
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

    private hashToken(token: string): string {
        let hash = 0;
        for (let i = 0; i < token.length; i++) {
            const char = token.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString(36);
    }

    private getTokenExpiry(token: string): Date | null {
        const payload = this.decodeToken(token);
        return payload?.exp ? new Date(payload.exp * 1000) : null;
    }

    private async revokeOldestTokens(familyId: string, count: number): Promise<void> {
        const family = await this.getTokenFamily(familyId);
        if (family) {
            const sortedTokens = family.tokens.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
            const tokensToRevoke = sortedTokens.slice(0, count);

            for (const token of tokensToRevoke) {
                await this.blacklist.blacklistToken(token.token);
            }

            family.tokens = family.tokens.filter(t => !tokensToRevoke.includes(t));
            await this.saveTokenFamily(family);
        }
    }

    private async removeTokenFromFamily(familyId: string, jti: string): Promise<void> {
        const family = await this.getTokenFamily(familyId);
        if (family) {
            family.tokens = family.tokens.filter(t => t.jti !== jti);
            await this.saveTokenFamily(family);
        }
    }

    private async removeTokensFromFamily(familyId: string, jtis: string[]): Promise<void> {
        const family = await this.getTokenFamily(familyId);
        if (family) {
            family.tokens = family.tokens.filter(t => !jtis.includes(t.jti));
            await this.saveTokenFamily(family);
        }
    }
}

/**
 * Token family interface
 */
export interface TokenFamily {
    familyId: string;
    userId: string;
    tokens: TokenInfo[];
    createdAt: Date;
}

/**
 * Token information interface
 */
export interface TokenInfo {
    jti: string;
    token: string;
    deviceId: string;
    createdAt: Date;
    isActive: boolean;
    userId?: string;
}

/**
 * Refresh token result interface
 */
export interface RefreshTokenResult {
    accessToken?: string;
    refreshToken: string;
    familyId: string;
    deviceId: string;
    expiresAt: Date | null;
    message?: string; // Localized message for multi-login
}
