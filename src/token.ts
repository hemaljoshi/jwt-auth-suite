import jwt from 'jsonwebtoken';
import { AuthConfig, JWTPayload, JWTAlgorithm } from './types';
import {
    createTokenInvalidError,
    createTokenExpiredError,
    createConfigError
} from './errors';

/**
 * Parse time string to seconds
 * Supports: '15m', '1h', '7d', '30d', etc.
 */
function parseTimeToSeconds(timeStr: string): number {
    const timeRegex = /^(\d+)([smhd])$/;
    const match = timeStr.match(timeRegex);

    if (!match) {
        throw createConfigError(`Invalid time format: ${timeStr}. Use format like '15m', '1h', '7d'`);
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    const multipliers: { [key: string]: number } = {
        's': 1,
        'm': 60,
        'h': 60 * 60,
        'd': 60 * 60 * 24
    };

    return value * multipliers[unit];
}

/**
 * Create token manager with configuration
 */
export class TokenManager {
    private secret: string;
    private accessExpiry: number;
    private refreshExpiry: number;
    private algorithm: JWTAlgorithm;

    constructor(config: AuthConfig) {
        this.secret = config.secret;
        this.algorithm = config.algorithm || 'HS256';

        // Parse expiry times
        this.accessExpiry = parseTimeToSeconds(config.accessExpiry || '15m');
        this.refreshExpiry = parseTimeToSeconds(config.refreshExpiry || '7d');

        // Validate secret
        if (!this.secret || this.secret.length < 32) {
            throw createConfigError('Secret must be at least 32 characters long');
        }
    }

    /**
     * Generate access token
     */
    generateAccessToken(payload: Partial<JWTPayload>): string {
        const now = Math.floor(Date.now() / 1000);

        const tokenPayload: JWTPayload = {
            sub: payload.sub || '',
            iat: now,
            exp: now + this.accessExpiry,
            ...payload
        };

        try {
            return jwt.sign(tokenPayload, this.secret, {
                algorithm: this.algorithm
            });
        } catch (error) {
            throw createConfigError(`Failed to generate token: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Generate refresh token
     */
    generateRefreshToken(payload: Partial<JWTPayload>): string {
        const now = Math.floor(Date.now() / 1000);

        const tokenPayload: JWTPayload = {
            sub: payload.sub || '',
            iat: now,
            exp: now + this.refreshExpiry,
            type: 'refresh', // Mark as refresh token
            ...payload
        };

        try {
            return jwt.sign(tokenPayload, this.secret, {
                algorithm: this.algorithm
            });
        } catch (error) {
            throw createConfigError(`Failed to generate refresh token: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Verify and decode token
     */
    verifyToken(token: string): JWTPayload {
        try {
            const decoded = jwt.verify(token, this.secret, {
                algorithms: [this.algorithm]
            }) as JWTPayload;

            // Check if token is expired
            const now = Math.floor(Date.now() / 1000);
            if (decoded.exp && decoded.exp < now) {
                throw createTokenExpiredError();
            }

            return decoded;
        } catch (error) {
            if (error instanceof jwt.TokenExpiredError) {
                throw createTokenExpiredError();
            } else if (error instanceof jwt.JsonWebTokenError) {
                throw createTokenInvalidError();
            } else if (error instanceof jwt.NotBeforeError) {
                throw createTokenInvalidError();
            } else if (isJWTAuthSuiteError(error)) {
                throw error;
            } else {
                throw createTokenInvalidError();
            }
        }
    }

    /**
     * Generate both access and refresh tokens
     */
    generateTokenPair(payload: Partial<JWTPayload>): { accessToken: string; refreshToken: string } {
        return {
            accessToken: this.generateAccessToken(payload),
            refreshToken: this.generateRefreshToken(payload)
        };
    }

    /**
     * Check if token is expired
     */
    isTokenExpired(token: string): boolean {
        try {
            const decoded = jwt.decode(token) as JWTPayload;
            if (!decoded || !decoded.exp) return true;

            const now = Math.floor(Date.now() / 1000);
            return decoded.exp < now;
        } catch {
            return true;
        }
    }

    /**
     * Get token expiry time
     */
    getTokenExpiry(token: string): Date | null {
        try {
            const decoded = jwt.decode(token) as JWTPayload;
            if (!decoded || !decoded.exp) return null;

            return new Date(decoded.exp * 1000);
        } catch {
            return null;
        }
    }
}

// Helper function to check if error is JWT Auth Suite error
function isJWTAuthSuiteError(error: any): error is Error {
    return error instanceof Error && error.name === 'JWTAuthSuiteError';
}
