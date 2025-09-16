import { Request, Response, NextFunction } from 'express';

// JWT Algorithm types
export type JWTAlgorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';

// Token storage locations
export type TokenStorage = 'header' | 'cookie';

// User interface that will be attached to req.user
export interface User {
    id: string | number;
    email?: string;
    role?: string;
    permissions?: string[];
    [key: string]: any; // Allow custom properties
}

// JWT Payload interface
export interface JWTPayload {
    sub: string | number; // Subject (user ID)
    iat: number; // Issued at
    exp: number; // Expires at
    role?: string;
    permissions?: string[];
    [key: string]: any; // Allow custom claims
}

// i18n configuration
export interface I18nConfig {
    locale?: string; // Default locale (e.g., 'en', 'es', 'fr')
    messages?: Record<string, Record<string, string>>; // Custom messages
    fallbackLocale?: string; // Fallback when translation not found
}

// Error message keys enum for type safety
export enum ErrorMessageKeys {
    // Multi-login messages
    MULTI_LOGIN_DISABLED = 'MULTI_LOGIN_DISABLED',
    PREVIOUS_SESSIONS_LOGGED_OUT = 'PREVIOUS_SESSIONS_LOGGED_OUT',
    SINGLE_DEVICE_ONLY = 'SINGLE_DEVICE_ONLY',
    DEVICE_LIMIT_EXCEEDED = 'DEVICE_LIMIT_EXCEEDED',

    // General auth messages
    INVALID_TOKEN = 'INVALID_TOKEN',
    TOKEN_EXPIRED = 'TOKEN_EXPIRED',
    INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
    ACCESS_DENIED = 'ACCESS_DENIED',
    RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
    UNAUTHORIZED = 'UNAUTHORIZED',
    FORBIDDEN = 'FORBIDDEN',
    NOT_FOUND = 'NOT_FOUND',
    INTERNAL_ERROR = 'INTERNAL_ERROR'
}

// Error message configuration
export interface ErrorMessages {
    // Multi-login messages
    MULTI_LOGIN_DISABLED?: string;
    PREVIOUS_SESSIONS_LOGGED_OUT?: string;
    SINGLE_DEVICE_ONLY?: string;
    DEVICE_LIMIT_EXCEEDED?: string;

    // General auth messages
    INVALID_TOKEN?: string;
    TOKEN_EXPIRED?: string;
    INVALID_CREDENTIALS?: string;
    ACCESS_DENIED?: string;
    RATE_LIMIT_EXCEEDED?: string;
    UNAUTHORIZED?: string;
    FORBIDDEN?: string;
    NOT_FOUND?: string;
    INTERNAL_ERROR?: string;
}

// Configuration interface for initAuth
export interface AuthConfig {
    secret: string;
    accessExpiry?: string; // e.g., '15m', '1h', '7d'
    refreshExpiry?: string; // e.g., '7d', '30d'
    algorithm?: JWTAlgorithm;
    storage?: TokenStorage;
    roles?: string[];
    permissions?: string[];
    cookieName?: string; // For cookie storage
    cookieOptions?: {
        httpOnly?: boolean;
        secure?: boolean;
        sameSite?: 'strict' | 'lax' | 'none';
        domain?: string;
        path?: string;
    };
    multiLogin?: boolean; // Allow multiple device logins (default: true)
    i18n?: I18nConfig; // Internationalization support
    errorMessages?: ErrorMessages; // Custom error messages
}

// Auth instance interface
export interface AuthInstance {
    generateToken: (payload: Partial<JWTPayload>) => string;
    verifyToken: (token: string) => JWTPayload;
    protect: (options?: ProtectOptions) => (req: Request, res: Response, next: NextFunction) => void;
    extractToken: (req: Request) => string | null;
    isMultiLoginEnabled?: () => boolean; // Optional for basic auth
}

// Protection options for middleware
export interface ProtectOptions {
    role?: string | string[];
    roles?: string[];
    permission?: string | string[];
    permissions?: string[];
    requireAll?: boolean; // If true, user must have ALL specified roles/permissions
}

// Error types
export interface AuthError extends Error {
    code: string;
    statusCode: number;
}

// Express Request extension
declare global {
    namespace Express {
        interface Request {
            user?: User;
        }
    }
}

// Error codes
export enum ErrorCodes {
    TOKEN_MISSING = 'TOKEN_MISSING',
    TOKEN_INVALID = 'TOKEN_INVALID',
    TOKEN_EXPIRED = 'TOKEN_EXPIRED',
    INSUFFICIENT_PERMISSIONS = 'INSUFFICIENT_PERMISSIONS',
    INVALID_ROLE = 'INVALID_ROLE',
    CONFIG_ERROR = 'CONFIG_ERROR'
}
