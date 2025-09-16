import { Request, Response, NextFunction } from 'express';
import { AuthConfig, AuthInstance, ProtectOptions, JWTPayload, User } from './types';
import { MiddlewareFactory } from './middleware';
import { TokenManager } from './token';
import { RoleChecker } from './roles';
import { createConfigError } from './errors';
import { JWTBlacklist } from './blacklist';
import { BlacklistAdapter, PrismaBlacklistAdapter, MongoDBBlacklistAdapter, SequelizeBlacklistAdapter } from './adapters/blacklist-adapter';
import { PasswordManager, PasswordStrengthChecker } from './password';
import { TenantManager, TenantMiddlewareFactory } from './tenant';
import { RefreshTokenManager } from './refresh';
import { RateLimiter, AuthRateLimiters, MemoryRateLimitStorage, RedisRateLimitStorage } from './rate-limiter';
import { SecurityLogger, securityLogger } from './security-logger';
import { MetricsCollector, metricsCollector } from './metrics';

/**
 * Initialize JWT Auth Suite authentication system
 */
export function initAuth(config: AuthConfig): AuthInstance {
    // Validate required configuration
    if (!config.secret) {
        throw createConfigError('Secret is required');
    }

    // Initialize components
    const tokenManager = new TokenManager(config);
    const roleChecker = new RoleChecker(config.roles, config.permissions);
    const middlewareFactory = new MiddlewareFactory(config);

    // Create auth instance
    const auth: AuthInstance = {
        /**
         * Generate access token
         */
        generateToken: (payload: Partial<JWTPayload>): string => {
            return tokenManager.generateAccessToken(payload);
        },

        /**
         * Verify token
         */
        verifyToken: (token: string): JWTPayload => {
            return tokenManager.verifyToken(token);
        },

        /**
         * Extract token from request
         */
        extractToken: (req: Request): string | null => {
            return middlewareFactory.extractToken(req);
        },

        /**
         * Create protection middleware
         */
        protect: (options?: ProtectOptions) => {
            return middlewareFactory.protect(options);
        }
    };

    return auth;
}

/**
 * Create a complete auth instance with additional utilities
 */
export function createAuth(config: AuthConfig & {
    blacklistAdapter?: BlacklistAdapter;
    passwordSaltRounds?: number;
    enableTenants?: boolean;
    enableRefreshRotation?: boolean;
    redisClient?: any;
    prismaClient?: any;
    mongoClient?: any;
    sequelizeClient?: any;
    enableRateLimiting?: boolean;
    enableSecurityLogging?: boolean;
    enableMetrics?: boolean;
    rateLimitStorage?: 'memory' | 'redis';
    securityLoggerConfig?: any;
    metricsConfig?: any;
}) {
    const auth = initAuth(config);
    const tokenManager = new TokenManager(config);
    const roleChecker = new RoleChecker(config.roles, config.permissions);
    const middlewareFactory = new MiddlewareFactory(config);

    // Initialize blacklist with adapter
    let blacklist: JWTBlacklist;
    if (config.blacklistAdapter) {
        blacklist = JWTBlacklist.custom(config.blacklistAdapter);
    } else if (config.redisClient) {
        blacklist = JWTBlacklist.redis(config.redisClient);
    } else if (config.prismaClient) {
        blacklist = JWTBlacklist.custom(new PrismaBlacklistAdapter(config.prismaClient));
    } else if (config.mongoClient) {
        blacklist = JWTBlacklist.custom(new MongoDBBlacklistAdapter(config.mongoClient));
    } else if (config.sequelizeClient) {
        blacklist = JWTBlacklist.custom(new SequelizeBlacklistAdapter(config.sequelizeClient.sequelize, config.sequelizeClient.models));
    } else {
        blacklist = JWTBlacklist.memory();
    }

    const passwordManager = new PasswordManager(config.passwordSaltRounds);
    const passwordStrengthChecker = new PasswordStrengthChecker();

    const tenantManager = config.enableTenants ? new TenantManager() : null;
    const tenantMiddleware = tenantManager ? new TenantMiddlewareFactory(tenantManager) : null;

    // Determine storage type for RefreshTokenManager
    let refreshStorage: 'memory' | 'redis' | 'database' = 'memory';
    let refreshOptions: any = {
        multiLogin: config.multiLogin ?? true,
        i18n: config.i18n,
        errorMessages: config.errorMessages
    };

    if (config.redisClient) {
        refreshStorage = 'redis';
        refreshOptions.redisClient = config.redisClient;
    } else if (config.prismaClient || config.mongoClient || config.sequelizeClient) {
        refreshStorage = 'database';
        refreshOptions.dbClient = config.prismaClient || config.mongoClient || config.sequelizeClient;
    }

    const refreshManager = config.enableRefreshRotation ? new RefreshTokenManager(
        tokenManager,
        blacklist,
        refreshStorage,
        refreshOptions
    ) : null;

    // Initialize production features
    const rateLimitStorage = config.rateLimitStorage === 'redis' && config.redisClient
        ? new RedisRateLimitStorage(config.redisClient)
        : new MemoryRateLimitStorage();

    const securityLoggerInstance = config.enableSecurityLogging
        ? new SecurityLogger(config.securityLoggerConfig)
        : securityLogger;

    const metricsCollectorInstance = config.enableMetrics
        ? new MetricsCollector(config.metricsConfig)
        : metricsCollector;

    return {
        ...auth,

        // Token utilities
        generateRefreshToken: (payload: Partial<JWTPayload>) => {
            return tokenManager.generateRefreshToken(payload);
        },

        generateTokenPair: (payload: Partial<JWTPayload>) => {
            return tokenManager.generateTokenPair(payload);
        },

        isTokenExpired: (token: string) => {
            return tokenManager.isTokenExpired(token);
        },

        getTokenExpiry: (token: string) => {
            return tokenManager.getTokenExpiry(token);
        },

        // JWT Blacklisting
        blacklistToken: async (token: string, expiry?: number) => {
            return await blacklist.blacklistToken(token, expiry);
        },

        blacklistUser: async (userId: string) => {
            return await blacklist.blacklistUser(userId);
        },

        isTokenBlacklisted: async (token: string) => {
            return await blacklist.isTokenBlacklisted(token);
        },

        whitelistToken: async (token: string) => {
            return await blacklist.whitelistToken(token);
        },

        whitelistUser: async (userId: string) => {
            return await blacklist.whitelistUser(userId);
        },

        getBlacklistStats: async () => {
            return await blacklist.getStats();
        },

        // Password utilities
        hashPassword: async (password: string) => {
            return await passwordManager.hashPassword(password);
        },

        verifyPassword: async (password: string, hash: string) => {
            return await passwordManager.verifyPassword(password, hash);
        },

        validatePassword: (password: string) => {
            return passwordManager.validatePassword(password);
        },

        generatePassword: (length?: number) => {
            return passwordManager.generatePassword(length);
        },

        checkPasswordStrength: (password: string) => {
            return passwordStrengthChecker.calculateStrength(password);
        },

        // Multi-tenant support
        registerTenant: (tenantId: string, tenantConfig: any) => {
            return tenantManager?.registerTenant(tenantId, tenantConfig);
        },

        getTenant: (tenantId: string) => {
            return tenantManager?.getTenant(tenantId);
        },

        resolveTenant: async (req: any) => {
            return await tenantManager?.resolveTenant(req);
        },

        tenantMiddleware: tenantMiddleware ? {
            resolveTenant: () => tenantMiddleware.resolveTenant(),
            requireTenant: (tenantId: string) => tenantMiddleware.requireTenant(tenantId),
            requireTenantAdmin: () => tenantMiddleware.requireTenantAdmin()
        } : null,

        // Refresh token rotation
        generateRefreshTokenWithRotation: async (user: User, options?: any) => {
            return await refreshManager?.generateRefreshToken(user, options);
        },

        rotateRefreshToken: async (refreshToken: string, user: User) => {
            return await refreshManager?.rotateRefreshToken(refreshToken, user);
        },

        revokeRefreshToken: async (refreshToken: string) => {
            return await refreshManager?.revokeRefreshToken(refreshToken);
        },

        revokeUserTokens: async (userId: string) => {
            return await refreshManager?.revokeUserTokens(userId);
        },

        revokeDeviceTokens: async (userId: string, deviceId: string) => {
            return await refreshManager?.revokeDeviceTokens(userId, deviceId);
        },

        getUserActiveTokens: async (userId: string) => {
            return await refreshManager?.getUserActiveTokens(userId);
        },

        cleanupExpiredTokens: async () => {
            return await refreshManager?.cleanupExpiredTokens();
        },

        // Middleware utilities
        optional: () => {
            return middlewareFactory.optional();
        },

        requireRole: (role: string | string[]) => {
            return middlewareFactory.requireRole(role);
        },

        requirePermission: (permission: string | string[]) => {
            return middlewareFactory.requirePermission(permission);
        },

        requireAdmin: () => {
            return middlewareFactory.requireAdmin();
        },

        requireAllRoles: (roles: string[]) => {
            return middlewareFactory.requireAllRoles(roles);
        },

        requireAllPermissions: (permissions: string[]) => {
            return middlewareFactory.requireAllPermissions(permissions);
        },

        // Role checking utilities
        hasRole: (user: User, role: string | string[], requireAll?: boolean) => {
            return roleChecker.hasRole(user, role, requireAll || false);
        },

        hasPermission: (user: User, permission: string | string[], requireAll?: boolean) => {
            return roleChecker.hasPermission(user, permission, requireAll || false);
        },

        isAdmin: (user: User) => {
            return roleChecker.isAdmin(user);
        },

        // Production features
        rateLimiter: config.enableRateLimiting ? {
            login: AuthRateLimiters.loginRateLimiter(rateLimitStorage),
            passwordReset: AuthRateLimiters.passwordResetRateLimiter(rateLimitStorage),
            tokenRefresh: AuthRateLimiters.tokenRefreshRateLimiter(rateLimitStorage),
            api: AuthRateLimiters.apiRateLimiter(rateLimitStorage)
        } : null,

        securityLogger: securityLoggerInstance,

        metrics: metricsCollectorInstance,

        // Multi-login configuration
        isMultiLoginEnabled: () => {
            return config.multiLogin ?? true;
        },

        // i18n support
        setLocale: (locale: string) => {
            refreshManager?.setLocale(locale);
        },

        getLocale: () => {
            return refreshManager?.getLocale() || 'en';
        },

        getErrorMessage: (key: string, locale?: string) => {
            return refreshManager?.getErrorMessage(key as any, locale) || key;
        },

        getErrorMessageWithParams: (key: string, params: Record<string, string | number>, locale?: string) => {
            return refreshManager?.getErrorMessageWithParams(key as any, params, locale) || key;
        },

        addMessages: (locale: string, messages: Record<string, string>) => {
            refreshManager?.addMessages(locale, messages);
        },

        // Internal access to managers
        _tokenManager: tokenManager,
        _roleChecker: roleChecker,
        _middlewareFactory: middlewareFactory,
        _blacklist: blacklist,
        _passwordManager: passwordManager,
        _tenantManager: tenantManager,
        _refreshManager: refreshManager,
        _rateLimitStorage: rateLimitStorage
    };
}

// Export types for TypeScript users
export * from './types';
export * from './errors';

// Export classes for advanced usage
export { TokenManager } from './token';
export { RoleChecker } from './roles';
export { MiddlewareFactory } from './middleware';
export { JWTBlacklist } from './blacklist';
export { PasswordManager, PasswordStrengthChecker } from './password';
export { TenantManager, TenantMiddlewareFactory } from './tenant';
export { RefreshTokenManager } from './refresh';

// Export adapters
export {
    BlacklistAdapter,
    MemoryBlacklistAdapter,
    RedisBlacklistAdapter,
    PrismaBlacklistAdapter,
    MongoDBBlacklistAdapter,
    SequelizeBlacklistAdapter
} from './adapters/blacklist-adapter';

// Export production features
export {
    RateLimiter,
    AuthRateLimiters,
    MemoryRateLimitStorage,
    RedisRateLimitStorage
} from './rate-limiter';

export {
    SecurityLogger,
    securityLogger,
    SecurityEventType
} from './security-logger';

export {
    MetricsCollector,
    metricsCollector,
    MetricType
} from './metrics';

// Default export
export default { initAuth, createAuth };
