import { Request, Response, NextFunction } from 'express';
import { AuthConfig, ProtectOptions, TokenStorage, User } from './types';
import { TokenManager } from './token';
import { RoleChecker } from './roles';
import {
    createTokenMissingError,
    createTokenInvalidError,
    createInsufficientPermissionsError,
    createInvalidRoleError,
    formatErrorResponse,
    isSuperJWTError
} from './errors';

/**
 * Middleware factory for creating authentication middleware
 */
export class MiddlewareFactory {
    private tokenManager: TokenManager;
    private roleChecker: RoleChecker;
    private storage: TokenStorage;
    private cookieName: string;

    constructor(config: AuthConfig) {
        this.tokenManager = new TokenManager(config);
        this.roleChecker = new RoleChecker(config.roles, config.permissions);
        this.storage = config.storage || 'header';
        this.cookieName = config.cookieName || 'access_token';
    }

    /**
     * Extract token from request based on storage type
     */
    extractToken(req: Request): string | null {
        if (this.storage === 'cookie') {
            return req.cookies?.[this.cookieName] || null;
        } else {
            // Extract from Authorization header
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return null;
            }
            return authHeader.substring(7); // Remove 'Bearer ' prefix
        }
    }

    /**
     * Create protection middleware
     */
    protect(options: ProtectOptions = {}): (req: Request, res: Response, next: NextFunction) => void {
        return (req: Request, res: Response, next: NextFunction) => {
            try {
                // Extract token
                const token = this.extractToken(req);
                if (!token) {
                    throw createTokenMissingError();
                }

                // Verify token
                const payload = this.tokenManager.verifyToken(token);

                // Convert payload to user object
                const user = this.roleChecker.payloadToUser(payload);

                // Attach user to request
                req.user = user;

                // Check access requirements
                if (Object.keys(options).length > 0) {
                    if (!this.roleChecker.checkAccess(user, options)) {
                        // Determine what's missing for better error messages
                        if (options.role || options.roles) {
                            const requiredRoles = options.roles || (options.role ? [options.role] : []);
                            const missingRoles = this.roleChecker.getMissingRoles(user, requiredRoles as string[]);
                            throw createInvalidRoleError(missingRoles);
                        }

                        if (options.permission || options.permissions) {
                            const requiredPermissions = options.permissions || (options.permission ? [options.permission] : []);
                            const missingPermissions = this.roleChecker.getMissingPermissions(user, requiredPermissions as string[]);
                            throw createInsufficientPermissionsError(missingPermissions);
                        }
                    }
                }

                next();
            } catch (error) {
                this.handleError(error, res);
            }
        };
    }

    /**
     * Create optional authentication middleware (doesn't fail if no token)
     */
    optional(): (req: Request, res: Response, next: NextFunction) => void {
        return (req: Request, res: Response, next: NextFunction) => {
            try {
                const token = this.extractToken(req);
                if (token) {
                    const payload = this.tokenManager.verifyToken(token);
                    req.user = this.roleChecker.payloadToUser(payload);
                }
                next();
            } catch (error) {
                // For optional auth, we don't fail on invalid tokens
                // Just continue without setting req.user
                next();
            }
        };
    }

    /**
     * Create role-specific middleware
     */
    requireRole(role: string | string[]): (req: Request, res: Response, next: NextFunction) => void {
        return this.protect({ role, roles: Array.isArray(role) ? role : [role] });
    }

    /**
     * Create permission-specific middleware
     */
    requirePermission(permission: string | string[]): (req: Request, res: Response, next: NextFunction) => void {
        return this.protect({ permission, permissions: Array.isArray(permission) ? permission : [permission] });
    }

    /**
     * Create admin-only middleware
     */
    requireAdmin(): (req: Request, res: Response, next: NextFunction) => void {
        return this.requireRole('admin');
    }

    /**
     * Create middleware that requires all specified roles
     */
    requireAllRoles(roles: string[]): (req: Request, res: Response, next: NextFunction) => void {
        return this.protect({ roles, requireAll: true });
    }

    /**
     * Create middleware that requires all specified permissions
     */
    requireAllPermissions(permissions: string[]): (req: Request, res: Response, next: NextFunction) => void {
        return this.protect({ permissions, requireAll: true });
    }

    /**
     * Handle authentication errors
     */
    private handleError(error: any, res: Response): void {
        if (isSuperJWTError(error)) {
            res.status(error.statusCode).json(formatErrorResponse(error));
        } else {
            res.status(500).json({
                error: {
                    code: 'INTERNAL_ERROR',
                    message: 'An internal error occurred',
                    statusCode: 500
                }
            });
        }
    }

    /**
     * Get token manager instance
     */
    getTokenManager(): TokenManager {
        return this.tokenManager;
    }

    /**
     * Get role checker instance
     */
    getRoleChecker(): RoleChecker {
        return this.roleChecker;
    }
}
