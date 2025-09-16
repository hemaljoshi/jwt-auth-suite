import { User, ProtectOptions, JWTPayload } from './types';
import {
    createInsufficientPermissionsError,
    createInvalidRoleError
} from './errors';

/**
 * Role and permission checker utility
 */
export class RoleChecker {
    private availableRoles: string[];
    private availablePermissions: string[];

    constructor(roles: string[] = [], permissions: string[] = []) {
        this.availableRoles = roles;
        this.availablePermissions = permissions;
    }

    /**
     * Check if user has required role(s)
     */
    hasRole(user: User, requiredRoles: string | string[], requireAll: boolean = false): boolean {
        const userRole = user.role;
        if (!userRole) return false;

        const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];

        if (requireAll) {
            // User must have ALL specified roles
            return roles.every(role => userRole === role);
        } else {
            // User must have ANY of the specified roles
            return roles.includes(userRole);
        }
    }

    /**
     * Check if user has required permission(s)
     */
    hasPermission(user: User, requiredPermissions: string | string[], requireAll: boolean = false): boolean {
        const userPermissions = user.permissions || [];
        const permissions = Array.isArray(requiredPermissions) ? requiredPermissions : [requiredPermissions];

        if (requireAll) {
            // User must have ALL specified permissions
            return permissions.every(permission => userPermissions.includes(permission));
        } else {
            // User must have ANY of the specified permissions
            return permissions.some(permission => userPermissions.includes(permission));
        }
    }

    /**
     * Check if user meets the protection requirements
     */
    checkAccess(user: User, options: ProtectOptions): boolean {
        // Check role requirements
        if (options.role || options.roles) {
            const requiredRoles = options.roles || (options.role ? [options.role] : []);
            if (!this.hasRole(user, requiredRoles as string[], options.requireAll)) {
                return false;
            }
        }

        // Check permission requirements
        if (options.permission || options.permissions) {
            const requiredPermissions = options.permissions || (options.permission ? [options.permission] : []);
            if (!this.hasPermission(user, requiredPermissions as string[], options.requireAll)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get missing roles for user
     */
    getMissingRoles(user: User, requiredRoles: string | string[]): string[] {
        const userRole = user.role;
        if (!userRole) return Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];

        const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];
        return roles.filter(role => userRole !== role);
    }

    /**
     * Get missing permissions for user
     */
    getMissingPermissions(user: User, requiredPermissions: string | string[]): string[] {
        const userPermissions = user.permissions || [];
        const permissions = Array.isArray(requiredPermissions) ? requiredPermissions : [requiredPermissions];
        return permissions.filter(permission => !userPermissions.includes(permission));
    }

    /**
     * Validate that all required roles exist in available roles
     */
    validateRoles(requiredRoles: string[]): void {
        const invalidRoles = requiredRoles.filter(role => !this.availableRoles.includes(role));
        if (invalidRoles.length > 0) {
            throw createInvalidRoleError(invalidRoles);
        }
    }

    /**
     * Validate that all required permissions exist in available permissions
     */
    validatePermissions(requiredPermissions: string[]): void {
        const invalidPermissions = requiredPermissions.filter(permission => !this.availablePermissions.includes(permission));
        if (invalidPermissions.length > 0) {
            throw createInsufficientPermissionsError(invalidPermissions);
        }
    }

    /**
     * Convert JWT payload to User object
     */
    payloadToUser(payload: JWTPayload): User {
        return {
            id: payload.sub,
            email: payload.email,
            role: payload.role,
            permissions: payload.permissions,
            ...payload // Include any additional claims
        };
    }

    /**
     * Check if user has admin role
     */
    isAdmin(user: User): boolean {
        return this.hasRole(user, 'admin');
    }

    /**
     * Check if user has any of the specified roles
     */
    hasAnyRole(user: User, roles: string[]): boolean {
        return this.hasRole(user, roles, false);
    }

    /**
     * Check if user has all of the specified roles
     */
    hasAllRoles(user: User, roles: string[]): boolean {
        return this.hasRole(user, roles, true);
    }

    /**
     * Check if user has any of the specified permissions
     */
    hasAnyPermission(user: User, permissions: string[]): boolean {
        return this.hasPermission(user, permissions, false);
    }

    /**
     * Check if user has all of the specified permissions
     */
    hasAllPermissions(user: User, permissions: string[]): boolean {
        return this.hasPermission(user, permissions, true);
    }
}
