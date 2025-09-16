import { JWTPayload, User } from './types';

/**
 * Multi-tenant support for SaaS applications
 * Handles tenant isolation and tenant-specific authentication
 */
export class TenantManager {
    private tenants: Map<string, TenantInfo> = new Map();
    private tenantResolver: TenantResolver;

    constructor(tenantResolver?: TenantResolver) {
        this.tenantResolver = tenantResolver || new DefaultTenantResolver();
    }

    /**
     * Register a tenant
     */
    registerTenant(tenantId: string, config: TenantConfig): void {
        this.tenants.set(tenantId, {
            id: tenantId,
            createdAt: new Date(),
            isActive: true,
            settings: {},
            ...config
        });
    }

    /**
     * Get tenant by ID
     */
    getTenant(tenantId: string): TenantInfo | null {
        return this.tenants.get(tenantId) || null;
    }

    /**
     * Resolve tenant from request
     */
    async resolveTenant(req: any): Promise<TenantInfo | null> {
        return await this.tenantResolver.resolve(req, this.tenants);
    }

    /**
     * Check if tenant is active
     */
    isTenantActive(tenantId: string): boolean {
        const tenant = this.getTenant(tenantId);
        return tenant ? tenant.isActive : false;
    }

    /**
     * Get tenant-specific configuration
     */
    getTenantConfig(tenantId: string, key: string): any {
        const tenant = this.getTenant(tenantId);
        return tenant ? tenant.settings[key] : null;
    }

    /**
     * Update tenant configuration
     */
    updateTenantConfig(tenantId: string, key: string, value: any): void {
        const tenant = this.getTenant(tenantId);
        if (tenant) {
            tenant.settings[key] = value;
        }
    }

    /**
     * Deactivate tenant
     */
    deactivateTenant(tenantId: string): void {
        const tenant = this.getTenant(tenantId);
        if (tenant) {
            tenant.isActive = false;
        }
    }

    /**
     * Activate tenant
     */
    activateTenant(tenantId: string): void {
        const tenant = this.getTenant(tenantId);
        if (tenant) {
            tenant.isActive = true;
        }
    }

    /**
     * List all tenants
     */
    listTenants(): TenantInfo[] {
        return Array.from(this.tenants.values());
    }

    /**
     * List active tenants
     */
    listActiveTenants(): TenantInfo[] {
        return Array.from(this.tenants.values()).filter(tenant => tenant.isActive);
    }
}

/**
 * Tenant information interface
 */
export interface TenantInfo {
    id: string;
    name: string;
    domain?: string;
    subdomain?: string;
    isActive: boolean;
    settings: Record<string, any>;
    createdAt: Date;
    [key: string]: any;
}

/**
 * Tenant configuration interface
 */
export interface TenantConfig {
    name: string;
    domain?: string;
    subdomain?: string;
    isActive?: boolean;
    settings?: Record<string, any>;
    [key: string]: any;
}

/**
 * Tenant resolver interface
 */
export interface TenantResolver {
    resolve(req: any, tenants: Map<string, TenantInfo>): Promise<TenantInfo | null>;
}

/**
 * Default tenant resolver
 * Resolves tenant by subdomain, domain, or header
 */
export class DefaultTenantResolver implements TenantResolver {
    async resolve(req: any, tenants: Map<string, TenantInfo>): Promise<TenantInfo | null> {
        // Try to resolve by subdomain
        const host = req.get('host') || req.hostname;
        if (host) {
            const subdomain = host.split('.')[0];
            for (const tenant of tenants.values()) {
                if (tenant.subdomain === subdomain) {
                    return tenant;
                }
            }
        }

        // Try to resolve by domain
        if (host) {
            for (const tenant of tenants.values()) {
                if (tenant.domain === host) {
                    return tenant;
                }
            }
        }

        // Try to resolve by X-Tenant-ID header
        const tenantId = req.get('X-Tenant-ID');
        if (tenantId) {
            return tenants.get(tenantId) || null;
        }

        // Try to resolve by query parameter
        const queryTenantId = req.query.tenant;
        if (queryTenantId) {
            return tenants.get(queryTenantId) || null;
        }

        return null;
    }
}

/**
 * Custom tenant resolver
 * Allows custom logic for tenant resolution
 */
export class CustomTenantResolver implements TenantResolver {
    private resolverFn: (req: any, tenants: Map<string, TenantInfo>) => Promise<TenantInfo | null>;

    constructor(resolverFn: (req: any, tenants: Map<string, TenantInfo>) => Promise<TenantInfo | null>) {
        this.resolverFn = resolverFn;
    }

    async resolve(req: any, tenants: Map<string, TenantInfo>): Promise<TenantInfo | null> {
        return await this.resolverFn(req, tenants);
    }
}

/**
 * Tenant-aware user interface
 */
export interface TenantUser extends User {
    tenantId: string;
    tenantRole?: string;
    tenantPermissions?: string[];
}

/**
 * Tenant-aware JWT payload
 */
export interface TenantJWTPayload extends JWTPayload {
    tenantId: string;
    tenantRole?: string;
    tenantPermissions?: string[];
}

/**
 * Tenant middleware factory
 */
export class TenantMiddlewareFactory {
    private tenantManager: TenantManager;

    constructor(tenantManager: TenantManager) {
        this.tenantManager = tenantManager;
    }

    /**
     * Create tenant resolution middleware
     */
    resolveTenant() {
        return async (req: any, res: any, next: any) => {
            try {
                const tenant = await this.tenantManager.resolveTenant(req);

                if (!tenant) {
                    return res.status(400).json({
                        error: 'Tenant not found',
                        code: 'TENANT_NOT_FOUND'
                    });
                }

                if (!tenant.isActive) {
                    return res.status(403).json({
                        error: 'Tenant is inactive',
                        code: 'TENANT_INACTIVE'
                    });
                }

                req.tenant = tenant;
                next();
            } catch (error) {
                res.status(500).json({
                    error: 'Tenant resolution failed',
                    code: 'TENANT_RESOLUTION_ERROR'
                });
            }
        };
    }

    /**
     * Create tenant-specific auth middleware
     */
    requireTenant(tenantId: string) {
        return (req: any, res: any, next: any) => {
            if (!req.tenant || req.tenant.id !== tenantId) {
                return res.status(403).json({
                    error: 'Access denied for this tenant',
                    code: 'TENANT_ACCESS_DENIED'
                });
            }
            next();
        };
    }

    /**
     * Create tenant admin middleware
     */
    requireTenantAdmin() {
        return (req: any, res: any, next: any) => {
            if (!req.tenant) {
                return res.status(400).json({
                    error: 'Tenant not resolved',
                    code: 'TENANT_NOT_RESOLVED'
                });
            }

            if (!req.user || req.user.tenantRole !== 'admin') {
                return res.status(403).json({
                    error: 'Tenant admin access required',
                    code: 'TENANT_ADMIN_REQUIRED'
                });
            }

            next();
        };
    }
}
