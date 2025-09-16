import { AuthError, ErrorCodes } from './types';

/**
 * Custom error class for authentication errors
 */
export class SuperJWTError extends Error implements AuthError {
    public code: string;
    public statusCode: number;

    constructor(message: string, code: string, statusCode: number = 401) {
        super(message);
        this.name = 'SuperJWTError';
        this.code = code;
        this.statusCode = statusCode;

        // Maintains proper stack trace for where our error was thrown
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, SuperJWTError);
        }
    }
}

/**
 * Create a token missing error
 */
export function createTokenMissingError(): SuperJWTError {
    return new SuperJWTError(
        'Access token is missing',
        ErrorCodes.TOKEN_MISSING,
        401
    );
}

/**
 * Create a token invalid error
 */
export function createTokenInvalidError(): SuperJWTError {
    return new SuperJWTError(
        'Access token is invalid',
        ErrorCodes.TOKEN_INVALID,
        401
    );
}

/**
 * Create a token expired error
 */
export function createTokenExpiredError(): SuperJWTError {
    return new SuperJWTError(
        'Access token has expired',
        ErrorCodes.TOKEN_EXPIRED,
        401
    );
}

/**
 * Create an insufficient permissions error
 */
export function createInsufficientPermissionsError(required: string[]): SuperJWTError {
    return new SuperJWTError(
        `Insufficient permissions. Required: ${required.join(', ')}`,
        ErrorCodes.INSUFFICIENT_PERMISSIONS,
        403
    );
}

/**
 * Create an invalid role error
 */
export function createInvalidRoleError(required: string[]): SuperJWTError {
    return new SuperJWTError(
        `Invalid role. Required: ${required.join(', ')}`,
        ErrorCodes.INVALID_ROLE,
        403
    );
}

/**
 * Create a configuration error
 */
export function createConfigError(message: string): SuperJWTError {
    return new SuperJWTError(
        `Configuration error: ${message}`,
        ErrorCodes.CONFIG_ERROR,
        500
    );
}

/**
 * Check if an error is a SuperJWT error
 */
export function isSuperJWTError(error: any): error is SuperJWTError {
    return error instanceof SuperJWTError;
}

/**
 * Format error for API response
 */
export function formatErrorResponse(error: SuperJWTError) {
    return {
        error: {
            code: error.code,
            message: error.message,
            statusCode: error.statusCode
        }
    };
}
