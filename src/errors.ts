import { AuthError, ErrorCodes } from './types';

/**
 * Custom error class for authentication errors
 */
export class JWTAuthSuiteError extends Error implements AuthError {
    public code: string;
    public statusCode: number;

    constructor(message: string, code: string, statusCode: number = 401) {
        super(message);
        this.name = 'JWTAuthSuiteError';
        this.code = code;
        this.statusCode = statusCode;

        // Maintains proper stack trace for where our error was thrown
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, JWTAuthSuiteError);
        }
    }
}

/**
 * Create a token missing error
 */
export function createTokenMissingError(): JWTAuthSuiteError {
    return new JWTAuthSuiteError(
        'Access token is missing',
        ErrorCodes.TOKEN_MISSING,
        401
    );
}

/**
 * Create a token invalid error
 */
export function createTokenInvalidError(): JWTAuthSuiteError {
    return new JWTAuthSuiteError(
        'Access token is invalid',
        ErrorCodes.TOKEN_INVALID,
        401
    );
}

/**
 * Create a token expired error
 */
export function createTokenExpiredError(): JWTAuthSuiteError {
    return new JWTAuthSuiteError(
        'Access token has expired',
        ErrorCodes.TOKEN_EXPIRED,
        401
    );
}

/**
 * Create an insufficient permissions error
 */
export function createInsufficientPermissionsError(required: string[]): JWTAuthSuiteError {
    return new JWTAuthSuiteError(
        `Insufficient permissions. Required: ${required.join(', ')}`,
        ErrorCodes.INSUFFICIENT_PERMISSIONS,
        403
    );
}

/**
 * Create an invalid role error
 */
export function createInvalidRoleError(required: string[]): JWTAuthSuiteError {
    return new JWTAuthSuiteError(
        `Invalid role. Required: ${required.join(', ')}`,
        ErrorCodes.INVALID_ROLE,
        403
    );
}

/**
 * Create a configuration error
 */
export function createConfigError(message: string): JWTAuthSuiteError {
    return new JWTAuthSuiteError(
        `Configuration error: ${message}`,
        ErrorCodes.CONFIG_ERROR,
        500
    );
}

/**
 * Check if an error is a JWT Auth Suite error
 */
export function isJWTAuthSuiteError(error: any): error is JWTAuthSuiteError {
    return error instanceof JWTAuthSuiteError;
}

/**
 * Format error for API response
 */
export function formatErrorResponse(error: JWTAuthSuiteError) {
    return {
        error: {
            code: error.code,
            message: error.message,
            statusCode: error.statusCode
        }
    };
}
