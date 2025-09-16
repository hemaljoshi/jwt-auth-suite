import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';

/**
 * Password hashing utilities
 * Provides secure password hashing and verification
 */
export class PasswordManager {
    private saltRounds: number;

    constructor(saltRounds: number = 12) {
        this.saltRounds = saltRounds;
    }

    /**
     * Hash a password
     */
    async hashPassword(password: string): Promise<string> {
        if (!password || password.length < 6) {
            throw new Error('Password must be at least 6 characters long');
        }

        return await bcrypt.hash(password, this.saltRounds);
    }

    /**
     * Verify a password against a hash
     */
    async verifyPassword(password: string, hash: string): Promise<boolean> {
        if (!password || !hash) {
            return false;
        }

        return await bcrypt.compare(password, hash);
    }

    /**
     * Check if a password meets security requirements
     */
    validatePassword(password: string): { valid: boolean; errors: string[] } {
        const errors: string[] = [];

        if (!password) {
            errors.push('Password is required');
            return { valid: false, errors };
        }

        if (password.length < 8) {
            errors.push('Password must be at least 8 characters long');
        }

        if (password.length > 128) {
            errors.push('Password must be less than 128 characters');
        }

        if (!/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter');
        }

        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter');
        }

        if (!/\d/.test(password)) {
            errors.push('Password must contain at least one number');
        }

        if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            errors.push('Password must contain at least one special character');
        }

        // Check for common passwords
        const commonPasswords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        ];

        if (commonPasswords.includes(password.toLowerCase())) {
            errors.push('Password is too common, please choose a stronger password');
        }

        return {
            valid: errors.length === 0,
            errors
        };
    }

    /**
     * Generate a random password using cryptographically secure random bytes
     */
    generatePassword(length: number = 12): string {
        const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
        let password = '';

        // Ensure at least one character from each category using secure random
        const lowercaseBytes = randomBytes(1);
        password += 'abcdefghijklmnopqrstuvwxyz'[lowercaseBytes[0] % 26]; // lowercase

        const uppercaseBytes = randomBytes(1);
        password += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[uppercaseBytes[0] % 26]; // uppercase

        const numberBytes = randomBytes(1);
        password += '0123456789'[numberBytes[0] % 10]; // number

        const specialBytes = randomBytes(1);
        password += '!@#$%^&*'[specialBytes[0] % 8]; // special char

        // Fill the rest randomly using secure random
        const remainingLength = length - 4;
        const randomBytesArray = randomBytes(remainingLength);
        for (let i = 0; i < remainingLength; i++) {
            password += charset[randomBytesArray[i] % charset.length];
        }

        // Shuffle the password using Fisher-Yates algorithm with secure random
        const passwordArray = password.split('');
        for (let i = passwordArray.length - 1; i > 0; i--) {
            const randomBytesArray = randomBytes(1);
            const j = randomBytesArray[0] % (i + 1);
            [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]];
        }

        return passwordArray.join('');
    }

    /**
     * Check if a password hash needs to be updated (older algorithm)
     */
    needsUpdate(hash: string): boolean {
        // Check if the hash uses an older bcrypt version or fewer rounds
        const rounds = this.getRoundsFromHash(hash);
        return rounds < this.saltRounds;
    }

    /**
     * Get the number of rounds from a bcrypt hash
     */
    private getRoundsFromHash(hash: string): number {
        const match = hash.match(/\$(\d+)\$/);
        return match ? parseInt(match[1], 10) : 0;
    }

    /**
     * Update password hash if needed
     */
    async updatePasswordIfNeeded(password: string, currentHash: string): Promise<string> {
        if (this.needsUpdate(currentHash)) {
            return await this.hashPassword(password);
        }
        return currentHash;
    }
}

/**
 * Password strength checker
 */
export class PasswordStrengthChecker {
    /**
     * Calculate password strength score (0-100)
     */
    calculateStrength(password: string): { score: number; level: string; feedback: string[] } {
        let score = 0;
        const feedback: string[] = [];

        if (!password) {
            return { score: 0, level: 'Very Weak', feedback: ['Password is required'] };
        }

        // Length scoring
        if (password.length >= 8) score += 20;
        else feedback.push('Use at least 8 characters');

        if (password.length >= 12) score += 10;
        if (password.length >= 16) score += 10;

        // Character variety scoring
        if (/[a-z]/.test(password)) score += 10;
        else feedback.push('Add lowercase letters');

        if (/[A-Z]/.test(password)) score += 10;
        else feedback.push('Add uppercase letters');

        if (/\d/.test(password)) score += 10;
        else feedback.push('Add numbers');

        if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score += 10;
        else feedback.push('Add special characters');

        // Pattern detection (penalties)
        if (/(.)\1{2,}/.test(password)) {
            score -= 10;
            feedback.push('Avoid repeated characters');
        }

        if (/123|abc|qwe|asd|zxc/i.test(password)) {
            score -= 15;
            feedback.push('Avoid common patterns');
        }

        // Common password check
        const commonPasswords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        ];

        if (commonPasswords.includes(password.toLowerCase())) {
            score = Math.min(score, 20);
            feedback.push('Avoid common passwords');
        }

        // Determine level
        let level: string;
        if (score >= 80) level = 'Very Strong';
        else if (score >= 60) level = 'Strong';
        else if (score >= 40) level = 'Medium';
        else if (score >= 20) level = 'Weak';
        else level = 'Very Weak';

        return { score: Math.max(0, Math.min(100, score)), level, feedback };
    }
}
