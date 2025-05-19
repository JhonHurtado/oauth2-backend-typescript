import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

/**
 * Generate a random token
 */
export function generateToken(): string {
  return uuidv4();
}

/**
 * Generate a secure random string
 */
export function generateSecureToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Create a JWT token
 */
export function createJWT(payload: any, expiresIn: string = '1h'): string {
  const secret = process.env.JWT_SECRET || 'fallback-secret';
  return jwt.sign(payload, secret, { expiresIn });
}

/**
 * Verify a JWT token
 */
export function verifyJWT(token: string): any {
  const secret = process.env.JWT_SECRET || 'fallback-secret';
  return jwt.verify(token, secret);
}

/**
 * Generate authorization code with expiration
 */
export function generateAuthCode(): { code: string; expiresAt: Date } {
  return {
    code: generateToken(),
    expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
  };
}

/**
 * Generate access token with expiration
 */
export function generateAccessToken(): { token: string; expiresAt: Date } {
  return {
    token: generateToken(),
    expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
  };
}

/**
 * Generate refresh token with expiration
 */
export function generateRefreshToken(): { token: string; expiresAt: Date } {
  return {
    token: generateToken(),
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
  };
}

/**
 * Check if a token is expired
 */
export function isExpired(expiresAt: Date): boolean {
  return new Date() > expiresAt;
}

/**
 * Format scope string into array
 */
export function formatScope(scope?: string | string[]): string[] {
  if (!scope) return [];
  if (Array.isArray(scope)) return scope;
  return scope.split(' ').filter(Boolean);
}

/**
 * Validate email format
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validate password strength
 */
export function isValidPassword(password: string): {
  isValid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
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
  
  return {
    isValid: errors.length === 0,
    errors,
  };
}

/**
 * Validate username format
 */
export function isValidUsername(username: string): boolean {
  // Username: 3-30 characters, letters, numbers, underscores only
  const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
  return usernameRegex.test(username);
}

/**
 * Extract basic authorization from header
 */
export function extractBasicAuth(authorization?: string): { clientId: string; clientSecret: string } | null {
  if (!authorization || !authorization.startsWith('Basic ')) {
    return null;
  }
  
  try {
    const credentials = Buffer.from(authorization.slice(6), 'base64').toString('utf-8');
    const [clientId, clientSecret] = credentials.split(':');
    
    if (!clientId || !clientSecret) {
      return null;
    }
    
    return { clientId, clientSecret };
  } catch (error) {
    return null;
  }
}

/**
 * Extract bearer token from header
 */
export function extractBearerToken(authorization?: string): string | null {
  if (!authorization || !authorization.startsWith('Bearer ')) {
    return null;
  }
  
  return authorization.slice(7);
}

/**
 * Sanitize user object (remove sensitive fields)
 */
export function sanitizeUser(user: any): any {
  const { password, ...sanitizedUser } = user;
  return sanitizedUser;
}

/**
 * Generate client credentials
 */
export function generateClientCredentials(): { clientId: string; clientSecret: string } {
  return {
    clientId: generateSecureToken(16),
    clientSecret: generateSecureToken(32),
  };
}

/**
 * Calculate token expiration time in seconds
 */
export function getExpiresIn(expiresAt: Date): number {
  return Math.floor((expiresAt.getTime() - Date.now()) / 1000);
}

/**
 * Validate redirect URI
 */
export function isValidRedirectUri(uri: string): boolean {
  try {
    const url = new URL(uri);
    // Only allow http and https protocols
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch (error) {
    return false;
  }
}

/**
 * Sleep utility for testing/delayed operations
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Format error response
 */
export function formatErrorResponse(message: string, statusCode: number = 500, details?: any): any {
  return {
    success: false,
    error: {
      message,
      statusCode,
      ...(details && { details }),
    },
    timestamp: new Date().toISOString(),
  };
}

/**
 * Format success response
 */
export function formatSuccessResponse(data?: any, message?: string): any {
  return {
    success: true,
    ...(message && { message }),
    ...(data && { data }),
    timestamp: new Date().toISOString(),
  };
}