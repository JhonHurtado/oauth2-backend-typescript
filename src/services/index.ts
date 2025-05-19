import bcrypt from 'bcryptjs';
import prisma from '../config/database';
import { createError } from '../middleware/errorHandler';
import { 
  generateToken, 
  generateAccessToken, 
  generateRefreshToken,
  isExpired,
  formatScope,
  sanitizeUser 
} from '../utils';
import { 
  UserWithoutPassword, 
  RegisterUserBody, 
  OAuth2User, 
  OAuth2Client,
  AccessTokenWithRelations,
  RefreshTokenWithRelations
} from '../types';

export class UserService {
  /**
   * Create a new user
   */
  static async createUser(userData: RegisterUserBody): Promise<UserWithoutPassword> {
    const { email, username, password, firstName, lastName } = userData;

    // Check if user already exists
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ email }, { username }],
      },
    });

    if (existingUser) {
      throw createError('User with this email or username already exists', 409);
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = await prisma.user.create({
      data: {
        email,
        username,
        password: hashedPassword,
        firstName: firstName || null,
        lastName: lastName || null,
      },
      select: {
        id: true,
        email: true,
        username: true,
        firstName: true,
        lastName: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return user;
  }

  /**
   * Find user by email or username
   */
  static async findUserByLogin(login: string): Promise<OAuth2User | null> {
    return await prisma.user.findFirst({
      where: {
        OR: [{ email: login }, { username: login }],
        isActive: true,
      },
    });
  }

  /**
   * Find user by ID
   */
  static async findUserById(id: string): Promise<UserWithoutPassword | null> {
    return await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        username: true,
        firstName: true,
        lastName: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });
  }

  /**
   * Update user information
   */
  static async updateUser(id: string, updateData: Partial<RegisterUserBody>): Promise<UserWithoutPassword> {
    const user = await prisma.user.update({
      where: { id },
      data: updateData,
      select: {
        id: true,
        email: true,
        username: true,
        firstName: true,
        lastName: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return user;
  }

  /**
   * Verify user password
   */
  static async verifyPassword(user: OAuth2User, password: string): Promise<boolean> {
    return await bcrypt.compare(password, user.password);
  }

  /**
   * Deactivate user
   */
  static async deactivateUser(id: string): Promise<void> {
    await prisma.user.update({
      where: { id },
      data: { isActive: false },
    });
  }
}

export class ClientService {
  /**
   * Find client by clientId
   */
  static async findClientById(clientId: string): Promise<OAuth2Client | null> {
    return await prisma.client.findUnique({
      where: { clientId, isActive: true },
    });
  }

  /**
   * Verify client credentials
   */
  static async verifyClient(clientId: string, clientSecret: string): Promise<OAuth2Client | null> {
    const client = await prisma.client.findUnique({
      where: { clientId },
    });

    if (!client || client.clientSecret !== clientSecret || !client.isActive) {
      return null;
    }

    return client;
  }

  /**
   * Create a new client
   */
  static async createClient(clientData: {
    clientId: string;
    clientSecret: string;
    name: string;
    redirectUris: string[];
  }): Promise<OAuth2Client> {
    return await prisma.client.create({
      data: clientData,
    });
  }

  /**
   * Validate redirect URI for client
   */
  static async validateRedirectUri(clientId: string, redirectUri: string): Promise<boolean> {
    const client = await this.findClientById(clientId);
    return client ? client.redirectUris.includes(redirectUri) : false;
  }
}

export class TokenService {
  /**
   * Create authorization code
   */
  static async createAuthorizationCode(
    clientId: string,
    userId: string,
    redirectUri: string,
    scope: string[] = []
  ): Promise<string> {
    const code = generateToken();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await prisma.authorizationCode.create({
      data: {
        code,
        clientId,
        userId,
        redirectUri,
        scope,
        expiresAt,
      },
    });

    return code;
  }

  /**
   * Exchange authorization code for tokens
   */
  static async exchangeAuthorizationCode(
    clientId: string,
    code: string,
    redirectUri: string
  ): Promise<{ accessToken: string; refreshToken: string; expiresIn: number } | null> {
    // Find and validate authorization code
    const authCode = await prisma.authorizationCode.findUnique({
      where: { code },
      include: { user: true },
    });

    if (!authCode || authCode.clientId !== clientId || authCode.redirectUri !== redirectUri) {
      return null;
    }

    if (isExpired(authCode.expiresAt)) {
      // Clean up expired code
      await prisma.authorizationCode.delete({ where: { id: authCode.id } });
      return null;
    }

    // Delete the authorization code (one-time use)
    await prisma.authorizationCode.delete({ where: { id: authCode.id } });

    // Generate tokens
    const { token: accessToken, expiresAt: accessTokenExpiresAt } = generateAccessToken();
    const { token: refreshToken, expiresAt: refreshTokenExpiresAt } = generateRefreshToken();

    // Save tokens to database
    await Promise.all([
      prisma.accessToken.create({
        data: {
          token: accessToken,
          clientId,
          userId: authCode.userId,
          scope: authCode.scope,
          expiresAt: accessTokenExpiresAt,
        },
      }),
      prisma.refreshToken.create({
        data: {
          token: refreshToken,
          clientId,
          userId: authCode.userId,
          scope: authCode.scope,
          expiresAt: refreshTokenExpiresAt,
        },
      }),
    ]);

    return {
      accessToken,
      refreshToken,
      expiresIn: 3600, // 1 hour in seconds
    };
  }

  /**
   * Exchange refresh token for new access token
   */
  static async exchangeRefreshToken(
    clientId: string,
    refreshToken: string,
    scope?: string[]
  ): Promise<{ accessToken: string; expiresIn: number } | null> {
    // Find and validate refresh token
    const storedRefreshToken = await prisma.refreshToken.findUnique({
      where: { token: refreshToken },
      include: { user: true },
    });

    if (!storedRefreshToken || storedRefreshToken.clientId !== clientId) {
      return null;
    }

    if (isExpired(storedRefreshToken.expiresAt)) {
      // Clean up expired token
      await prisma.refreshToken.delete({ where: { id: storedRefreshToken.id } });
      return null;
    }

    // Generate new access token
    const { token: accessToken, expiresAt: accessTokenExpiresAt } = generateAccessToken();

    // Use provided scope or fall back to original scope
    const tokenScope = scope && scope.length > 0 ? scope : storedRefreshToken.scope;

    // Save new access token
    await prisma.accessToken.create({
      data: {
        token: accessToken,
        clientId,
        userId: storedRefreshToken.userId,
        scope: tokenScope,
        expiresAt: accessTokenExpiresAt,
      },
    });

    return {
      accessToken,
      expiresIn: 3600, // 1 hour in seconds
    };
  }

  /**
   * Validate access token
   */
  static async validateAccessToken(token: string): Promise<AccessTokenWithRelations | null> {
    const accessToken = await prisma.accessToken.findUnique({
      where: { token },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            username: true,
            firstName: true,
            lastName: true,
            isActive: true,
            createdAt: true,
            updatedAt: true,
          },
        },
        client: true,
      },
    });

    if (!accessToken || isExpired(accessToken.expiresAt) || !accessToken.user.isActive) {
      return null;
    }

    return accessToken;
  }

  /**
   * Revoke token (access or refresh)
   */
  static async revokeToken(token: string): Promise<boolean> {
    try {
      // Try to delete as access token
      const accessTokenResult = await prisma.accessToken.deleteMany({
        where: { token },
      });

      if (accessTokenResult.count > 0) {
        return true;
      }

      // Try to delete as refresh token
      const refreshTokenResult = await prisma.refreshToken.deleteMany({
        where: { token },
      });

      return refreshTokenResult.count > 0;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get user's active sessions
   */
  static async getUserSessions(userId: string): Promise<any[]> {
    const accessTokens = await prisma.accessToken.findMany({
      where: {
        userId,
        expiresAt: { gt: new Date() },
      },
      include: {
        client: {
          select: {
            name: true,
            clientId: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    return accessTokens.map(token => ({
      id: token.id,
      clientName: token.client.name,
      clientId: token.client.clientId,
      scope: token.scope,
      createdAt: token.createdAt,
      expiresAt: token.expiresAt,
    }));
  }

  /**
   * Revoke user session
   */
  static async revokeUserSession(userId: string, sessionId: string): Promise<boolean> {
    const result = await prisma.accessToken.deleteMany({
      where: {
        id: sessionId,
        userId,
      },
    });

    return result.count > 0;
  }

  /**
   * Revoke all user sessions except current
   */
  static async revokeAllUserSessions(userId: string, currentToken?: string): Promise<void> {
    // Delete all access tokens except current
    await prisma.accessToken.deleteMany({
      where: {
        userId,
        ...(currentToken && { token: { not: currentToken } }),
      },
    });

    // Delete all refresh tokens
    await prisma.refreshToken.deleteMany({
      where: { userId },
    });
  }

  /**
   * Clean up expired tokens
   */
  static async cleanupExpiredTokens(): Promise<{ accessTokens: number; refreshTokens: number; authCodes: number }> {
    const now = new Date();

    const [accessTokens, refreshTokens, authCodes] = await Promise.all([
      prisma.accessToken.deleteMany({
        where: { expiresAt: { lt: now } },
      }),
      prisma.refreshToken.deleteMany({
        where: { expiresAt: { lt: now } },
      }),
      prisma.authorizationCode.deleteMany({
        where: { expiresAt: { lt: now } },
      }),
    ]);

    return {
      accessTokens: accessTokens.count,
      refreshTokens: refreshTokens.count,
      authCodes: authCodes.count,
    };
  }
}