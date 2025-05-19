import { Router, Request, Response } from 'express';
import oauth2Server from '../config/oauth2';
import passport from 'passport';
import prisma from '../config/database';
import { asyncHandler, createError } from '../middleware/errorHandler';
import { authenticateClient } from '../middleware/auth';
import { validateOAuth2Authorization, validateOAuth2Token } from '../middleware/validation';

const router = Router();

// OAuth2 authorization endpoint
router.get('/authorize', asyncHandler(async (req: Request, res: Response) => {
  const { client_id, redirect_uri, response_type, scope, state } = req.query;

  // Validate required parameters
  if (!client_id || !redirect_uri || response_type !== 'code') {
    throw createError('Invalid authorization request', 400);
  }

  // Verify client exists and redirect URI is valid
  const client = await prisma.client.findUnique({
    where: { clientId: client_id as string },
  });

  if (!client || !client.isActive) {
    throw createError('Invalid client', 400);
  }

  if (!client.redirectUris.includes(redirect_uri as string)) {
    throw createError('Invalid redirect URI', 400);
  }

  // Check if user is authenticated
  if (!req.isAuthenticated()) {
    // Redirect to login with authorization parameters
    const loginUrl = new URL('/api/auth/login', `${req.protocol}://${req.get('host')}`);\
    loginUrl.searchParams.set('redirect', req.originalUrl);
    
    return res.redirect(loginUrl.toString());
  }

  // If user is authenticated, show authorization page or auto-approve
  // For simplicity, we'll auto-approve if user is authenticated
  try {
    const code = await new Promise<string>((resolve, reject) => {
      oauth2Server.grant(oauth2Server.grant.code(async (client, redirectUri, user, ares, done) => {
        done(null, 'temporary-code'); // This will be replaced by oauth2Server
      }))(client, redirect_uri as string, req.user as any, { scope: scope as string }, (err: any, code: string) => {
        if (err) reject(err);
        else resolve(code);
      });
    });

    const authUrl = new URL(redirect_uri as string);
    authUrl.searchParams.set('code', code);
    if (state) authUrl.searchParams.set('state', state as string);

    res.redirect(authUrl.toString());
  } catch (error) {
    throw createError('Authorization failed', 500);
  }
}));

// OAuth2 authorization decision (for explicit user consent)
router.post('/authorize/decision', asyncHandler(async (req: Request, res: Response) => {
  const { transaction_id, allow } = req.body;

  if (!req.isAuthenticated()) {
    throw createError('Authentication required', 401);
  }

  // This would handle explicit user consent
  // For now, we'll implement a simple allow/deny
  if (allow) {
    // Continue with authorization
    res.json({
      success: true,
      message: 'Authorization granted',
      timestamp: new Date().toISOString(),
    });
  } else {
    // User denied authorization
    res.status(403).json({
      success: false,
      error: {
        message: 'Authorization denied by user',
        statusCode: 403,
      },
      timestamp: new Date().toISOString(),
    });
  }
}));

// OAuth2 token endpoint
router.post('/token', authenticateClient, validateOAuth2Token, (req: Request, res: Response, next) => {
  oauth2Server.token()(req, res, next);
});

// OAuth2 token information endpoint
router.get('/tokeninfo', (req: Request, res: Response, next) => {
  passport.authenticate('bearer', { session: false }, async (err: any, user: Express.User) => {
    if (err) {
      return next(err);
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        error: {
          message: 'Invalid access token',
          statusCode: 401,
        },
        timestamp: new Date().toISOString(),
      });
    }

    try {
      // Get token information
      const authHeader = req.headers.authorization;
      const token = authHeader?.split(' ')[1];

      if (!token) {
        return res.status(401).json({
          success: false,
          error: {
            message: 'No token provided',
            statusCode: 401,
          },
          timestamp: new Date().toISOString(),
        });
      }

      const accessToken = await prisma.accessToken.findUnique({
        where: { token },
        include: {
          client: {
            select: {
              clientId: true,
              name: true,
            },
          },
          user: {
            select: {
              id: true,
              email: true,
              username: true,
            },
          },
        },
      });

      if (!accessToken) {
        return res.status(401).json({
          success: false,
          error: {
            message: 'Token not found',
            statusCode: 401,
          },
          timestamp: new Date().toISOString(),
        });
      }

      res.json({
        success: true,
        data: {
          client_id: accessToken.client.clientId,
          client_name: accessToken.client.name,
          user_id: accessToken.user.id,
          username: accessToken.user.username,
          email: accessToken.user.email,
          scope: accessToken.scope,
          expires_at: accessToken.expiresAt,
          issued_at: accessToken.createdAt,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  })(req, res, next);
});

// Revoke token endpoint
router.post('/revoke', authenticateClient, asyncHandler(async (req: Request, res: Response) => {
  const { token, token_type_hint } = req.body;

  if (!token) {
    throw createError('Token is required', 400);
  }

  try {
    // Try to revoke as access token first
    const accessToken = await prisma.accessToken.findUnique({
      where: { token },
    });

    if (accessToken) {
      await prisma.accessToken.delete({
        where: { token },
      });
    } else {
      // Try to revoke as refresh token
      const refreshToken = await prisma.refreshToken.findUnique({
        where: { token },
      });

      if (refreshToken) {
        await prisma.refreshToken.delete({
          where: { token },
        });
      }
    }

    // Always return success (as per RFC 7009)
    res.json({
      success: true,
      message: 'Token revoked successfully',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    // Always return success for security reasons
    res.json({
      success: true,
      message: 'Token revoked successfully',
      timestamp: new Date().toISOString(),
    });
  }
}));

export default router;