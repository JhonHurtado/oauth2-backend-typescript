import { Router, Request, Response } from 'express';
import { authenticateBearer, requireAuth } from '../middleware/auth';
import { asyncHandler, createError } from '../middleware/errorHandler';
import prisma from '../config/database';

const router = Router();

// Get user profile (session-based authentication)
router.get('/profile', requireAuth, asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw createError('User not found in session', 404);
  }

  res.json({
    success: true,
    data: { user: req.user },
    timestamp: new Date().toISOString(),
  });
}));

// Get user profile (OAuth2 bearer token authentication)
router.get('/me', authenticateBearer, asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw createError('User not found', 404);
  }

  // Get additional user information
  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
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

  if (!user) {
    throw createError('User not found', 404);
  }

  res.json({
    success: true,
    data: { user },
    timestamp: new Date().toISOString(),
  });
}));

// Update user profile (session-based authentication)
router.put('/profile', requireAuth, asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw createError('User not found in session', 404);
  }

  const { firstName, lastName } = req.body;

  // Update user information
  const updatedUser = await prisma.user.update({
    where: { id: req.user.id },
    data: {
      firstName: firstName !== undefined ? firstName : undefined,
      lastName: lastName !== undefined ? lastName : undefined,
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

  res.json({
    success: true,
    message: 'Profile updated successfully',
    data: { user: updatedUser },
    timestamp: new Date().toISOString(),
  });
}));

// Update user profile (OAuth2 bearer token authentication)
router.put('/me', authenticateBearer, asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw createError('User not found', 404);
  }

  const { firstName, lastName } = req.body;

  // Update user information
  const updatedUser = await prisma.user.update({
    where: { id: req.user.id },
    data: {
      firstName: firstName !== undefined ? firstName : undefined,
      lastName: lastName !== undefined ? lastName : undefined,
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

  res.json({
    success: true,
    message: 'Profile updated successfully',
    data: { user: updatedUser },
    timestamp: new Date().toISOString(),
  });
}));

// Get user's active sessions/tokens (OAuth2 bearer token authentication)
router.get('/sessions', authenticateBearer, asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw createError('User not found', 404);
  }

  // Get user's active access tokens
  const accessTokens = await prisma.accessToken.findMany({
    where: {
      userId: req.user.id,
      expiresAt: {
        gt: new Date(),
      },
    },
    include: {
      client: {
        select: {
          name: true,
          clientId: true,
        },
      },
    },
    orderBy: {
      createdAt: 'desc',
    },
  });

  const sessions = accessTokens.map(token => ({
    id: token.id,
    clientName: token.client.name,
    clientId: token.client.clientId,
    scope: token.scope,
    createdAt: token.createdAt,
    expiresAt: token.expiresAt,
  }));

  res.json({
    success: true,
    data: { sessions },
    timestamp: new Date().toISOString(),
  });
}));

// Revoke a specific session/token
router.delete('/sessions/:sessionId', authenticateBearer, asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw createError('User not found', 404);
  }

  const { sessionId } = req.params;

  // Delete the access token (if it belongs to the user)
  const deletedToken = await prisma.accessToken.deleteMany({
    where: {
      id: sessionId,
      userId: req.user.id,
    },
  });

  if (deletedToken.count === 0) {
    throw createError('Session not found or not authorized', 404);
  }

  res.json({
    success: true,
    message: 'Session revoked successfully',
    timestamp: new Date().toISOString(),
  });
}));

// Revoke all sessions/tokens for the user
router.delete('/sessions', authenticateBearer, asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw createError('User not found', 404);
  }

  // Get current token to exclude it from deletion
  const authHeader = req.headers.authorization;
  const currentToken = authHeader?.split(' ')[1];

  // Delete all access tokens except the current one
  await prisma.accessToken.deleteMany({
    where: {
      userId: req.user.id,
      token: {
        not: currentToken,
      },
    },
  });

  // Delete all refresh tokens
  await prisma.refreshToken.deleteMany({
    where: {
      userId: req.user.id,
    },
  });

  res.json({
    success: true,
    message: 'All sessions revoked successfully',
    timestamp: new Date().toISOString(),
  });
}));

export default router;