import { Request, Response, NextFunction } from 'express';
import passport from 'passport';
import { User } from '@prisma/client';

// Extend Express Request type to include user
declare global {
  namespace Express {
    interface User {
      id: string;
      email: string;
      username: string;
      firstName?: string;
      lastName?: string;
      isActive: boolean;
      createdAt: Date;
      updatedAt: Date;
    }
  }
}

// Middleware to ensure user is authenticated
export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  if (req.isAuthenticated()) {
    return next();
  }
  
  res.status(401).json({
    success: false,
    error: {
      message: 'Authentication required',
      statusCode: 401,
    },
    timestamp: new Date().toISOString(),
  });
};

// Middleware to authenticate with bearer token
export const authenticateBearer = (req: Request, res: Response, next: NextFunction): void => {
  passport.authenticate('bearer', { session: false }, (err: any, user: Express.User) => {
    if (err) {
      return next(err);
    }
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: {
          message: 'Invalid or expired access token',
          statusCode: 401,
        },
        timestamp: new Date().toISOString(),
      });
    }
    
    req.user = user;
    next();
  })(req, res, next);
};

// Middleware to authenticate client credentials
export const authenticateClient = (req: Request, res: Response, next: NextFunction): void => {
  passport.authenticate(['basic', 'oauth2-client-password'], { session: false }, (err: any, client: any) => {
    if (err) {
      return next(err);
    }
    
    if (!client) {
      return res.status(401).json({
        success: false,
        error: {
          message: 'Invalid client credentials',
          statusCode: 401,
        },
        timestamp: new Date().toISOString(),
      });
    }
    
    req.user = client;
    next();
  })(req, res, next);
};

// Optional authentication - doesn't fail if no auth provided
export const optionalAuth = (req: Request, res: Response, next: NextFunction): void => {
  passport.authenticate('bearer', { session: false }, (err: any, user: Express.User) => {
    if (err) {
      return next(err);
    }
    
    if (user) {
      req.user = user;
    }
    
    next();
  })(req, res, next);
};