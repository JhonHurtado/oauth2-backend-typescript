import { Router, Request, Response } from 'express';
import passport from 'passport';
import bcrypt from 'bcryptjs';
import prisma from '../config/database';
import { asyncHandler, createError } from '../middleware/errorHandler';
import { validateUserRegistration, validateUserLogin } from '../middleware/validation';

const router = Router();

// User registration
router.post('/register', validateUserRegistration, asyncHandler(async (req: Request, res: Response) => {
  const { email, username, password, firstName, lastName } = req.body;

  // Check if user already exists
  const existingUser = await prisma.user.findFirst({
    where: {
      OR: [
        { email },
        { username },
      ],
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

  res.status(201).json({
    success: true,
    message: 'User registered successfully',
    data: { user },
    timestamp: new Date().toISOString(),
  });
}));

// User login
router.post('/login', validateUserLogin, (req: Request, res: Response, next) => {
  passport.authenticate('local', (err: any, user: Express.User, info: any) => {
    if (err) {
      return next(err);
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        error: {
          message: info?.message || 'Invalid credentials',
          statusCode: 401,
        },
        timestamp: new Date().toISOString(),
      });
    }

    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }

      res.json({
        success: true,
        message: 'Login successful',
        data: { user },
        timestamp: new Date().toISOString(),
      });
    });
  })(req, res, next);
});

// User logout
router.post('/logout', (req: Request, res: Response) => {
  req.logOut((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        error: {
          message: 'Error during logout',
          statusCode: 500,
        },
        timestamp: new Date().toISOString(),
      });
    }

    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          error: {
            message: 'Error destroying session',
            statusCode: 500,
          },
          timestamp: new Date().toISOString(),
        });
      }

      res.clearCookie('connect.sid');
      res.json({
        success: true,
        message: 'Logout successful',
        timestamp: new Date().toISOString(),
      });
    });
  });
});

// Check authentication status
router.get('/me', (req: Request, res: Response) => {
  if (req.isAuthenticated()) {
    res.json({
      success: true,
      data: { user: req.user },
      timestamp: new Date().toISOString(),
    });
  } else {
    res.status(401).json({
      success: false,
      error: {
        message: 'Not authenticated',
        statusCode: 401,
      },
      timestamp: new Date().toISOString(),
    });
  }
});

export default router;