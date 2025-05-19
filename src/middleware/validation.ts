import { Request, Response, NextFunction } from 'express';
import { body, validationResult } from 'express-validator';

// Extract validation errors
export const handleValidationErrors = (req: Request, res: Response, next: NextFunction): void => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        statusCode: 400,
        details: errors.array(),
      },
      timestamp: new Date().toISOString(),
    });
    return;
  }
  
  next();
};

// User registration validation
export const validateUserRegistration = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Must be a valid email address'),
  
  body('username')
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number'),
  
  body('firstName')
    .optional()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters')
    .matches(/^[a-zA-ZÀ-ÿ\s]+$/)
    .withMessage('First name can only contain letters and spaces'),
  
  body('lastName')
    .optional()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters')
    .matches(/^[a-zA-ZÀ-ÿ\s]+$/)
    .withMessage('Last name can only contain letters and spaces'),
  
  handleValidationErrors,
];

// User login validation
export const validateUserLogin = [
  body('login')
    .notEmpty()
    .withMessage('Email or username is required'),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  
  handleValidationErrors,
];

// OAuth2 authorization validation
export const validateOAuth2Authorization = [
  body('response_type')
    .equals('code')
    .withMessage('Response type must be "code"'),
  
  body('client_id')
    .notEmpty()
    .withMessage('Client ID is required'),
  
  body('redirect_uri')
    .isURL()
    .withMessage('Redirect URI must be a valid URL'),
  
  body('scope')
    .optional()
    .isString()
    .withMessage('Scope must be a string'),
  
  body('state')
    .optional()
    .isString()
    .withMessage('State must be a string'),
  
  handleValidationErrors,
];

// OAuth2 token exchange validation
export const validateOAuth2Token = [
  body('grant_type')
    .isIn(['authorization_code', 'refresh_token'])
    .withMessage('Grant type must be "authorization_code" or "refresh_token"'),
  
  body('code')
    .if(body('grant_type').equals('authorization_code'))
    .notEmpty()
    .withMessage('Authorization code is required'),
  
  body('refresh_token')
    .if(body('grant_type').equals('refresh_token'))
    .notEmpty()
    .withMessage('Refresh token is required'),
  
  body('redirect_uri')
    .if(body('grant_type').equals('authorization_code'))
    .isURL()
    .withMessage('Redirect URI must be a valid URL'),
  
  body('client_id')
    .notEmpty()
    .withMessage('Client ID is required'),
  
  handleValidationErrors,
];