import { User, Client, AccessToken, RefreshToken, AuthorizationCode } from '@prisma/client';

// Extend Express Request type
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

    interface Request {
      user?: User;
    }
  }
}

// OAuth2 Server types
export interface OAuth2Client extends Client {}

export interface OAuth2User extends User {}

export interface TokenInfo {
  client_id: string;
  client_name: string;
  user_id: string;
  username: string;
  email: string;
  scope: string[];
  expires_at: Date;
  issued_at: Date;
}

// API Response types
export interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
  error?: {
    message: string;
    statusCode: number;
    details?: any;
  };
  timestamp: string;
}

export interface UserSession {
  id: string;
  clientName: string;
  clientId: string;
  scope: string[];
  createdAt: Date;
  expiresAt: Date;
}

// Request body types
export interface RegisterUserBody {
  email: string;
  username: string;
  password: string;
  firstName?: string;
  lastName?: string;
}

export interface LoginUserBody {
  login: string; // email or username
  password: string;
}

export interface UpdateUserBody {
  firstName?: string;
  lastName?: string;
}

export interface OAuth2AuthorizeQuery {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  scope?: string;
  state?: string;
}

export interface OAuth2TokenBody {
  grant_type: 'authorization_code' | 'refresh_token';
  code?: string;
  refresh_token?: string;
  redirect_uri?: string;
  client_id: string;
  client_secret?: string;
}

export interface RevokeTokenBody {
  token: string;
  token_type_hint?: 'access_token' | 'refresh_token';
}

// Error types
export interface AppError extends Error {
  statusCode?: number;
  isOperational?: boolean;
}

// Database model extensions
export interface UserWithoutPassword extends Omit<User, 'password'> {}

export interface AccessTokenWithRelations extends AccessToken {
  user: UserWithoutPassword;
  client: Client;
}

export interface RefreshTokenWithRelations extends RefreshToken {
  user: UserWithoutPassword;
  client: Client;
}

export interface AuthorizationCodeWithRelations extends AuthorizationCode {
  user: UserWithoutPassword;
  client: Client;
}

export { User, Client, AccessToken, RefreshToken, AuthorizationCode };