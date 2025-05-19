import oauth2orize from 'oauth2orize';
import { v4 as uuidv4 } from 'uuid';
import prisma from './database';
import { User, Client } from '@prisma/client';

// Create OAuth2 server
const server = oauth2orize.createServer();

// Generate authorization code
server.grant(oauth2orize.grant.code(async (client: Client, redirectUri: string, user: User, ares: any, done: Function) => {
  try {
    const code = uuidv4();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    
    await prisma.authorizationCode.create({
      data: {
        code,
        clientId: client.clientId,
        userId: user.id,
        redirectUri,
        scope: ares.scope || [],
        expiresAt,
      },
    });
    
    done(null, code);
  } catch (error) {
    done(error);
  }
}));

// Exchange authorization code for access token
server.exchange(oauth2orize.exchange.code(async (client: Client, code: string, redirectUri: string, done: Function) => {
  try {
    const authCode = await prisma.authorizationCode.findUnique({
      where: { code },
      include: { user: true },
    });
    
    if (!authCode || authCode.clientId !== client.clientId || authCode.redirectUri !== redirectUri) {
      return done(null, false);
    }
    
    if (authCode.expiresAt < new Date()) {
      return done(null, false);
    }
    
    // Delete the authorization code (one-time use)
    await prisma.authorizationCode.delete({
      where: { id: authCode.id },
    });
    
    // Generate access token
    const accessToken = uuidv4();
    const refreshToken = uuidv4();
    const accessTokenExpiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    const refreshTokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    
    // Save tokens
    await prisma.accessToken.create({
      data: {
        token: accessToken,
        clientId: client.clientId,
        userId: authCode.userId,
        scope: authCode.scope,
        expiresAt: accessTokenExpiresAt,
      },
    });
    
    await prisma.refreshToken.create({
      data: {
        token: refreshToken,
        clientId: client.clientId,
        userId: authCode.userId,
        scope: authCode.scope,
        expiresAt: refreshTokenExpiresAt,
      },
    });
    
    done(null, accessToken, refreshToken, {
      expires_in: 3600,
      token_type: 'Bearer',
    });
  } catch (error) {
    done(error);
  }
}));

// Exchange refresh token for new access token
server.exchange(oauth2orize.exchange.refreshToken(async (client: Client, refreshToken: string, scope: string[], done: Function) => {
  try {
    const storedRefreshToken = await prisma.refreshToken.findUnique({
      where: { token: refreshToken },
      include: { user: true },
    });
    
    if (!storedRefreshToken || storedRefreshToken.clientId !== client.clientId) {
      return done(null, false);
    }
    
    if (storedRefreshToken.expiresAt < new Date()) {
      return done(null, false);
    }
    
    // Generate new access token
    const newAccessToken = uuidv4();
    const accessTokenExpiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    
    // Save new access token
    await prisma.accessToken.create({
      data: {
        token: newAccessToken,
        clientId: client.clientId,
        userId: storedRefreshToken.userId,
        scope: scope || storedRefreshToken.scope,
        expiresAt: accessTokenExpiresAt,
      },
    });
    
    done(null, newAccessToken, null, {
      expires_in: 3600,
      token_type: 'Bearer',
    });
  } catch (error) {
    done(error);
  }
}));

// User authorization endpoint
server.serializeClient((client: Client, done: Function) => {
  return done(null, client.clientId);
});

server.deserializeClient(async (clientId: string, done: Function) => {
  try {
    const client = await prisma.client.findUnique({
      where: { clientId },
    });
    return done(null, client);
  } catch (error) {
    return done(error);
  }
});

export default server;