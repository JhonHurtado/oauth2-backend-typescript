import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { BasicStrategy } from 'passport-http';
import { Strategy as BearerStrategy } from 'passport-http-bearer';
import { Strategy as ClientPasswordStrategy } from 'passport-oauth2-client-password';
import bcrypt from 'bcryptjs';
import { Application } from 'express';
import prisma from './database';
import { User, Client } from '@prisma/client';

// User serialization
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await prisma.user.findUnique({
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
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// Local Strategy for username/password authentication
passport.use('local', new LocalStrategy(
  {
    usernameField: 'login', // Can be email or username
    passwordField: 'password',
  },
  async (login: string, password: string, done) => {
    try {
      // Find user by email or username
      const user = await prisma.user.findFirst({
        where: {
          OR: [
            { email: login },
            { username: login },
          ],
          isActive: true,
        },
      });

      if (!user) {
        return done(null, false, { message: 'Invalid credentials' });
      }

      // Check password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return done(null, false, { message: 'Invalid credentials' });
      }

      // Remove password from user object
      const { password: _, ...userWithoutPassword } = user;
      return done(null, userWithoutPassword);
    } catch (error) {
      return done(error);
    }
  }
));

// Bearer token strategy for API authentication
passport.use('bearer', new BearerStrategy(
  async (token: string, done) => {
    try {
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
        },
      });

      if (!accessToken || accessToken.expiresAt < new Date()) {
        return done(null, false);
      }

      if (!accessToken.user.isActive) {
        return done(null, false);
      }

      return done(null, accessToken.user);
    } catch (error) {
      return done(error);
    }
  }
));

// Basic strategy for client authentication
passport.use('basic', new BasicStrategy(
  async (clientId: string, clientSecret: string, done) => {
    try {
      const client = await prisma.client.findUnique({
        where: { clientId },
      });

      if (!client || client.clientSecret !== clientSecret || !client.isActive) {
        return done(null, false);
      }

      return done(null, client);
    } catch (error) {
      return done(error);
    }
  }
));

// Client password strategy for OAuth2
passport.use('oauth2-client-password', new ClientPasswordStrategy(
  async (clientId: string, clientSecret: string, done) => {
    try {
      const client = await prisma.client.findUnique({
        where: { clientId },
      });

      if (!client || client.clientSecret !== clientSecret || !client.isActive) {
        return done(null, false);
      }

      return done(null, client);
    } catch (error) {
      return done(error);
    }
  }
));

export function initializePassport(app: Application): void {
  app.use(passport.initialize());
  app.use(passport.session());
}

export default passport;