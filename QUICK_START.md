# OAuth2 TypeScript Backend

## Quick Start Guide

### 1. Clone & Install
```bash
git clone https://github.com/JhonHurtado/oauth2-backend-typescript.git
cd oauth2-backend-typescript
npm install
```

### 2. Environment Setup
```bash
cp .env.example .env
# Edit .env with your MongoDB connection and secrets
```

### 3. Database Setup
```bash
npm run db:generate
npm run db:push
npm run db:seed
```

### 4. Run Development Server
```bash
npm run dev
# Server will start on http://localhost:3000
```

## Test the API

### Register a new user:
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "testuser2",
    "password": "Password123",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

### Login:
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "login": "user@example.com",
    "password": "Password123"
  }' \
  -c cookies.txt
```

### Check authentication:
```bash
curl -X GET http://localhost:3000/api/auth/me \
  -b cookies.txt
```

### OAuth2 Authorization Flow:
1. Visit in browser:
   ```
   http://localhost:3000/api/oauth2/authorize?response_type=code&client_id=test-client-id&redirect_uri=http://localhost:3001/auth/callback&scope=read&state=test123
   ```

2. Exchange code for token:
   ```bash
   curl -X POST http://localhost:3000/api/oauth2/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "Authorization: Basic $(echo -n 'test-client-id:test-client-secret' | base64)" \
     -d "grant_type=authorization_code&code=YOUR_CODE&redirect_uri=http://localhost:3001/auth/callback"
   ```

3. Use token to access protected resources:
   ```bash
   curl -X GET http://localhost:3000/api/user/me \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
   ```

## License
MIT