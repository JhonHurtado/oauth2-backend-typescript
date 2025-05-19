# OAuth2 Backend with TypeScript

Un backend completo de autenticación OAuth2 construido con Node.js, TypeScript, oauth2orize, Prisma y MongoDB.

## 🚀 Características

- ✅ Autenticación OAuth2 con flujo de código de autorización
- ✅ Registro y login de usuarios (email/username + contraseña)
- ✅ Gestión de sesiones y tokens
- ✅ Base de datos MongoDB con Prisma ORM
- ✅ TypeScript para mayor seguridad de tipos
- ✅ Middleware de seguridad (helmet, cors, rate limiting)
- ✅ Validación de datos con express-validator
- ✅ Manejo centralizado de errores

## 📋 Requisitos

- Node.js >= 16.0.0
- MongoDB (local o en la nube)
- npm o yarn

## 🛠️ Instalación

1. **Clonar el repositorio**
   ```bash
   git clone https://github.com/JhonHurtado/oauth2-backend-typescript.git
   cd oauth2-backend-typescript
   ```

2. **Instalar dependencias**
   ```bash
   npm install
   ```

3. **Configurar variables de entorno**
   ```bash
   cp .env.example .env
   ```
   
   Edita el archivo `.env` con tus configuraciones:
   ```env
   DATABASE_URL="mongodb://localhost:27017/oauth2_db"
   PORT=3000
   NODE_ENV=development
   JWT_SECRET=your-super-secret-jwt-key-here
   SESSION_SECRET=your-session-secret-here
   CLIENT_ID=test-client-id
   CLIENT_SECRET=test-client-secret
   CLIENT_REDIRECT_URI=http://localhost:3001/auth/callback
   CORS_ORIGIN=http://localhost:3001
   ```

4. **Configurar la base de datos**
   ```bash
   # Generar el cliente Prisma
   npm run db:generate
   
   # Sincronizar el esquema con la base de datos
   npm run db:push
   
   # Poblar la base de datos con datos de prueba
   npm run db:seed
   ```

5. **Compilar TypeScript**
   ```bash
   npm run build
   ```

6. **Iniciar el servidor**
   ```bash
   # Desarrollo
   npm run dev
   
   # Producción
   npm start
   ```

## 📚 API Endpoints

### Authentication Routes (`/api/auth`)

#### Registro de usuario
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "testuser",
  "password": "Password123",
  "firstName": "John",
  "lastName": "Doe"
}
```

#### Login de usuario
```http
POST /api/auth/login
Content-Type: application/json

{
  "login": "user@example.com", // email o username
  "password": "Password123"
}
```

#### Logout
```http
POST /api/auth/logout
```

#### Verificar autenticación
```http
GET /api/auth/me
```

### OAuth2 Routes (`/api/oauth2`)

#### Autorización (Paso 1)
```http
GET /api/oauth2/authorize?response_type=code&client_id=test-client-id&redirect_uri=http://localhost:3001/auth/callback&scope=read&state=random-state
```

#### Intercambio de código por token (Paso 2)
```http
POST /api/oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=http://localhost:3001/auth/callback
```

#### Información del token
```http
GET /api/oauth2/tokeninfo
Authorization: Bearer ACCESS_TOKEN
```

#### Revocar token
```http
POST /api/oauth2/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=ACCESS_TOKEN&token_type_hint=access_token
```

### User Routes (`/api/user`)

#### Obtener perfil (sesión)
```http
GET /api/user/profile
Cookie: connect.sid=SESSION_ID
```

#### Obtener perfil (OAuth2)
```http
GET /api/user/me
Authorization: Bearer ACCESS_TOKEN
```

#### Actualizar perfil
```http
PUT /api/user/profile
Cookie: connect.sid=SESSION_ID
Content-Type: application/json

{
  "firstName": "John Updated",
  "lastName": "Doe Updated"
}
```

#### Obtener sesiones activas
```http
GET /api/user/sessions
Authorization: Bearer ACCESS_TOKEN
```

#### Revocar todas las sesiones
```http
DELETE /api/user/sessions
Authorization: Bearer ACCESS_TOKEN
```

### Health Check

```http
GET /api/health
```

## 🔄 Flujo OAuth2

1. **Autorización**: El cliente redirige al usuario a `/api/oauth2/authorize`
2. **Login**: Si no está autenticado, el usuario se loguea
3. **Consentimiento**: El usuario autoriza al cliente (auto-aprobado en este ejemplo)
4. **Código**: El servidor redirige al cliente con un código de autorización
5. **Token**: El cliente intercambia el código por un access token en `/api/oauth2/token`
6. **Acceso**: El cliente usa el access token para acceder a recursos protegidos

## 🗂️ Estructura del Proyecto

```
src/
├── config/
│   ├── database.ts      # Configuración de Prisma
│   ├── oauth2.ts        # Configuración del servidor OAuth2
│   └── passport.ts      # Estrategias de autenticación
├── middleware/
│   ├── auth.ts          # Middleware de autenticación
│   ├── errorHandler.ts  # Manejo de errores
│   ├── notFoundHandler.ts
│   └── validation.ts    # Validación de datos
├── routes/
│   ├── auth.ts          # Rutas de autenticación
│   ├── oauth2.ts        # Rutas OAuth2
│   └── user.ts          # Rutas de usuario
└── index.ts             # Punto de entrada
```

## 🛡️ Seguridad

- Contraseñas hasheadas con bcrypt
- Rate limiting para prevenir ataques de fuerza bruta
- Headers de seguridad con Helmet
- Validación de datos de entrada
- Tokens con expiración automática
- CORS configurado
- Sesiones seguras

## 🔧 Scripts Disponibles

```bash
npm run dev          # Modo desarrollo con recarga automática
npm run build        # Compilar TypeScript
npm start            # Ejecutar versión de producción
npm run db:generate  # Generar cliente Prisma
npm run db:push      # Sincronizar esquema con BD
npm run db:seed      # Poblar BD con datos de prueba
npm run lint         # Ejecutar ESLint
npm run lint:fix     # Corregir errores de ESLint automáticamente
```

## 🧪 Datos de Prueba

Después de ejecutar `npm run db:seed`, tendrás disponible:

**Usuario de prueba:**
- Email: `test@example.com`
- Username: `testuser`
- Password: `password123`

**Cliente OAuth2:**
- Client ID: `test-client-id`
- Client Secret: `test-client-secret`
- Redirect URI: `http://localhost:3001/auth/callback`

## 📄 Variables de Entorno

| Variable | Descripción | Ejemplo |
|----------|-------------|---------|
| `DATABASE_URL` | URL de conexión a MongoDB | `mongodb://localhost:27017/oauth2_db` |
| `PORT` | Puerto del servidor | `3000` |
| `NODE_ENV` | Entorno de ejecución | `development` |
| `JWT_SECRET` | Secreto para JWT | `your-jwt-secret` |
| `SESSION_SECRET` | Secreto para sesiones | `your-session-secret` |
| `CLIENT_ID` | ID del cliente OAuth2 | `test-client-id` |
| `CLIENT_SECRET` | Secreto del cliente OAuth2 | `test-client-secret` |
| `CLIENT_REDIRECT_URI` | URI de redirección | `http://localhost:3001/auth/callback` |
| `CORS_ORIGIN` | Origen permitido para CORS | `http://localhost:3001` |

## 🚀 Ejemplo de Integración con Frontend

```javascript
// Ejemplo en React/JavaScript
const CLIENT_ID = 'test-client-id';
const REDIRECT_URI = 'http://localhost:3001/auth/callback';
const OAUTH_URL = 'http://localhost:3000/api/oauth2/authorize';

// 1. Redirigir para autorización
const handleLogin = () => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'read',
    state: Math.random().toString(36)
  });
  
  window.location.href = `${OAUTH_URL}?${params}`;
};

// 2. Manejar callback con código
const handleCallback = async (code) => {
  const response = await fetch('http://localhost:3000/api/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${btoa(`${CLIENT_ID}:test-client-secret`)}`
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: REDIRECT_URI
    })
  });
  
  const data = await response.json();
  const accessToken = data.access_token;
  
  // Guardar token y usar para hacer requests
  localStorage.setItem('access_token', accessToken);
};

// 3. Hacer requests autenticados
const fetchUserProfile = async () => {
  const token = localStorage.getItem('access_token');
  const response = await fetch('http://localhost:3000/api/user/me', {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  return response.json();
};
```

## 📦 Tecnologías Utilizadas

- **Backend**: Node.js, Express.js, TypeScript
- **Autenticación**: oauth2orize, Passport.js
- **Base de datos**: MongoDB, Prisma ORM
- **Seguridad**: bcryptjs, helmet, cors, express-rate-limit
- **Validación**: express-validator
- **Sesiones**: express-session, connect-mongo

## 🤝 Contribuir

1. Fork del proyecto
2. Crear una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abrir un Pull Request

## 📝 Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## ⚠️ Nota Importante

Este es un proyecto de demostración. Para uso en producción, asegúrate de:

- Cambiar todos los secretos por valores seguros
- Configurar HTTPS
- Implementar logging apropiado
- Configurar monitoring y alertas
- Revisar y ajustar las configuraciones de seguridad
- Implementar backup de la base de datos
- Configurar variables de entorno de producción

## 📞 Soporte

Si tienes preguntas o problemas, por favor abre un issue en el repositorio de GitHub.