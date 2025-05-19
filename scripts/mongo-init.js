// MongoDB initialization script
db = db.getSiblingDB('oauth2_db');

// Create a user for the application
db.createUser({
  user: 'oauth2_user',
  pwd: 'oauth2_password',
  roles: [
    {
      role: 'readWrite',
      db: 'oauth2_db'
    }
  ]
});

console.log('MongoDB initialized successfully with oauth2_db database and oauth2_user user.');