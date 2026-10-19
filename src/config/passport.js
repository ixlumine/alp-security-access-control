const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, CALLBACK_URL } = require('./env');
const { db } = require('../db/database');

passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: CALLBACK_URL,
      scope: ['profile', 'email']
    },
    (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        const googleId = profile.id;

        // Search users table by google_id or email
        let user = null;
        if (googleId) {
          user = db.prepare('SELECT * FROM users WHERE google_id = ?').get(googleId);
        }

        if (!user && email) {
          user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
          if (user && !user.google_id) {
            db.prepare('UPDATE users SET google_id = ? WHERE id = ?').run(googleId, user.id);
            user.google_id = googleId;
          }
        }

        // If not found, insert a new user
        if (!user) {
          const rawUsername = profile.displayName || (email ? email.split('@')[0] : 'google_user');
          let baseUsername = rawUsername.toLowerCase().replace(/[^a-z0-9_]/g, '_');
          if (!baseUsername) baseUsername = 'google_user';

          let username = baseUsername;
          let counter = 1;
          while (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
            username = `${baseUsername}_${counter++}`;
          }

          const userEmail = email || `${googleId}@google.user`;
          const insertStmt = db.prepare(`
            INSERT INTO users (username, email, password_hash, role, tier, is_verified, google_id)
            VALUES (?, ?, NULL, 'customer', 'regular', 1, ?)
          `);

          const result = insertStmt.run(username, userEmail, googleId);
          user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
        }

        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

module.exports = passport;
