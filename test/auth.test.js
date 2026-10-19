const assert = require('assert');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { db } = require('../src/db/database');
const { seedDatabase } = require('../src/db/seed');
const { JWT_SECRET } = require('../src/config/env');
const { generateToken, authenticateToken } = require('../src/middleware/authenticate');
const passport = require('../src/config/passport');
const authRouter = require('../src/routes/auth');

console.log('--- Running Authentication & Token Layer Tests (Task 2) ---');

// Helper to start an ephemeral Express test server
async function startTestServer() {
  const app = express();
  app.use(express.json());
  app.use(passport.initialize());
  app.use('/api/auth', authRouter);
  app.use('/auth', authRouter);

  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const baseUrl = `http://127.0.0.1:${port}`;
      resolve({
        server,
        baseUrl,
        close: () => new Promise((res) => server.close(res))
      });
    });
  });
}

// Helper mock req/res for middleware unit testing
function createMockReqRes(headers = {}) {
  const req = { headers, user: null };
  let statusCode = 200;
  let jsonBody = null;
  const res = {
    status(code) {
      statusCode = code;
      return this;
    },
    json(data) {
      jsonBody = data;
      return this;
    }
  };
  return {
    req,
    res,
    getStatusCode: () => statusCode,
    getJsonBody: () => jsonBody
  };
}

async function runTests() {
  // Re-seed DB to a known baseline
  seedDatabase();

  let testCount = 0;

  // ============================================================
  // Test 1: Unit Test - generateToken produces valid signed JWT
  // ============================================================
  {
    testCount++;
    const dummyUser = {
      id: 99,
      username: 'tester',
      email: 'tester@example.com',
      role: 'customer',
      tier: 'vip',
      is_verified: 1
    };

    const token = generateToken(dummyUser);
    assert(typeof token === 'string' && token.length > 20, 'generateToken must return a JWT string');

    const decoded = jwt.verify(token, JWT_SECRET);
    assert.strictEqual(decoded.id, 99, 'Token payload must include id');
    assert.strictEqual(decoded.username, 'tester', 'Token payload must include username');
    assert.strictEqual(decoded.email, 'tester@example.com', 'Token payload must include email');
    assert.strictEqual(decoded.role, 'customer', 'Token payload must include role');
    assert.strictEqual(decoded.tier, 'vip', 'Token payload must include tier');
    assert.strictEqual(decoded.is_verified, true, 'is_verified 1 must resolve to boolean true in payload');
    assert(decoded.exp, 'Token must contain exp claim');

    console.log(`✓ Test ${testCount} Passed: generateToken creates signed JWT with required payload claims`);
  }

  // ============================================================
  // Test 2: Unit Test - authenticateToken middleware
  // ============================================================
  {
    testCount++;
    // Case 2a: Missing Authorization header -> 401
    {
      const { req, res, getStatusCode, getJsonBody } = createMockReqRes();
      let nextCalled = false;
      authenticateToken(req, res, () => { nextCalled = true; });
      assert.strictEqual(getStatusCode(), 401, 'Missing token must return 401');
      assert.strictEqual(getJsonBody().error, 'Unauthorized: Access token is missing');
      assert.strictEqual(nextCalled, false, 'next() must NOT be called on missing token');
    }

    // Case 2b: Invalid token -> 403
    {
      const { req, res, getStatusCode, getJsonBody } = createMockReqRes({ authorization: 'Bearer invalid.garbage.token' });
      let nextCalled = false;
      authenticateToken(req, res, () => { nextCalled = true; });
      assert.strictEqual(getStatusCode(), 403, 'Invalid token must return 403');
      assert.strictEqual(getJsonBody().error, 'Forbidden: Invalid or expired access token');
      assert.strictEqual(nextCalled, false, 'next() must NOT be called on invalid token');
    }

    // Case 2c: Expired token -> 403
    {
      const expiredToken = jwt.sign(
        { id: 1, username: 'old', role: 'customer' },
        JWT_SECRET,
        { expiresIn: '-1s' }
      );
      const { req, res, getStatusCode, getJsonBody } = createMockReqRes({ authorization: `Bearer ${expiredToken}` });
      let nextCalled = false;
      authenticateToken(req, res, () => { nextCalled = true; });
      assert.strictEqual(getStatusCode(), 403, 'Expired token must return 403');
      assert.strictEqual(getJsonBody().error, 'Forbidden: Invalid or expired access token');
      assert.strictEqual(nextCalled, false, 'next() must NOT be called on expired token');
    }

    // Case 2d: Valid token -> calls next() and attaches req.user
    {
      const validToken = generateToken({
        id: 42,
        username: 'alice',
        email: 'alice@test.local',
        role: 'seller',
        tier: 'regular',
        is_verified: 1
      });
      const { req, res, getStatusCode } = createMockReqRes({ authorization: `Bearer ${validToken}` });
      let nextCalled = false;
      authenticateToken(req, res, () => { nextCalled = true; });
      assert.strictEqual(nextCalled, true, 'next() must be called on valid token');
      assert(req.user, 'req.user must be set on valid token');
      assert.strictEqual(req.user.username, 'alice');
      assert.strictEqual(req.user.role, 'seller');
    }

    console.log(`✓ Test ${testCount} Passed: authenticateToken middleware enforces 401, 403, and injects req.user`);
  }

  // Launch test server for HTTP route tests
  const testEnv = await startTestServer();

  try {
    // ============================================================
    // Test 3: HTTP - User Registration with password hashing
    // ============================================================
    {
      testCount++;
      const regRes = await fetch(`${testEnv.baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'brand_new_user',
          email: 'newuser@store.local',
          password: 'securePassword123!',
          role: 'customer',
          tier: 'regular'
        })
      });

      assert.strictEqual(regRes.status, 201, `Registration should return 201, got ${regRes.status}`);
      const regData = await regRes.json();
      assert(regData.token, 'Registration must return a token');
      assert.strictEqual(regData.user.username, 'brand_new_user');
      assert.strictEqual(regData.user.email, 'newuser@store.local');
      assert.strictEqual(regData.user.role, 'customer');

      // Verify DB persistence and password hashing
      const savedUser = db.prepare('SELECT * FROM users WHERE username = ?').get('brand_new_user');
      assert(savedUser, 'User must exist in database');
      assert.notStrictEqual(savedUser.password_hash, 'securePassword123!', 'Password must NOT be plain text');
      assert(bcrypt.compareSync('securePassword123!', savedUser.password_hash), 'Password hash must be valid bcrypt');

      // Reject duplicate registration
      const dupRes = await fetch(`${testEnv.baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'brand_new_user',
          email: 'newuser@store.local',
          password: 'anotherPassword'
        })
      });
      assert(dupRes.status === 400 || dupRes.status === 409, `Duplicate registration must be rejected with 400/409, got ${dupRes.status}`);

      console.log(`✓ Test ${testCount} Passed: Registration hashes password and persists user with token`);
    }

    // ============================================================
    // Test 4: HTTP - Valid Login returning JWT with expected payload claims
    // ============================================================
    {
      testCount++;
      // Test seeded customer_vip
      const loginRes = await fetch(`${testEnv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'customer_vip',
          password: 'user123'
        })
      });

      assert.strictEqual(loginRes.status, 200, `Login should return 200, got ${loginRes.status}`);
      const loginData = await loginRes.json();
      assert(loginData.token, 'Login response must include token');
      assert.strictEqual(loginData.message, 'Login successful');
      assert.strictEqual(loginData.user.username, 'customer_vip');
      assert.strictEqual(loginData.user.role, 'customer');
      assert.strictEqual(loginData.user.tier, 'vip');

      // Verify token payload claims
      const decoded = jwt.verify(loginData.token, JWT_SECRET);
      assert.strictEqual(decoded.username, 'customer_vip');
      assert.strictEqual(decoded.role, 'customer');
      assert.strictEqual(decoded.tier, 'vip');
      assert.strictEqual(decoded.is_verified, true);

      // Also test login by email
      const emailLoginRes = await fetch(`${testEnv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'admin@ecommerce.local',
          password: 'admin123'
        })
      });
      assert.strictEqual(emailLoginRes.status, 200, 'Login by email should succeed');
      const emailLoginData = await emailLoginRes.json();
      assert.strictEqual(emailLoginData.user.role, 'admin');

      console.log(`✓ Test ${testCount} Passed: Login returns JWT containing role, tier, and verified claims`);
    }

    // ============================================================
    // Test 5: HTTP - Rejection of invalid credentials (401)
    // ============================================================
    {
      testCount++;
      // Wrong password
      const wrongPwdRes = await fetch(`${testEnv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'customer_vip',
          password: 'wrongPassword'
        })
      });
      assert.strictEqual(wrongPwdRes.status, 401, 'Wrong password must return 401');

      // Non-existent user
      const nonExistentRes = await fetch(`${testEnv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'nobody_here',
          password: 'password123'
        })
      });
      assert.strictEqual(nonExistentRes.status, 401, 'Non-existent user must return 401');

      // Missing fields -> 400
      const missingFieldRes = await fetch(`${testEnv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'customer_vip'
        })
      });
      assert.strictEqual(missingFieldRes.status, 400, 'Missing password must return 400');

      console.log(`✓ Test ${testCount} Passed: Invalid credentials rejected with 401 / missing fields with 400`);
    }

    // ============================================================
    // Test 6: HTTP - Protected endpoint GET /api/auth/me
    // ============================================================
    {
      testCount++;
      // 6a: Access without token -> 401
      const noTokenRes = await fetch(`${testEnv.baseUrl}/api/auth/me`);
      assert.strictEqual(noTokenRes.status, 401, 'Unauthenticated /me must return 401');

      // 6b: Access with invalid token -> 403
      const badTokenRes = await fetch(`${testEnv.baseUrl}/api/auth/me`, {
        headers: { 'Authorization': 'Bearer bad.token.here' }
      });
      assert.strictEqual(badTokenRes.status, 403, 'Invalid token on /me must return 403');

      // 6c: Access with valid token -> 200 with req.user
      const loginRes = await fetch(`${testEnv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'customer_regular', password: 'user123' })
      });
      const { token } = await loginRes.json();

      const meRes = await fetch(`${testEnv.baseUrl}/api/auth/me`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      assert.strictEqual(meRes.status, 200, 'Valid token on /me must return 200');
      const meData = await meRes.json();
      assert(meData.user, '/me response must contain user');
      assert.strictEqual(meData.user.username, 'customer_regular');
      assert.strictEqual(meData.user.role, 'customer');
      assert.strictEqual(meData.user.tier, 'regular');

      console.log(`✓ Test ${testCount} Passed: /api/auth/me validates Bearer token and returns profile`);
    }

    // ============================================================
    // Test 7: HTTP - Mock Google OAuth Login creates customer and returns token
    // ============================================================
    {
      testCount++;
      const mockRes = await fetch(`${testEnv.baseUrl}/api/auth/mock-google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'oauth.tester@gmail.com',
          name: 'OAuth Tester',
          tier: 'regular'
        })
      });

      assert.strictEqual(mockRes.status, 200, `Mock Google login must return 200, got ${mockRes.status}`);
      const mockData = await mockRes.json();
      assert(mockData.token, 'Mock Google login must return JWT token');
      assert.strictEqual(mockData.message, 'Mock Google Login successful');
      assert.strictEqual(mockData.user.email, 'oauth.tester@gmail.com');
      assert.strictEqual(mockData.user.role, 'customer');

      // Verify database record
      const dbUser = db.prepare('SELECT * FROM users WHERE email = ?').get('oauth.tester@gmail.com');
      assert(dbUser, 'Mock OAuth user must be saved in database');
      assert(dbUser.google_id, 'google_id must be populated');
      assert.strictEqual(dbUser.role, 'customer');
      assert.strictEqual(dbUser.is_verified, 1);
      assert.strictEqual(dbUser.password_hash, null, 'OAuth user password_hash should be null');

      // Subsequent login with same email should return existing user, not error or duplicate
      const secondLoginRes = await fetch(`${testEnv.baseUrl}/api/auth/mock-google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'oauth.tester@gmail.com',
          name: 'OAuth Tester'
        })
      });
      assert.strictEqual(secondLoginRes.status, 200);
      const secondData = await secondLoginRes.json();
      assert.strictEqual(secondData.user.id, dbUser.id, 'Subsequent mock login returns existing record');

      console.log(`✓ Test ${testCount} Passed: Mock Google OAuth provisions customer user and issues valid token`);
    }

    // ============================================================
    // Test 8: Passport Google Strategy Configuration Check
    // ============================================================
    {
      testCount++;
      // Verify passport has google strategy configured
      const strategy = passport._strategy('google');
      assert(strategy, 'Passport must have strategy named "google" registered');

      console.log(`✓ Test ${testCount} Passed: Passport GoogleStrategy configured and registered`);
    }

    console.log('\n========================================');
    console.log(`ALL AUTHENTICATION TESTS PASSED (${testCount}/${testCount} tests)`);
    console.log('========================================\n');
  } finally {
    await testEnv.close();
  }
}

runTests().catch((err) => {
  console.error('\n❌ Test execution failed:', err);
  process.exit(1);
});
