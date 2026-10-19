# E-Commerce Authorization & Security Platform (ALP Cyber Security)

A complete, self-contained single-application demonstration of advanced authentication and authorization concepts for Cyber Security:
1. **Access Token**: JWT Authentication & Google OAuth 2.0
2. **Role-Based Access Control (RBAC)**: Multi-role hierarchy (`admin`, `seller`, `customer`)
3. **Attribute-Based Access Control (ABAC)**: Subject attributes (`tier`, `is_verified`, `id`) and object attributes (`is_vip_exclusive`, `seller_id`, `customer_id`, `status`)
4. **Combined RBAC + ABAC**: Compound decisions (product deletion constraints and multi-tier refund approvals)
5. **Interactive Web Dashboard**: Single-Page Application (SPA) with one-click user switching and real-time HTTP response console.

---

## Quick Start

### 1. Installation
Open terminal in the `ecommerce-app` directory:
```bash
cd ecommerce-app
npm install
```

### 2. Run Database Seeder
Reset or initialize the SQLite database with default demo accounts, products, and orders:
```bash
npm run seed
```

### 3. Run Automated Tests
Execute the complete test suite (6 test suites covering 60 automated test cases):
```bash
npm test
```

### 4. Start the Application Server
```bash
npm start
```
The server will start on port 4000.
Open your browser and visit: **[http://localhost:4000](http://localhost:4000)**

---

## Pre-seeded Demo Accounts

| Username | Password | Role | Tier | Verified | Context / Usage |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `admin` | `admin123` | `admin` | `regular` | `1` | Global marketplace manager (all rights) |
| `seller_tech` | `seller123` | `seller` | `regular` | `1` | Tech store merchant (owns Product 1 & 2) |
| `seller_fashion` | `seller123` | `seller` | `regular` | `0` | Fashion merchant (owns Product 3 & 4) |
| `customer_vip` | `user123` | `customer` | `vip` | `1` | Premium buyer (can view VIP flash deals) |
| `customer_regular`| `user123` | `customer` | `regular` | `1` | Standard buyer |
| `Google User` | *OAuth* | `customer` | `regular` | `1` | Google OAuth 2.0 authenticated account |

---

## Authorization Scenarios Covered

### #1 Access Token (JWT & OAuth 2.0)
- **JWT**: Issues signed tokens (`HS256`, 2-hour expiry) upon login via `POST /api/auth/login`. Token claims carry `{ id, username, email, role, tier, is_verified }`.
- **OAuth 2.0**: Integrated via `passport-google-oauth20` (`GET /auth/google` and `GET /auth/google/callback`).
- **Mock Google OAuth**: Endpoint `POST /api/auth/mock-google` provides instant OAuth token generation for testing in environments without Google Cloud credentials.
- **Middleware**: `authenticateToken` validates `Authorization: Bearer <token>` and injects `req.user`.

### #2 Role-Based Access Control (RBAC)
- 3 Roles defined: `admin`, `seller`, `customer`.
- Policy matrix in `src/policies/rbac.js`.
- Endpoints:
  - `GET /api/admin/metrics`: Only `admin` allowed (200 OK). `seller` & `customer` rejected (403 Forbidden).
  - `GET /api/admin/users`: Only `admin` allowed (200 OK).
  - `POST /api/products`: Only `admin` and `seller` allowed.

### #3 Attribute-Based Access Control (ABAC)
- **VIP Catalog Access**: `GET /api/products/vip-deals` checks `user.tier === 'vip'`. Regular customers receive `403 Forbidden`, while VIP customers receive `200 OK`.
- **Order History Visibility**: `GET /api/orders/:id` requires `order.customer_id === user.id` (or `order.seller_id === user.id` or `user.role === 'admin'`). Customers viewing another customer's order receive `403 Forbidden`.
- **Order Cancellation**: `POST /api/orders/:id/cancel` allowed only if `order.customer_id === user.id` AND `order.status === 'pending'`. Once an order is `'shipped'`, cancellation is rejected with `403 Forbidden`.

### #4 Combined RBAC + ABAC
- **Product Deletion (`DELETE /api/products/:id`)**:
  - `admin`: Allowed globally (RBAC override).
  - `seller`: Allowed ONLY IF `product.seller_id === user.id` (ABAC: Ownership) AND active orders count is 0 (ABAC: Integrity constraint).
  - `customer`: Forbidden (RBAC rejection).
- **Refund Approval (`POST /api/orders/:id/approve-refund`)**:
  - `admin`: Allowed globally for any amount.
  - `seller`: Allowed ONLY IF `order.seller_id === user.id` (ABAC: Store ownership) AND `order.amount <= 500000` (ABAC: Maximum ceiling) AND status is `'refund_requested'`. Amounts above Rp 500.000 require Admin approval.
  - `customer`: Forbidden.

---

## Interactive Dashboard Features (`public/index.html`)

1. **One-Click Quick Switcher**: Instantly log in as any of the 5 pre-seeded personas or Google OAuth user with a single click.
2. **Access Token Inspector**: Live display and copy of raw JWT and decoded payload claims.
3. **Interactive Testing Matrices**: Dedicated test buttons for RBAC, ABAC, and Combined controls with instant pass/fail badges.
4. **Live HTTP Console Log**: Displays outgoing requests, authorization headers, response HTTP status codes (`200 OK` vs `403 Forbidden`), and the JSON explanation string.
