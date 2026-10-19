const bcrypt = require('bcryptjs');
const { db, initSchema } = require('./database');

function seedDatabase(targetDb = db) {
  initSchema(targetDb);

  const seed = targetDb.transaction(() => {
    // Clean existing data
    targetDb.prepare('DELETE FROM orders').run();
    targetDb.prepare('DELETE FROM products').run();
    targetDb.prepare('DELETE FROM users').run();

    // Reset auto-increment counters if sqlite_sequence table exists
    try {
      targetDb.prepare("DELETE FROM sqlite_sequence WHERE name IN ('users', 'products', 'orders')").run();
    } catch (e) {
      // sqlite_sequence might not exist if autoincrement has not been used yet
    }

    // 1. Seed Users
    const insertUser = targetDb.prepare(`
      INSERT INTO users (username, email, password_hash, role, tier, is_verified, google_id)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    const usersData = [
      {
        username: 'admin',
        email: 'admin@ecommerce.local',
        password: 'admin123',
        role: 'admin',
        tier: 'regular',
        is_verified: 1,
        google_id: null
      },
      {
        username: 'seller_tech',
        email: 'tech@store.local',
        password: 'seller123',
        role: 'seller',
        tier: 'regular',
        is_verified: 1,
        google_id: null
      },
      {
        username: 'seller_fashion',
        email: 'fashion@store.local',
        password: 'seller123',
        role: 'seller',
        tier: 'regular',
        is_verified: 0,
        google_id: null
      },
      {
        username: 'customer_vip',
        email: 'vip@customer.local',
        password: 'user123',
        role: 'customer',
        tier: 'vip',
        is_verified: 1,
        google_id: null
      },
      {
        username: 'customer_regular',
        email: 'regular@customer.local',
        password: 'user123',
        role: 'customer',
        tier: 'regular',
        is_verified: 1,
        google_id: null
      }
    ];

    const userMap = {};
    for (const u of usersData) {
      const hash = bcrypt.hashSync(u.password, 10);
      const res = insertUser.run(u.username, u.email, hash, u.role, u.tier, u.is_verified, u.google_id);
      userMap[u.username] = { id: res.lastInsertRowid, ...u };
    }

    // 2. Seed Products
    const insertProduct = targetDb.prepare(`
      INSERT INTO products (name, price, seller_id, category, is_vip_exclusive)
      VALUES (?, ?, ?, ?, ?)
    `);

    const productsData = [
      {
        name: 'Flagship Smartphone',
        price: 12000000,
        seller_id: userMap['seller_tech'].id,
        category: 'Electronics',
        is_vip_exclusive: 0
      },
      {
        name: 'VIP Exclusive Gold Watch',
        price: 25000000,
        seller_id: userMap['seller_tech'].id,
        category: 'Luxury',
        is_vip_exclusive: 1
      },
      {
        name: 'Designer Handbag',
        price: 3500000,
        seller_id: userMap['seller_fashion'].id,
        category: 'Fashion',
        is_vip_exclusive: 0
      },
      {
        name: 'Designer Sunglasses',
        price: 1500000,
        seller_id: userMap['seller_fashion'].id,
        category: 'Fashion',
        is_vip_exclusive: 1
      }
    ];

    const productMap = {};
    for (const p of productsData) {
      const res = insertProduct.run(p.name, p.price, p.seller_id, p.category, p.is_vip_exclusive);
      productMap[p.name] = { id: res.lastInsertRowid, ...p };
    }

    // 3. Seed Orders
    const insertOrder = targetDb.prepare(`
      INSERT INTO orders (customer_id, seller_id, product_id, amount, status, refund_reason)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    const ordersData = [
      {
        customer_id: userMap['customer_regular'].id,
        seller_id: userMap['seller_tech'].id,
        product_id: productMap['Flagship Smartphone'].id,
        amount: 12000000,
        status: 'pending',
        refund_reason: null
      },
      {
        customer_id: userMap['customer_regular'].id,
        seller_id: userMap['seller_tech'].id,
        product_id: productMap['Flagship Smartphone'].id,
        amount: 12000000,
        status: 'shipped',
        refund_reason: null
      },
      {
        customer_id: userMap['customer_vip'].id,
        seller_id: userMap['seller_fashion'].id,
        product_id: productMap['Designer Handbag'].id,
        amount: 350000,
        status: 'refund_requested',
        refund_reason: 'Defective zipper'
      },
      {
        customer_id: userMap['customer_vip'].id,
        seller_id: userMap['seller_tech'].id,
        product_id: productMap['Flagship Smartphone'].id,
        amount: 12000000,
        status: 'refund_requested',
        refund_reason: 'Screen flickering issue'
      }
    ];

    for (const o of ordersData) {
      insertOrder.run(o.customer_id, o.seller_id, o.product_id, o.amount, o.status, o.refund_reason);
    }

    return {
      usersCount: usersData.length,
      productsCount: productsData.length,
      ordersCount: ordersData.length
    };
  });

  return seed();
}

if (require.main === module) {
  const result = seedDatabase();
  console.log(`Database seeded successfully! Users: ${result.usersCount}, Products: ${result.productsCount}, Orders: ${result.ordersCount}`);
}

module.exports = {
  seedDatabase
};
