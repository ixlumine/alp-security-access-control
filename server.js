const app = require('./src/app');
const { PORT } = require('./src/config/env');

const server = app.listen(PORT, () => {
  console.log('================================================================');
  console.log('  E-COMMERCE AUTHORIZATION & SECURITY PLATFORM (ALP CYBERSEC)  ');
  console.log('================================================================');
  console.log(`  🚀 Server listening on port: ${PORT}`);
  console.log(`  🌐 Interactive Dashboard:   http://localhost:${PORT}`);
  console.log(`  🩺 API Health Check:        http://localhost:${PORT}/api/health`);
  console.log('  --------------------------------------------------------------');
  console.log('  Active Route Mount Points:');
  console.log('    • Authentication: /api/auth & /auth');
  console.log('    • Admin RBAC:     /api/admin');
  console.log('    • Products ABAC:  /api/products');
  console.log('    • Orders Controls: /api/orders');
  console.log('================================================================');
});

// Graceful termination handlers
process.on('SIGINT', () => {
  console.log('\nShutting down server gracefully...');
  server.close(() => {
    console.log('Server terminated.');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\nShutting down server gracefully...');
  server.close(() => {
    console.log('Server terminated.');
    process.exit(0);
  });
});

module.exports = server;
