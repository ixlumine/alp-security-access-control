/**
 * Toko Ku E-Commerce Platform & Security Testing Controller
 * Controls both the Storefront and the Dedicated Security Testing Dashboard
 * Demonstrating:
 * 1. Access Token (JWT & OAuth 2.0)
 * 2. Role-Based Access Control (RBAC)
 * 3. Attribute-Based Access Control (ABAC)
 * 4. Combined RBAC + ABAC Compound Decisions
 */

// Global State
let currentToken = (typeof localStorage !== 'undefined' ? (localStorage.getItem('token') || localStorage.getItem('ecommerce_jwt_token')) : null) || null;
let currentUser = null;
let currentPersonaKey = null;
let allCatalogProducts = [];

// Credentials dictionary for quick one-click persona switching
const PERSONAS = {
  admin: {
    username: 'admin',
    password: 'password123',
    name: 'Administrator',
    role: 'admin',
    tier: 'regular'
  },
  seller_tech: {
    username: 'seller_tech',
    password: 'password123',
    name: 'seller_tech (Toko Gadget)',
    role: 'seller',
    tier: 'regular'
  },
  seller_fashion: {
    username: 'seller_fashion',
    password: 'password123',
    name: 'seller_fashion (Toko Butik)',
    role: 'seller',
    tier: 'regular'
  },
  customer_vip: {
    username: 'customer_vip',
    password: 'password123',
    name: 'customer_vip',
    role: 'customer',
    tier: 'vip'
  },
  customer_regular: {
    username: 'customer_regular',
    password: 'password123',
    name: 'customer_regular',
    role: 'customer',
    tier: 'regular'
  }
};

/**
 * Format integer amount to Indonesian Rupiah
 */
function formatRupiah(amount) {
  return new Intl.NumberFormat('id-ID', {
    style: 'currency',
    currency: 'IDR',
    maximumFractionDigits: 0
  }).format(amount);
}

/**
 * Safely parse a JWT without external libraries
 */
function parseJwt(token) {
  try {
    const base64Url = token.split('.')[1];
    if (!base64Url) return null;
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (e) {
    return null;
  }
}

/**
 * Append formatted log entry into the live HTTP console
 */
function logHttp(method, url, authHeader, status, responseData) {
  const consoleEl = document.getElementById('httpConsole');
  if (!consoleEl) return;

  const timeStr = new Date().toLocaleTimeString();
  const entry = document.createElement('div');
  entry.className = 'log-entry bg-white border border-gray-200 rounded-lg p-2.5 text-xs font-mono space-y-1 shadow-xs text-gray-800';

  let statusClass = 'text-gray-600 bg-gray-100 border border-gray-200';
  if (status >= 200 && status < 300) statusClass = 'text-emerald-700 bg-emerald-50 border border-emerald-200 font-bold';
  else if (status === 401) statusClass = 'text-amber-800 bg-amber-50 border border-amber-200 font-bold';
  else if (status === 403) statusClass = 'text-red-700 bg-red-50 border border-red-200 font-bold';
  else if (status >= 400) statusClass = 'text-red-700 bg-red-50 border border-red-200 font-bold';

  let methodColor = 'text-blue-600';
  if (method === 'POST') methodColor = 'text-emerald-600';
  if (method === 'DELETE') methodColor = 'text-red-600';
  if (method === 'GET') methodColor = 'text-blue-600';

  const authShort = authHeader ? `${authHeader.substring(0, 24)}...` : 'None';

  let formattedBody = '';
  try {
    formattedBody = JSON.stringify(responseData, null, 2);
  } catch (err) {
    formattedBody = String(responseData);
  }

  entry.innerHTML = `
    <div class="flex flex-wrap items-center justify-between text-[11px] text-gray-500 pb-1 border-b border-gray-100">
      <div class="flex items-center gap-2">
        <span class="text-gray-400">[${timeStr}]</span>
        <span class="${methodColor} font-bold">${method}</span>
        <span class="text-gray-900 font-semibold truncate max-w-xs">${url}</span>
      </div>
      <div class="flex items-center gap-2">
        <span class="text-gray-400">Auth:</span>
        <span class="text-gray-600 font-mono text-[10px]">${authShort}</span>
        <span class="px-1.5 py-0.5 rounded text-[10px] ${statusClass}">${status}</span>
      </div>
    </div>
    <div class="text-[11px] text-gray-800 max-h-28 overflow-y-auto pt-1 font-mono">
      <pre class="whitespace-pre-wrap">${escapeHtml(formattedBody)}</pre>
    </div>
  `;

  // Remove placeholder if present
  if (consoleEl.children.length === 1 && (consoleEl.children[0].innerText.includes('Menunggu') || consoleEl.children[0].innerText.includes('Waiting'))) {
    consoleEl.innerHTML = '';
  }

  consoleEl.appendChild(entry);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function escapeHtml(string) {
  return String(string)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Universal fetch wrapper injecting Authorization Bearer token
 */
async function fetchWithAuth(url, options = {}) {
  const headers = Object.assign({}, options.headers || {});

  if (!headers['Content-Type'] && options.body && typeof options.body === 'string') {
    headers['Content-Type'] = 'application/json';
  }

  if (currentToken && !headers['Authorization'] && !options.skipAuth) {
    headers['Authorization'] = `Bearer ${currentToken}`;
  }

  const method = options.method || 'GET';
  const authHeader = headers['Authorization'] || null;

  try {
    const res = await fetch(url, { ...options, headers });
    let data;
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      data = await res.json();
    } else {
      data = await res.text();
    }

    logHttp(method, url, authHeader, res.status, data);
    return { status: res.status, ok: res.ok, data };
  } catch (err) {
    logHttp(method, url, authHeader, 0, { error: err.message });
    return { status: 0, ok: false, data: { error: err.message } };
  }
}

/**
 * Show clean notification banner for authorization feedback
 */
let alertTimeout = null;
function showAlert(title, message, isSuccess = true) {
  const banner = document.getElementById('authAlertBanner');
  const box = document.getElementById('alertBox');
  const icon = document.getElementById('alertIcon');
  const titleEl = document.getElementById('alertTitle');
  const msgEl = document.getElementById('alertMessage');

  if (!banner || !box) return;

  titleEl.innerText = title;
  msgEl.innerText = message;

  if (isSuccess) {
    icon.className = 'fa-solid fa-circle-check text-zinc-700';
  } else {
    icon.className = 'fa-solid fa-circle-exclamation text-red-600';
  }

  banner.classList.remove('hidden');

  if (alertTimeout) clearTimeout(alertTimeout);
  alertTimeout = setTimeout(() => {
    hideAlert();
  }, 6000);
}

function hideAlert() {
  const banner = document.getElementById('authAlertBanner');
  if (banner) banner.classList.add('hidden');
}

/**
 * Dynamically ensure the Security Authorization Decision Modal is present in the DOM
 */
function ensureAuthModal() {
  if (document.getElementById('authDecisionModal')) return;

  const modalHtml = `
    <div id="authDecisionModal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4 bg-zinc-950/40 backdrop-blur-xs transition-opacity duration-150">
      <div id="authModalCard" class="bg-white rounded-xl shadow-xl border border-zinc-200 w-full max-w-md overflow-hidden transform transition-all duration-150 scale-95 opacity-0 flex flex-col p-6 gap-4">
        
        <!-- Header: Status & Policy Type -->
        <div class="flex items-start justify-between gap-3">
          <div class="flex items-center gap-2">
            <span id="authModalStatusBadge" class="text-[11px] font-mono px-2 py-0.5 rounded font-semibold uppercase bg-zinc-100 text-zinc-700">403 FORBIDDEN</span>
            <span id="authModalPolicyType" class="text-[11px] font-medium text-zinc-400 uppercase tracking-wide">RBAC</span>
          </div>
          <button onclick="closeAuthModal()" class="text-zinc-400 hover:text-zinc-700 transition p-1">
            <i class="fa-solid fa-xmark text-sm"></i>
          </button>
        </div>

        <!-- Title & Direct Reason -->
        <div>
          <h2 id="authModalTitle" class="text-sm font-bold text-zinc-900">Keputusan Otorisasi</h2>
          <p id="authModalMessage" class="text-xs text-zinc-600 mt-1 leading-relaxed"></p>
        </div>

        <!-- Attributes evaluated -->
        <div class="border-t border-b border-zinc-100 py-2.5">
          <div id="authModalAttributes" class="space-y-1.5 text-xs">
            <!-- Key-value lines -->
          </div>
        </div>

        <!-- Collapsible Raw JSON -->
        <div>
          <button onclick="toggleModalRawJson()" class="text-[11px] font-medium text-zinc-500 hover:text-zinc-900 flex items-center gap-1 transition">
            <i id="authModalJsonChevron" class="fa-solid fa-chevron-right text-[10px] transition-transform"></i>
            <span>Payload REST API (JSON)</span>
          </button>
          <div id="authModalJsonContainer" class="hidden mt-2 p-3 bg-zinc-950 text-emerald-400 font-mono text-[11px] rounded-lg overflow-x-auto max-h-36">
            <pre id="authModalJsonContent" class="whitespace-pre-wrap"></pre>
          </div>
        </div>

        <!-- Footer Button -->
        <div class="pt-1">
          <button onclick="closeAuthModal()" class="w-full py-2 bg-zinc-900 hover:bg-black text-white text-xs font-medium rounded-lg transition text-center">
            Tutup
          </button>
        </div>

      </div>
    </div>
  `;

  document.body.insertAdjacentHTML('beforeend', modalHtml);

  // Close modal when clicking outside card
  const modalEl = document.getElementById('authDecisionModal');
  modalEl.addEventListener('click', (e) => {
    if (e.target === modalEl) closeAuthModal();
  });

  // Close modal on Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAuthModal();
  });
}

/**
 * Display the Security Authorization Decision Modal with clean minimalist formatting
 */
function showAuthModal({ status = 200, policyType = 'RBAC', title = 'Keputusan Otorisasi', message = '', attributes = {}, rawResponse = null }) {
  ensureAuthModal();

  const modal = document.getElementById('authDecisionModal');
  const card = document.getElementById('authModalCard');
  const titleEl = document.getElementById('authModalTitle');
  const statusBadge = document.getElementById('authModalStatusBadge');
  const policyTypeEl = document.getElementById('authModalPolicyType');
  const msgEl = document.getElementById('authModalMessage');
  const attrContainer = document.getElementById('authModalAttributes');
  const jsonContent = document.getElementById('authModalJsonContent');
  const jsonContainer = document.getElementById('authModalJsonContainer');
  const jsonChevron = document.getElementById('authModalJsonChevron');

  titleEl.innerText = title;
  policyTypeEl.innerText = policyType;
  msgEl.innerText = message;

  const isSuccess = status >= 200 && status < 300;
  const isForbidden = status === 403;
  const isUnauthorized = status === 401;

  if (isSuccess) {
    statusBadge.innerText = `${status} DISETUJUI`;
    statusBadge.className = 'text-[11px] font-mono px-2 py-0.5 rounded font-semibold uppercase bg-emerald-50 text-emerald-800 border border-emerald-200';
  } else if (isForbidden) {
    statusBadge.innerText = '403 DITOLAK';
    statusBadge.className = 'text-[11px] font-mono px-2 py-0.5 rounded font-semibold uppercase bg-red-50 text-red-800 border border-red-200';
  } else if (isUnauthorized) {
    statusBadge.innerText = '401 UNAUTHORIZED';
    statusBadge.className = 'text-[11px] font-mono px-2 py-0.5 rounded font-semibold uppercase bg-amber-50 text-amber-800 border border-amber-200';
  } else {
    statusBadge.innerText = `${status} ERROR`;
    statusBadge.className = 'text-[11px] font-mono px-2 py-0.5 rounded font-semibold uppercase bg-zinc-100 text-zinc-700 border border-zinc-200';
  }

  // Populate Attributes Table cleanly
  const attrEntries = Object.entries(attributes);
  if (attrEntries.length > 0) {
    attrContainer.innerHTML = attrEntries.map(([k, v]) => `
      <div class="flex items-center justify-between py-0.5 text-xs">
        <span class="text-zinc-500">${escapeHtml(k)}</span>
        <span class="font-medium text-zinc-900 font-mono text-[11px]">${escapeHtml(String(v))}</span>
      </div>
    `).join('');
  } else {
    attrContainer.innerHTML = '<div class="text-zinc-400 italic">Tidak ada parameter tambahan.</div>';
  }

  // Populate Raw JSON
  if (rawResponse) {
    jsonContent.innerText = typeof rawResponse === 'object' ? JSON.stringify(rawResponse, null, 2) : String(rawResponse);
  } else {
    jsonContent.innerText = '// Tidak ada payload balasan';
  }
  jsonContainer.classList.add('hidden');
  jsonChevron.classList.remove('rotate-90');

  // Show Modal with smooth animation
  modal.classList.remove('hidden');
  setTimeout(() => {
    card.classList.remove('scale-95', 'opacity-0');
    card.classList.add('scale-100', 'opacity-100');
  }, 10);
}

function closeAuthModal() {
  const modal = document.getElementById('authDecisionModal');
  const card = document.getElementById('authModalCard');
  if (!modal || !card) return;

  card.classList.remove('scale-100', 'opacity-100');
  card.classList.add('scale-95', 'opacity-0');
  setTimeout(() => {
    modal.classList.add('hidden');
  }, 120);
}

function toggleModalRawJson() {
  const container = document.getElementById('authModalJsonContainer');
  const chevron = document.getElementById('authModalJsonChevron');
  if (!container) return;

  const isHidden = container.classList.contains('hidden');
  if (isHidden) {
    container.classList.remove('hidden');
    chevron.classList.add('rotate-90');
  } else {
    container.classList.add('hidden');
    chevron.classList.remove('rotate-90');
  }
}

/**
 * Update badge elements on the security testing dashboard
 */
function updateBadge(badgeId, status, text) {
  const el = document.getElementById(badgeId);
  if (!el) return;

  el.className = 'text-xs font-mono font-medium px-2 py-0.5 rounded transition';

  if (status >= 200 && status < 300) {
    el.classList.add('badge-200');
    el.innerText = `${status} OK`;
  } else if (status === 401) {
    el.classList.add('badge-401');
    el.innerText = '401 Unauthorized';
  } else if (status === 403) {
    el.classList.add('badge-403');
    el.innerText = '403 Forbidden';
  } else if (status === 404) {
    el.classList.add('badge-404');
    el.innerText = '404 Not Found';
  } else {
    el.classList.add('badge-500');
    el.innerText = `${status} Error`;
  }

  if (text) el.title = text;
}

/**
 * Switch tabs in the main storefront navigation (index.html)
 */
function switchNavTab(tabName) {
  // Update nav buttons
  document.querySelectorAll('.nav-item').forEach((btn) => {
    btn.classList.remove('active', 'bg-zinc-100', 'text-zinc-900', 'text-emerald-700', 'bg-emerald-50', 'text-blue-600', 'bg-blue-50');
    btn.classList.add('text-zinc-500');
  });

  const activeBtn = document.getElementById(`nav-${tabName}`);
  if (activeBtn) {
    activeBtn.classList.add('active', 'bg-zinc-100', 'text-zinc-900');
    activeBtn.classList.remove('text-zinc-500');
  }

  // Update view containers
  document.querySelectorAll('.view-panel').forEach((panel) => {
    panel.classList.add('hidden');
  });

  const targetPanel = document.getElementById(`view-${tabName}`);
  if (targetPanel) {
    targetPanel.classList.remove('hidden');
  }

  // Load contextual data
  if (tabName === 'storefront') {
    loadStorefrontProducts();
  } else if (tabName === 'vip-deals') {
    fetchVipDeals();
  } else if (tabName === 'my-orders') {
    loadUserOrders();
  } else if (tabName === 'seller-center') {
    loadSellerOrders();
  } else if (tabName === 'admin-panel') {
    loadAdminMetrics();
    loadAdminUsers();
  }
}

/**
 * Update User Profile & Decoded JWT Claims UI (both pages)
 */
function updateSessionUI(user, token) {
  currentUser = user;
  currentToken = token;

  const profileUsername = document.getElementById('profileUsername');
  const roleBadge = document.getElementById('roleBadge');
  const tierBadge = document.getElementById('tierBadge');
  const verifiedBadge = document.getElementById('verifiedBadge');
  const userAvatar = document.getElementById('userAvatar');
  const rawTokenInput = document.getElementById('rawTokenInput');
  const decodedClaimsViewer = document.getElementById('decodedClaimsViewer');

  if (user) {
    if (profileUsername) profileUsername.innerText = user.username || 'Pengguna';
    if (roleBadge) {
      roleBadge.innerText = (user.role || 'customer').toUpperCase();
      roleBadge.className = 'text-[10px] font-mono px-1.5 py-0.5 rounded font-medium uppercase bg-zinc-100 text-zinc-700 border border-zinc-200';
    }

    if (tierBadge) {
      tierBadge.innerText = user.tier === 'vip' ? 'VIP' : 'Regular';
      tierBadge.className = user.tier === 'vip' ? 'text-amber-800 font-semibold' : 'text-zinc-500 font-medium';
    }

    if (verifiedBadge) {
      verifiedBadge.innerText = user.is_verified ? 'Verified' : 'Unverified';
      verifiedBadge.className = user.is_verified ? 'text-zinc-900 font-medium' : 'text-zinc-400 font-normal';
    }

    if (userAvatar) {
      userAvatar.innerText = (user.username || 'U').charAt(0).toUpperCase();
    }
  }

  if (rawTokenInput) rawTokenInput.value = token || '';
  if (decodedClaimsViewer) {
    decodedClaimsViewer.innerText = token ? JSON.stringify(parseJwt(token), null, 2) : '// Tidak ada token aktif';
  }

  // Update compatibility elements for e2e tests
  const claimRole = document.getElementById('claimRole');
  const claimTier = document.getElementById('claimTier');
  const claimVerified = document.getElementById('claimVerified');
  const claimId = document.getElementById('claimId');
  if (user) {
    if (claimRole) claimRole.innerText = user.role || '-';
    if (claimTier) claimTier.innerText = user.tier || '-';
    if (claimVerified) claimVerified.innerText = String(user.is_verified);
    if (claimId) claimId.innerText = String(user.id);
  }

  // Enforce role barrier checks for dedicated pages (seller.html and admin.html)
  checkRoleAccess();
}

/**
 * Switch persona / user account (alias for backward compatibility with e2e tests)
 */
async function loginAsPersona(personaKey) {
  return selectPersona(personaKey);
}

/**
 * Switch persona / user account
 */
async function selectPersona(personaKey) {
  currentPersonaKey = personaKey;

  // Highlight button
  document.querySelectorAll('.persona-btn').forEach((btn) => {
    btn.classList.remove('active');
  });
  const activeBtn = document.querySelector(`[data-persona="${personaKey}"]`);
  if (activeBtn) activeBtn.classList.add('active');

  if (personaKey === 'mock_google') {
    const res = await fetchWithAuth('/api/auth/mock-google', {
      method: 'POST',
      body: JSON.stringify({ email: 'google.student@gmail.com', name: 'Google Student' })
    });
    if (res.ok && res.data.token) {
      localStorage.setItem('token', res.data.token);
      localStorage.setItem('ecommerce_jwt_token', res.data.token);
      updateSessionUI(res.data.user, res.data.token);
      showAlert('Autentikasi OAuth 2.0 Berhasil', 'Login via Google OAuth berhasil. Access Token JWT telah diterbitkan.', true);
      refreshCurrentView();
    }
    return;
  }

  const persona = PERSONAS[personaKey];
  if (!persona) return;

  const res = await fetchWithAuth('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: persona.username, password: persona.password })
  });

  if (res.ok && res.data.token) {
    localStorage.setItem('token', res.data.token);
    localStorage.setItem('ecommerce_jwt_token', res.data.token);
    updateSessionUI(res.data.user, res.data.token);
    showAlert('Berganti Pengguna Berhasil', `Anda sekarang login sebagai: ${persona.username} (Role: ${persona.role.toUpperCase()}, Tier: ${persona.tier.toUpperCase()})`, true);
    refreshCurrentView();
  } else {
    showAlert('Login Gagal', res.data.error || 'Gagal login persona', false);
  }
}

function refreshCurrentView() {
  const activeNav = document.querySelector('.nav-item.active');
  if (activeNav) {
    const tabName = activeNav.id.replace('nav-', '');
    switchNavTab(tabName);
  } else if (document.getElementById('productsGrid')) {
    switchNavTab('storefront');
  }
}

let currentCatalogCategory = 'all';

/**
 * Filter catalog products by category tab
 */
function filterCatalogByCategory(category) {
  currentCatalogCategory = category;

  document.querySelectorAll('.cat-pill').forEach((btn) => {
    btn.classList.remove('active', 'bg-zinc-900', 'text-white');
    btn.classList.add('bg-zinc-100', 'text-zinc-600');
  });

  const activeBtn = Array.from(document.querySelectorAll('.cat-pill')).find((b) =>
    b.getAttribute('onclick')?.includes(`'${category}'`)
  );
  if (activeBtn) {
    activeBtn.classList.add('active', 'bg-zinc-900', 'text-white');
    activeBtn.classList.remove('bg-zinc-100', 'text-zinc-600');
  }

  renderStorefrontCards();
}

/**
 * Render minimalist storefront catalog cards
 */
function renderStorefrontCards() {
  const container = document.getElementById('productsGrid');
  if (!container) return;

  const filtered = currentCatalogCategory === 'all'
    ? allCatalogProducts
    : allCatalogProducts.filter((p) => p.category === currentCatalogCategory);

  const countEl = document.getElementById('productTotalCount');
  if (countEl) {
    countEl.innerText = `${filtered.length} dari ${allCatalogProducts.length} produk`;
  }

  if (filtered.length === 0) {
    container.innerHTML = `<div class="col-span-full py-12 text-center text-zinc-400 text-xs">Tidak ada produk dalam kategori ini.</div>`;
    return;
  }

  container.innerHTML = filtered.map((p) => {
    const isVip = p.is_vip_exclusive === 1;
    const canAttemptDelete = currentUser && (currentUser.role === 'admin' || (currentUser.role === 'seller' && p.seller_id === currentUser.id));

    return `
      <div class="bg-white border ${isVip ? 'border-amber-300' : 'border-zinc-200'} rounded-lg p-4 hover:border-zinc-300 transition flex flex-col justify-between gap-3">
        <div class="space-y-2">
          <div class="flex items-center justify-between text-xs">
            <span class="text-[10px] font-mono uppercase text-zinc-500 bg-zinc-100 px-2 py-0.5 rounded">${p.category}</span>
            ${isVip ? `<span class="text-[10px] font-medium text-amber-800 bg-amber-50 border border-amber-200 px-1.5 py-0.5 rounded flex items-center gap-1"><i class="fa-solid fa-crown text-[9px]"></i> VIP</span>` : ''}
          </div>

          <div>
            <h3 class="font-semibold text-sm text-zinc-900 line-clamp-1" title="${escapeHtml(p.name)}">${escapeHtml(p.name)}</h3>
            <p class="text-[11px] text-zinc-400 mt-0.5 font-mono">Toko #${p.seller_id}</p>
          </div>

          <div class="text-sm font-semibold text-zinc-900 pt-1">
            ${formatRupiah(p.price)}
          </div>
        </div>

        <div class="pt-2 border-t border-zinc-100 flex items-center gap-1.5">
          <button onclick="handleBuyProduct(${p.id}, ${p.price})" class="flex-1 py-1.5 px-3 bg-zinc-900 hover:bg-black text-white text-xs font-medium rounded-md transition text-center">
            Beli
          </button>
          ${canAttemptDelete ? `
            <button onclick="handleDeleteProduct(${p.id})" title="Hapus Produk (Uji Otorisasi)" class="py-1.5 px-2.5 border border-zinc-200 hover:bg-zinc-50 text-zinc-500 hover:text-red-600 rounded-md text-xs transition">
              <i class="fa-solid fa-trash-can"></i>
            </button>
          ` : ''}
        </div>
      </div>
    `;
  }).join('');
}

/**
 * VIEW 1: Load and Render Storefront Catalog (Toko Ku)
 */
async function loadStorefrontProducts() {
  const container = document.getElementById('productsGrid');
  if (!container) return;

  container.innerHTML = `
    <div class="col-span-full py-12 text-center text-zinc-400">
      <i class="fa-solid fa-spinner fa-spin text-base text-zinc-600 mb-2"></i>
      <p class="text-xs">Memuat katalog produk Toko Ku...</p>
    </div>
  `;

  const res = await fetchWithAuth('/api/products');
  if (!res.ok || !res.data.products) {
    container.innerHTML = `<div class="col-span-full py-8 text-center text-red-500 text-xs">Gagal memuat produk.</div>`;
    return;
  }

  allCatalogProducts = res.data.products;
  renderStorefrontCards();
}

/**
 * Handle Order Purchase (Demonstrates ABAC VIP check & Order creation)
 */
async function handleBuyProduct(productId, amount) {
  const res = await fetchWithAuth('/api/orders', {
    method: 'POST',
    body: JSON.stringify({ product_id: productId, amount })
  });

  const p = allCatalogProducts.find(x => x.id === productId);
  const isVip = p && p.is_vip_exclusive === 1;

  if (res.ok) {
    showAlert('Pesanan Berhasil Dibuat!', `Pesanan baru (ID #${res.data.order.id}) berhasil dibuat dengan status 'pending'.`, true);
    showAuthModal({
      status: 201,
      policyType: isVip ? 'ABAC (VIP Exclusive Tier Authorization)' : 'ABAC / RBAC (Order Placement)',
      title: 'Pesanan Berhasil Dibuat (201 Created)',
      message: `Pesanan ID #${res.data.order.id} berhasil diterbitkan di database. Status awal: 'pending'. Evaluasi atribut tier '${currentUser ? currentUser.tier : 'regular'}' valid.`,
      attributes: {
        'Akun Pembeli': currentUser ? currentUser.username : 'Guest',
        'Tier Akun': currentUser ? currentUser.tier : 'regular',
        'Produk ID': `#${productId}`,
        'Nominal Transaksi': formatRupiah(amount),
        'Status Pesanan': 'pending'
      },
      rawResponse: res.data
    });
    loadUserOrders();
  } else {
    showAlert('Otorisasi Ditolak (ABAC)', res.data.error || 'Gagal membuat pesanan.', false);
    showAuthModal({
      status: res.status,
      policyType: 'ABAC (Attribute-Based Access Control Tier Gate)',
      title: 'Pembelian Ditolak (403 Forbidden)',
      message: res.data.error || 'Produk ini merupakan item eksklusif VIP. Akun dengan tier regular tidak dapat membelinya.',
      attributes: {
        'Akun Pembeli': currentUser ? currentUser.username : 'Guest',
        'Tier Akun Anda': currentUser ? currentUser.tier : 'regular',
        'Tier Diperlukan': 'vip',
        'Aturan Kebijakan': 'canAccessProduct: subject.tier === "vip"',
        'Rekomendasi': 'Ganti persona ke customer_vip untuk menyelesaikan pembelian'
      },
      rawResponse: res.data
    });
  }
}

/**
 * Handle Product Deletion (Demonstrates Combined RBAC + ABAC)
 */
async function handleDeleteProduct(productId) {
  if (!confirm(`Apakah Anda yakin ingin menguji penghapusan produk ID #${productId}?`)) return;

  const res = await fetchWithAuth(`/api/products/${productId}`, {
    method: 'DELETE'
  });

  const p = allCatalogProducts.find(x => x.id === productId);

  if (res.ok) {
    showAlert('Penghapusan Berhasil!', res.data.reason || res.data.message, true);
    showAuthModal({
      status: 200,
      policyType: 'Combined Controls (RBAC + ABAC Compound Policy)',
      title: 'Penghapusan Produk Berhasil (200 OK)',
      message: res.data.reason || res.data.message || 'Produk berhasil dihapus dari sistem Toko Ku.',
      attributes: {
        'Akun Eksekutor': currentUser ? currentUser.username : 'Unknown',
        'Role': currentUser ? currentUser.role : 'admin',
        'Produk ID': `#${productId}`,
        'Keputusan Evaluasi': currentUser && currentUser.role === 'admin' ? 'Admin Superuser Override (Global)' : 'Pemilik Sah & 0 Pesanan Aktif'
      },
      rawResponse: res.data
    });
    loadStorefrontProducts();
    loadSellerProducts();
  } else {
    showAlert('Otorisasi Penghapusan Ditolak (RBAC+ABAC)', res.data.error || 'Gagal menghapus produk.', false);
    showAuthModal({
      status: res.status,
      policyType: 'Combined Controls (RBAC + ABAC Compound Rule)',
      title: 'Penghapusan Produk Ditolak (403 Forbidden)',
      message: res.data.error || 'Penghapusan produk ditolak oleh kebijakan otorisasi gabungan.',
      attributes: {
        'Akun Eksekutor': currentUser ? currentUser.username : 'Guest',
        'Role Akun': currentUser ? currentUser.role : 'customer',
        'Produk ID Target': `#${productId}`,
        'Aturan Otorisasi': 'Hanya Admin (Bebas) ATAU Seller Pemilik Produk dengan 0 Pesanan Aktif',
        'Alasan Penolakan': res.data.error || 'Pelanggaran kebijakan compound'
      },
      rawResponse: res.data
    });
  }
}

/**
 * VIEW 2: VIP Deals (ABAC Tier Gate)
 */
async function fetchVipDeals() {
  const container = document.getElementById('vipProductsContainer');
  if (!container) return;

  container.innerHTML = `
    <div class="py-10 text-center text-zinc-400">
      <i class="fa-solid fa-spinner fa-spin text-base text-zinc-600 mb-2"></i>
      <p class="text-xs">Memeriksa hak akses VIP...</p>
    </div>
  `;

  const res = await fetchWithAuth('/api/products/vip-deals');

  if (!res.ok) {
    container.innerHTML = `
      <div class="border border-zinc-200 rounded-xl p-8 text-center max-w-lg mx-auto bg-zinc-50/50">
        <div class="w-10 h-10 rounded-full bg-zinc-100 text-zinc-700 mx-auto flex items-center justify-center text-sm mb-3">
          <i class="fa-solid fa-lock"></i>
        </div>
        <h3 class="text-sm font-semibold text-zinc-900">Akses Terkunci (ABAC Tier Gate)</h3>
        <p class="text-xs text-zinc-500 mt-1.5 leading-relaxed">
          ${res.data.error || "Halaman katalog ini memerlukan atribut tier: 'vip'. Akun regular tidak diizinkan mengakses diskon eksklusif."}
        </p>
        <div class="mt-4 pt-4 border-t border-zinc-200/70 text-[11px] text-zinc-500 flex items-center justify-center gap-1.5">
          <i class="fa-solid fa-info-circle text-zinc-400"></i>
          <span>Pilih persona <strong>VIP</strong> pada switcher atas untuk mengakses katalog ini.</span>
        </div>
      </div>
    `;
    showAlert('Akses VIP Deals Ditolak (ABAC)', res.data.error || 'Atribut tier akun Anda bukan VIP', false);
    showAuthModal({
      status: 403,
      policyType: 'ABAC (Tier Gate)',
      title: 'Akses Katalog VIP Ditolak (403 Forbidden)',
      message: res.data.error || 'Atribut tier akun Anda adalah regular. Halaman penawaran eksklusif ini dilindungi oleh kebijakan ABAC.',
      attributes: {
        'Akun Aktif': currentUser ? currentUser.username : 'Guest',
        'Tier Anda': currentUser ? currentUser.tier : 'regular',
        'Tier Diperlukan': 'vip',
        'Aturan Evaluasi': 'subject.tier === "vip"',
        'Endpoint': 'GET /api/products/vip-deals'
      },
      rawResponse: res.data
    });
    return;
  }

  const products = res.data.products || [];
  if (products.length === 0) {
    container.innerHTML = `<div class="p-6 rounded-lg border border-zinc-200 text-center text-xs text-zinc-500">Tidak ada produk VIP aktif saat ini.</div>`;
    return;
  }

  container.innerHTML = `
    <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
      ${products.map((p) => `
        <div class="bg-white border border-amber-300 rounded-lg p-4 hover:border-amber-400 transition flex flex-col justify-between gap-3">
          <div class="space-y-2">
            <div class="flex items-center justify-between text-xs">
              <span class="text-[10px] font-mono uppercase text-zinc-500 bg-zinc-100 px-2 py-0.5 rounded">${p.category}</span>
              <span class="text-[10px] font-medium text-amber-800 bg-amber-50 border border-amber-200 px-1.5 py-0.5 rounded flex items-center gap-1">
                <i class="fa-solid fa-crown text-[9px]"></i> VIP Deal
              </span>
            </div>

            <div>
              <h3 class="font-semibold text-sm text-zinc-900 line-clamp-1" title="${escapeHtml(p.name)}">${escapeHtml(p.name)}</h3>
              <p class="text-[11px] text-zinc-400 mt-0.5 font-mono">Toko #${p.seller_id}</p>
            </div>

            <div class="text-sm font-semibold text-zinc-900 pt-1">
              ${formatRupiah(p.price)}
            </div>
          </div>

          <div class="pt-2 border-t border-zinc-100">
            <button onclick="handleBuyProduct(${p.id}, ${p.price})" class="w-full py-1.5 px-3 bg-zinc-900 hover:bg-black text-white text-xs font-medium rounded-md transition text-center">
              Beli Penawaran VIP
            </button>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

/**
 * VIEW 3: Load User Orders (ABAC Ownership & Status Lifecycle)
 */
async function loadUserOrders() {
  const container = document.getElementById('ordersListContainer');
  if (!container) return;

  container.innerHTML = `
    <div class="py-10 text-center text-zinc-400">
      <i class="fa-solid fa-spinner fa-spin text-base text-zinc-600 mb-2"></i>
      <p class="text-xs">Memuat riwayat transaksi pesanan...</p>
    </div>
  `;

  const res = await fetchWithAuth('/api/orders');
  if (!res.ok) {
    container.innerHTML = `<div class="p-6 rounded-lg border border-red-200 text-center text-xs text-red-600">Gagal memuat pesanan.</div>`;
    return;
  }

  const orders = res.data.orders || [];
  const badgeCount = document.getElementById('orderCountBadge');
  if (badgeCount) badgeCount.innerText = orders.length;

  if (orders.length === 0) {
    container.innerHTML = `
      <div class="border border-zinc-200 rounded-lg p-8 text-center text-zinc-500 text-xs">
        Belum ada pesanan untuk akun ini. Buka tab <strong>Katalog</strong> dan klik "Beli" untuk membuat transaksi baru.
      </div>
    `;
    return;
  }

  const statusMap = {
    pending: { label: 'Pending', class: 'bg-amber-50 text-amber-800 border-amber-200' },
    shipped: { label: 'Shipped', class: 'bg-zinc-100 text-zinc-700 border-zinc-200' },
    refund_requested: { label: 'Refund Requested', class: 'bg-purple-50 text-purple-800 border-purple-200' },
    refunded: { label: 'Refunded', class: 'bg-emerald-50 text-emerald-800 border-emerald-200' },
    cancelled: { label: 'Cancelled', class: 'bg-zinc-100 text-zinc-400 border-zinc-200' }
  };

  container.innerHTML = orders.map((o) => {
    const s = statusMap[o.status] || { label: o.status, class: 'bg-zinc-100 text-zinc-700 border-zinc-200' };
    const canCancel = o.status === 'pending';

    return `
      <div class="bg-white border border-zinc-200 rounded-lg p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 transition hover:border-zinc-300">
        <div class="space-y-1">
          <div class="flex items-center gap-2">
            <span class="font-mono font-medium text-xs text-zinc-900">Order #${o.id}</span>
            <span class="text-[10px] px-2 py-0.5 rounded font-mono uppercase border ${s.class}">${s.label}</span>
          </div>
          <div class="text-xs text-zinc-500">
            Produk #${o.product_id} &bull; Toko #${o.seller_id}
          </div>
          <div class="text-[11px] text-zinc-400 font-mono">${o.created_at || ''}</div>
        </div>

        <div class="flex flex-col sm:items-end gap-2 w-full sm:w-auto">
          <div class="text-sm font-semibold text-zinc-900">${formatRupiah(o.amount)}</div>

          <div class="flex items-center gap-2">
            <button onclick="handleCancelOrder(${o.id})" class="px-2.5 py-1 text-xs font-medium rounded-md border border-zinc-200 text-zinc-700 hover:bg-zinc-50 transition" title="${canCancel ? 'Batalkan pesanan (pending)' : 'Uji ABAC (hanya status pending yang diizinkan)'}">
              Batalkan ${!canCancel ? '<span class="text-[10px] text-zinc-400 font-mono">(Uji ABAC)</span>' : ''}
            </button>

            ${o.status === 'shipped' ? `
              <button onclick="handleRequestRefund(${o.id})" class="px-2.5 py-1 text-xs font-medium rounded-md border border-zinc-200 text-zinc-700 hover:bg-zinc-50 transition">
                Minta Refund
              </button>
            ` : ''}
          </div>
        </div>
      </div>
    `;
  }).join('');
}

/**
 * Handle Order Cancellation (Demonstrates ABAC Status Lifecycle)
 */
async function handleCancelOrder(orderId) {
  const res = await fetchWithAuth(`/api/orders/${orderId}/cancel`, {
    method: 'POST'
  });

  if (res.ok) {
    showAlert('Pesanan Berhasil Dibatalkan (ABAC)', 'Status pesanan berhasil diubah menjadi cancelled karena masih berstatus pending.', true);
    showAuthModal({
      status: 200,
      policyType: 'ABAC (Order Lifecycle State Guard)',
      title: 'Pesanan Berhasil Dibatalkan (200 OK)',
      message: 'Evaluasi aturan ABAC berhasil: Pesanan dimiliki oleh pembeli yang login dan berstatus "pending", sehingga pembatalan diizinkan.',
      attributes: {
        'Akun Pembeli': currentUser ? currentUser.username : 'Customer',
        'Order ID': `#${orderId}`,
        'Status Lama': 'pending',
        'Status Baru': 'cancelled',
        'Aturan ABAC': 'canCancelOrder: order.customer_id === subject.id && order.status === "pending"'
      },
      rawResponse: res.data
    });
    loadUserOrders();
  } else {
    showAlert('Pembatalan Ditolak (ABAC Lifecycle)', res.data.error || 'Hanya pesanan berstatus pending yang dapat dibatalkan.', false);
    showAuthModal({
      status: res.status,
      policyType: 'ABAC (Order Lifecycle State Guard)',
      title: 'Pembatalan Pesanan Ditolak (403 Forbidden)',
      message: res.data.error || 'Pesanan tidak dapat dibatalkan. Sistem keamanan ABAC melarang pembatalan pesanan yang telah dikirim (shipped).',
      attributes: {
        'Akun Pembeli': currentUser ? currentUser.username : 'Customer',
        'Order ID': `#${orderId}`,
        'Status Pesanan Saat Ini': 'shipped (Terkunci)',
        'Syarat Pembatalan': 'Hanya diperbolehkan saat status masih "pending"',
        'Rekomendasi': 'Gunakan tombol "Minta Refund" untuk pesanan yang telah dikirim'
      },
      rawResponse: res.data
    });
  }
}

/**
 * Handle Customer Requesting Refund
 */
async function handleRequestRefund(orderId) {
  const reason = prompt('Masukkan alasan pengajuan pengembalian dana (refund):', 'Barang tidak sesuai / ingin retur');
  if (!reason) return;

  const res = await fetchWithAuth(`/api/orders/${orderId}/request-refund`, {
    method: 'POST',
    body: JSON.stringify({ reason })
  });

  if (res.ok) {
    showAlert('Pengajuan Refund Dikirim', 'Pesanan kini berstatus refund_requested. Penjual dapat mereviewnya di Seller Center.', true);
    showAuthModal({
      status: 200,
      policyType: 'ABAC (Order Lifecycle Transition)',
      title: 'Pengajuan Refund Terkirim (200 OK)',
      message: 'Status pesanan berhasil diubah menjadi "refund_requested". Penjual atau Admin sekarang dapat mengevaluasi permohonan pengembalian dana.',
      attributes: {
        'Akun Pembeli': currentUser ? currentUser.username : 'Customer',
        'Order ID': `#${orderId}`,
        'Alasan Pengajuan': reason,
        'Status Baru': 'refund_requested'
      },
      rawResponse: res.data
    });
    loadUserOrders();
  } else {
    showAlert('Gagal Mengajukan Refund', res.data.error, false);
  }
}

/**
 * VIEW 4: Seller Center (RBAC + ABAC)
 */
async function loadSellerOrders() {
  const container = document.getElementById('sellerOrdersContainer');
  if (!container) return;

  container.innerHTML = `
    <div class="py-6 text-center text-zinc-400 text-xs">
      <i class="fa-solid fa-spinner fa-spin text-sm text-zinc-600 mb-1"></i>
      <p>Memuat transaksi toko...</p>
    </div>
  `;

  if (currentUser && currentUser.role !== 'seller' && currentUser.role !== 'admin') {
    container.innerHTML = `
      <div class="p-4 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-900 text-center">
        <div class="font-bold flex items-center justify-center gap-1.5 mb-1">
          <i class="fa-solid fa-lock text-amber-700"></i>
          <span>Pesanan Masuk Terkunci (RBAC: ${currentUser.role.toUpperCase()})</span>
        </div>
        <p class="text-[11px] text-amber-800">
          Akun aktif saat ini adalah <strong>${currentUser.username}</strong> dengan role <code>${currentUser.role}</code>. 
          Pesanan masuk toko dan wewenang refund hanya dapat diakses oleh mitra <code>seller</code> atau <code>admin</code>.
        </p>
      </div>
    `;
    return;
  }

  const res = await fetchWithAuth('/api/orders');
  if (!res.ok) {
    container.innerHTML = `
      <div class="p-3 bg-red-50 border border-red-200 rounded-md text-xs text-red-700 text-center">
        ${res.data.error || 'Akses Ditolak: Anda tidak memiliki wewenang penjual.'}
      </div>
    `;
    return;
  }

  const orders = res.data.orders || [];
  if (orders.length === 0) {
    container.innerHTML = `<div class="p-4 text-center text-zinc-400 text-xs">Belum ada pesanan masuk ke toko ini.</div>`;
    return;
  }

  container.innerHTML = orders.map((o) => {
    const isRefundReq = o.status === 'refund_requested';
    const isOverCeiling = o.amount > 500000;

    return `
      <div class="p-3 border border-zinc-200 rounded-lg flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs bg-white hover:border-zinc-300 transition">
        <div>
          <div class="flex items-center gap-2">
            <span class="font-mono font-medium text-zinc-900">Order #${o.id}</span>
            <span class="text-[10px] px-1.5 py-0.5 rounded font-mono uppercase ${isRefundReq ? 'bg-purple-50 text-purple-800 border border-purple-200' : 'bg-zinc-100 text-zinc-600'}">${o.status}</span>
          </div>
          <div class="text-[11px] text-zinc-500 mt-1">
            Nominal: <strong class="text-zinc-900 font-semibold">${formatRupiah(o.amount)}</strong> &bull; Pembeli ID: #${o.customer_id}
          </div>
        </div>

        <div>
          ${isRefundReq ? `
            <button onclick="handleApproveRefund(${o.id})" class="px-2.5 py-1 text-xs font-medium rounded-md transition ${isOverCeiling ? 'border border-amber-300 bg-amber-50 text-amber-800 hover:bg-amber-100' : 'bg-zinc-900 hover:bg-black text-white'}">
              Setujui Refund (${formatRupiah(o.amount)}) ${isOverCeiling ? '<span class="text-[10px] font-mono">(Uji Plafon)</span>' : ''}
            </button>
          ` : `
            <span class="text-[11px] text-zinc-400 italic">Selesai</span>
          `}
        </div>
      </div>
    `;
  }).join('');
}

/**
 * Handle Seller Creating Product
 */
async function handleCreateProduct(e) {
  e.preventDefault();
  const name = document.getElementById('newProdName').value;
  const category = document.getElementById('newProdCategory').value;
  const price = document.getElementById('newProdPrice').value;
  const isVip = document.getElementById('newProdVip').checked ? 1 : 0;

  const res = await fetchWithAuth('/api/products', {
    method: 'POST',
    body: JSON.stringify({ name, category, price, is_vip_exclusive: isVip })
  });

  if (res.ok) {
    showAlert('Produk Berhasil Ditambahkan (RBAC)', `Produk '${name}' berhasil dipublikasikan ke katalog Toko Ku!`, true);
    showAuthModal({
      status: 201,
      policyType: 'RBAC (Role-Based Access Control)',
      title: 'Produk Berhasil Dibuat (201 Created)',
      message: `Role '${currentUser ? currentUser.role : 'seller'}' sah dan memiliki izin (products:create) untuk mempublikasikan produk baru ke katalog Toko Ku.`,
      attributes: {
        'Akun Pembuat': currentUser ? currentUser.username : 'seller',
        'Role Akun': currentUser ? currentUser.role : 'seller',
        'Izin RBAC': 'products:create (Granted)',
        'Nama Produk': name,
        'Kategori': category,
        'Harga': formatRupiah(price)
      },
      rawResponse: res.data
    });
    document.getElementById('createProductForm').reset();
    loadStorefrontProducts();
    loadSellerProducts();
  } else {
    showAlert('Gagal Tambah Produk (RBAC)', res.data.error || 'Akses ditolak', false);
    showAuthModal({
      status: res.status,
      policyType: 'RBAC (Role-Based Access Control)',
      title: 'Akses Tambah Produk Ditolak (403 Forbidden)',
      message: res.data.error || "Akses ditolak: Hanya role 'seller' dan 'admin' yang memiliki hak akses membuat produk baru.",
      attributes: {
        'Akun Aktif': currentUser ? currentUser.username : 'Tamu (Guest)',
        'Role Akun Anda': currentUser ? currentUser.role : 'customer',
        'Role Diperlukan': 'seller, admin',
        'Operasi Terlarang': 'POST /api/products',
        'Rekomendasi': 'Beralih ke akun seller_tech atau admin pada tombol switcher di atas'
      },
      rawResponse: res.data
    });
  }
}

/**
 * Handle Approve Refund (Demonstrates Combined RBAC + ABAC Ceilings)
 */
async function handleApproveRefund(orderId) {
  const res = await fetchWithAuth(`/api/orders/${orderId}/approve-refund`, {
    method: 'POST'
  });

  if (res.ok) {
    showAlert('Refund Disetujui (RBAC+ABAC)', res.data.reason || res.data.message, true);
    showAuthModal({
      status: 200,
      policyType: 'Combined Controls (RBAC + ABAC Approval Ceiling)',
      title: 'Persetujuan Refund Berhasil (200 OK)',
      message: res.data.reason || res.data.message || 'Refund berhasil disetujui.',
      attributes: {
        'Akun Eksekutor': currentUser ? currentUser.username : 'Unknown',
        'Role': currentUser ? currentUser.role : 'seller',
        'Order ID': `#${orderId}`,
        'Kebijakan Evaluasi': currentUser && currentUser.role === 'admin' ? 'Admin Superuser Override (Tanpa batasan nominal)' : 'Seller Store Owner (Nominal <= Rp 500.000)'
      },
      rawResponse: res.data
    });
    loadSellerOrders();
    loadAdminOrders();
    loadUserOrders();
  } else {
    showAlert('Approval Refund Ditolak (RBAC+ABAC)', res.data.error, false);
    showAuthModal({
      status: res.status,
      policyType: 'Combined Controls (RBAC + ABAC Amount Plafon Ceiling)',
      title: 'Persetujuan Refund Ditolak (403 Forbidden)',
      message: res.data.error || 'Akses ditolak oleh kebijakan plafon batas persetujuan refund.',
      attributes: {
        'Akun Eksekutor': currentUser ? currentUser.username : 'Guest',
        'Role Akun': currentUser ? currentUser.role : 'seller',
        'Order ID': `#${orderId}`,
        'Batas Plafon Seller': 'Maksimal Rp 500.000',
        'Penyebab Penolakan': res.data.error || 'Nominal melampaui limit wewenang seller',
        'Rekomendasi': 'Gunakan akun "admin" pada demo switcher untuk menyetujui refund bernilai besar'
      },
      rawResponse: res.data
    });
  }
}

/**
 * VIEW 5: Admin Panel (RBAC Superuser)
 */
async function loadAdminMetrics(isManualTrigger = false) {
  const res = await fetchWithAuth('/api/admin/metrics');
  const usersEl = document.getElementById('metricUsers');
  const prodsEl = document.getElementById('metricProducts');
  const revEl = document.getElementById('metricRevenue');

  if (!res.ok) {
    if (usersEl) usersEl.innerText = '403';
    if (prodsEl) prodsEl.innerText = '403';
    if (revEl) revEl.innerText = 'Terkunci (RBAC)';

    if (isManualTrigger) {
      showAuthModal({
        status: res.status,
        policyType: 'RBAC (Role-Based Access Control)',
        title: 'Akses Audit Finansial Ditolak (403 Forbidden)',
        message: res.data.error || 'Akses ditolak: Endpoint audit platform dilindungi oleh RBAC dan hanya dapat diakses oleh Administrator.',
        attributes: {
          'Akun Aktif': currentUser ? currentUser.username : 'Guest',
          'Role Akun': currentUser ? currentUser.role : 'customer',
          'Role Diperlukan': 'admin',
          'Izin Diperlukan': 'metrics:view',
          'Endpoint': 'GET /api/admin/metrics'
        },
        rawResponse: res.data
      });
    }
    return;
  }

  const data = res.data || {};
  if (usersEl) usersEl.innerText = data.total_users || 0;
  if (prodsEl) prodsEl.innerText = data.total_products || 0;
  if (revEl) revEl.innerText = formatRupiah(data.total_revenue || 0);
}

async function loadAdminUsers(isManualTrigger = false) {
  const tbody = document.getElementById('adminUsersTbody');
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-gray-400">Memuat audit pengguna...</td></tr>`;

  const res = await fetchWithAuth('/api/admin/users');
  if (!res.ok) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="p-5 text-center text-red-600 bg-red-50/70 border border-red-200 rounded-lg">
          <div class="font-bold text-xs flex items-center justify-center gap-1.5">
            <i class="fa-solid fa-ban"></i>
            <span>403 Forbidden: Direktori Pengguna Terkunci (RBAC)</span>
          </div>
          <p class="text-[11px] text-red-500 mt-0.5">
            ${res.data.error || "Hanya role 'admin' yang memiliki wewenang untuk melihat seluruh database pengguna."}
          </p>
        </td>
      </tr>
    `;

    if (isManualTrigger) {
      showAuthModal({
        status: res.status,
        policyType: 'RBAC (Role-Based Access Control)',
        title: 'Akses Direktori Pengguna Ditolak (403 Forbidden)',
        message: res.data.error || "Akses ditolak: Hanya role 'admin' dengan izin 'users:manage' yang berhak mengaudit akun pengguna.",
        attributes: {
          'Akun Aktif': currentUser ? currentUser.username : 'Guest',
          'Role Akun': currentUser ? currentUser.role : 'customer',
          'Role Diperlukan': 'admin',
          'Izin Diperlukan': 'users:manage',
          'Endpoint': 'GET /api/admin/users'
        },
        rawResponse: res.data
      });
    }
    return;
  }

  const users = res.data.users || [];
  tbody.innerHTML = users.map((u) => `
    <tr class="hover:bg-zinc-50/60 transition text-xs">
      <td class="py-2.5 px-3 font-mono text-zinc-400">#${u.id}</td>
      <td class="py-2.5 px-3 font-medium text-zinc-900">${escapeHtml(u.username)}</td>
      <td class="py-2.5 px-3 text-zinc-500 font-mono text-[11px]">${escapeHtml(u.email)}</td>
      <td class="py-2.5 px-3 font-mono uppercase text-[11px] text-zinc-700">${u.role}</td>
      <td class="py-2.5 px-3 font-mono text-[11px] ${u.tier === 'vip' ? 'text-amber-800 font-semibold' : 'text-zinc-500'}">${u.tier}</td>
      <td class="py-2.5 px-3 text-[11px]">${u.is_verified ? '<span class="text-zinc-700 font-medium">Verified</span>' : '<span class="text-zinc-400">Unverified</span>'}</td>
    </tr>
  `).join('');
}

/**
 * Load Seller's Own Products (for seller.html)
 */
async function loadSellerProducts() {
  const container = document.getElementById('sellerProductsContainer');
  if (!container) return;

  container.innerHTML = `
    <div class="col-span-full py-6 text-center text-zinc-400 text-xs">
      <i class="fa-solid fa-spinner fa-spin text-sm text-zinc-600 mb-1"></i>
      <p>Memuat produk toko...</p>
    </div>
  `;

  const res = await fetchWithAuth('/api/products');
  if (!res.ok || !res.data.products) {
    container.innerHTML = `<div class="col-span-full p-4 text-center text-red-500 text-xs">Gagal memuat produk.</div>`;
    return;
  }

  let products = [];
  let isDemoView = false;

  if (currentUser && currentUser.role === 'admin') {
    products = res.data.products;
  } else if (currentUser && currentUser.role === 'seller') {
    products = res.data.products.filter((p) => p.seller_id === currentUser.id);
  } else {
    // For Customer or Guest: display catalog products so they can test the delete button and trigger 403 Forbidden!
    products = res.data.products.slice(0, 3);
    isDemoView = true;
  }

  if (products.length === 0) {
    container.innerHTML = `<div class="col-span-full p-6 text-center text-zinc-400 text-xs border border-zinc-200 rounded-lg">Belum ada produk untuk toko ini. Tambahkan produk baru di atas.</div>`;
    return;
  }

  container.innerHTML = products.map((p) => `
    <div class="p-3.5 border border-zinc-200 rounded-lg flex flex-col justify-between gap-3 text-xs bg-white hover:border-zinc-300 transition">
      <div>
        <div class="flex items-center justify-between text-[10px] text-zinc-400 mb-1">
          <span class="font-mono uppercase px-1.5 py-0.5 rounded bg-zinc-100 text-zinc-600">${p.category}</span>
          <span class="font-mono">ID #${p.id}</span>
        </div>
        <h4 class="font-semibold text-zinc-900 mt-1">${escapeHtml(p.name)}</h4>
        <div class="text-sm font-semibold text-zinc-900 mt-1">${formatRupiah(p.price)}</div>
        ${p.is_vip_exclusive ? '<span class="inline-block text-[10px] font-medium text-amber-800 bg-amber-50 border border-amber-200 px-1 rounded mt-1">VIP Exclusive</span>' : ''}
        ${isDemoView ? '<div class="text-[10px] text-zinc-500 bg-zinc-50 px-1.5 py-0.5 rounded mt-1.5 border border-zinc-200 font-mono">Uji Otorisasi Hapus</div>' : ''}
      </div>
      <div class="pt-2 border-t border-zinc-100 flex items-center justify-between">
        <span class="text-[10px] text-zinc-400 font-mono">Toko #${p.seller_id}</span>
        <button onclick="handleDeleteProduct(${p.id})" class="px-2.5 py-1 border border-zinc-200 hover:bg-zinc-50 text-zinc-600 hover:text-red-600 rounded text-xs font-medium transition flex items-center gap-1">
          <i class="fa-solid fa-trash-can"></i>
          <span>Hapus</span>
        </button>
      </div>
    </div>
  `).join('');
}

/**
 * Load Admin Orders (for admin.html)
 */
async function loadAdminOrders() {
  const container = document.getElementById('adminOrdersContainer');
  if (!container) return;

  container.innerHTML = `
    <div class="py-6 text-center text-zinc-400 text-xs">
      <i class="fa-solid fa-spinner fa-spin text-sm text-zinc-600 mb-1"></i>
      <p>Memuat seluruh pesanan platform...</p>
    </div>
  `;

  if (currentUser && currentUser.role !== 'admin') {
    container.innerHTML = `
      <div class="p-4 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700 text-center">
        <div class="font-bold flex items-center justify-center gap-1.5 mb-1">
          <i class="fa-solid fa-shield-halved"></i>
          <span>Wewenang Superuser Diperlukan (RBAC)</span>
        </div>
        <p class="text-[11px] text-red-600">
          Akun aktif saat ini adalah <strong>${currentUser ? currentUser.username : 'Guest'}</strong> (Role: ${currentUser ? currentUser.role : 'guest'}). 
          Hanya Administrator (Role: <code>admin</code>) yang memiliki wewenang untuk mengawasi dan menyetujui refund bernilai besar (&gt; Rp 500.000).
        </p>
      </div>
    `;
    return;
  }

  const res = await fetchWithAuth('/api/orders');
  if (!res.ok) {
    container.innerHTML = `<div class="p-4 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700 text-center">${res.data.error || 'Akses ditolak.'}</div>`;
    return;
  }

  let orders = res.data.orders || [];

  // If user is Customer or Seller and has no refund requested orders in their scope, inject Order #4 so they can test the button!
  if (!orders.some((o) => o.status === 'refund_requested')) {
    orders = [
      { id: 4, customer_id: 4, seller_id: 2, product_id: 1, amount: 2500000, status: 'refund_requested' },
      ...orders
    ];
  }

  container.innerHTML = orders.map((o) => {
    const isRefundReq = o.status === 'refund_requested';
    const isHighValue = o.amount > 500000;

    return `
      <div class="p-3 border border-zinc-200 rounded-lg flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs bg-white hover:border-zinc-300 transition">
        <div>
          <div class="flex items-center gap-2">
            <span class="font-mono font-medium text-zinc-900">Order #${o.id}</span>
            <span class="text-[10px] px-1.5 py-0.5 rounded font-mono uppercase ${isRefundReq ? 'bg-purple-50 text-purple-800 border border-purple-200' : 'bg-zinc-100 text-zinc-600'}">${o.status}</span>
            ${isHighValue ? '<span class="text-[10px] px-1.5 py-0.5 rounded font-mono uppercase bg-amber-50 text-amber-800 border border-amber-200">Nilai Tinggi (&gt; Rp 500rb)</span>' : ''}
          </div>
          <div class="text-[11px] text-zinc-500 mt-1">
            Nominal: <strong class="text-zinc-900 font-semibold">${formatRupiah(o.amount)}</strong> &bull; Toko ID: #${o.seller_id} &bull; Pembeli ID: #${o.customer_id}
          </div>
        </div>

        <div>
          ${isRefundReq ? `
            <button onclick="handleApproveRefund(${o.id})" class="px-2.5 py-1 bg-zinc-900 hover:bg-black text-white rounded text-xs font-medium transition flex items-center gap-1.5">
              <i class="fa-solid fa-check text-[10px]"></i>
              <span>Setujui Refund (Admin Override)</span>
            </button>
          ` : `
            <span class="text-[11px] text-zinc-400 font-mono">Status: ${o.status}</span>
          `}
        </div>
      </div>
    `;
  }).join('');
}

/**
 * Role Barrier Verification for Dedicated Pages (seller.html & admin.html)
 * Configured in OPEN DEMONSTRATION MODE (Option 2):
 * Interface elements remain interactive so that students can demonstrate true server-side 403 Forbidden enforcement.
 */
function checkRoleAccess() {
  const sellerContent = document.getElementById('sellerDashboardContent');
  const roleIndicatorSeller = document.getElementById('currentRoleIndicatorSeller');
  if (sellerContent) {
    sellerContent.classList.remove('hidden');
    const role = currentUser ? currentUser.role : 'guest';
    const isSellerOrAdmin = role === 'seller' || role === 'admin';

    if (roleIndicatorSeller) {
      roleIndicatorSeller.innerText = `ROLE AKTIF: ${role.toUpperCase()}`;
      roleIndicatorSeller.className = isSellerOrAdmin
        ? 'text-[10px] font-mono px-2 py-0.5 rounded font-medium uppercase bg-zinc-100 text-zinc-900 border border-zinc-200'
        : 'text-[10px] font-mono px-2 py-0.5 rounded font-medium uppercase bg-amber-50 text-amber-800 border border-amber-200';
    }

    const storeTitle = document.getElementById('sellerStoreTitle');
    if (storeTitle && currentUser) {
      if (isSellerOrAdmin) {
        storeTitle.innerText = `Toko Saya — ${currentUser.username} (${currentUser.is_verified ? 'Verified Store' : 'Unverified Store'})`;
      } else {
        storeTitle.innerText = `Seller Center — Mode Eksplorasi Demo (${currentUser.username})`;
      }
    }

    loadSellerOrders();
    loadSellerProducts();
  }

  const adminContent = document.getElementById('adminDashboardContent');
  const roleIndicatorAdmin = document.getElementById('currentRoleIndicatorAdmin');
  if (adminContent) {
    adminContent.classList.remove('hidden');
    const role = currentUser ? currentUser.role : 'guest';
    const isAdmin = role === 'admin';

    if (roleIndicatorAdmin) {
      roleIndicatorAdmin.innerText = `ROLE AKTIF: ${role.toUpperCase()}`;
      roleIndicatorAdmin.className = isAdmin
        ? 'text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase bg-zinc-100 text-zinc-900 border border-zinc-200'
        : 'text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase bg-red-50 text-red-800 border border-red-200';
    }

    loadAdminMetrics();
    loadAdminUsers();
    loadAdminOrders();
  }
}

/**
 * Initialization on DOM Load
 */
document.addEventListener('DOMContentLoaded', async () => {
  // 1. Bind persona switcher buttons (present on both index.html and dashboard.html)
  document.querySelectorAll('.persona-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const p = btn.getAttribute('data-persona');
      selectPersona(p);
    });
  });

  // 2. Bind Reset DB button
  const resetBtn = document.getElementById('resetSeedBtn');
  if (resetBtn) {
    resetBtn.addEventListener('click', async () => {
      if (!confirm('Reset database ke baseline awal?')) return;
      const res = await fetchWithAuth('/api/seed', { method: 'POST' });
      if (res.ok) {
        showAlert('Database Direset', 'Seluruh data pengguna, produk, dan pesanan telah dikembalikan ke baseline.', true);
        refreshCurrentView();
      }
    });
  }

  // 3. Bind Copy Token button
  const copyBtn = document.getElementById('copyTokenBtn');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const input = document.getElementById('rawTokenInput');
      if (input && input.value) {
        navigator.clipboard.writeText(input.value);
        showAlert('Token Disalin', 'Bearer token JWT berhasil disalin ke clipboard.', true);
      }
    });
  }

  // 4. Bind Clear Console button
  const clearConsoleBtn = document.getElementById('clearConsoleBtn');
  if (clearConsoleBtn) {
    clearConsoleBtn.addEventListener('click', () => {
      const c = document.getElementById('httpConsole');
      if (c) c.innerHTML = '<div class="text-gray-400 italic">// Log dibersihkan.</div>';
    });
  }

  // 5. Bind Dashboard Tab Switcher (if on dashboard.html)
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetTabId = btn.getAttribute('data-tab');

      // Update button styles
      document.querySelectorAll('.tab-btn').forEach((b) => {
        b.classList.remove('active', 'text-indigo-400', 'border-indigo-500');
        b.classList.add('text-slate-400', 'border-transparent');
      });
      btn.classList.add('active', 'text-indigo-400', 'border-indigo-500');
      btn.classList.remove('text-slate-400', 'border-transparent');

      // Toggle tab content visibility
      document.querySelectorAll('.tab-content').forEach((tab) => {
        tab.classList.add('hidden');
      });
      const activeContent = document.getElementById(targetTabId);
      if (activeContent) activeContent.classList.remove('hidden');
    });
  });

  // 6. Bind Security Dashboard Interactive Test Buttons
  const verifyTokenBtn = document.getElementById('verifyTokenBtn');
  if (verifyTokenBtn) {
    verifyTokenBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/auth/me');
      showAlert(res.ok ? 'Verifikasi Token Sukses' : 'Verifikasi Gagal', res.ok ? `Token sah untuk pengguna: ${res.data.user.username}` : (res.data.error || 'Token tidak valid'), res.ok);
    });
  }

  const launchRealGoogleBtn = document.getElementById('launchRealGoogleBtn');
  if (launchRealGoogleBtn) {
    launchRealGoogleBtn.addEventListener('click', () => {
      window.location.href = '/auth/google';
    });
  }

  const tamperTokenBtn = document.getElementById('tamperTokenBtn');
  if (tamperTokenBtn) {
    tamperTokenBtn.addEventListener('click', () => {
      if (!currentToken) return;
      const parts = currentToken.split('.');
      if (parts.length === 3) {
        currentToken = `${parts[0]}.${parts[1]}.TAMPERED_INVALID_SIGNATURE`;
        currentUser = parseJwt(currentToken);
        updateSessionUI(currentUser, currentToken);
        logHttp('TAMPER', 'Local Token', 'Bearer [Tampered]', 0, {
          warning: 'Token signature rusak sengaja untuk uji penetrasi. Permintaan berikutnya akan ditolak (403).'
        });
        showAlert('Token Dirating (Tampered)', 'Signature token telah diubah sehingga tidak valid. Uji request sekarang untuk melihat penolakan 403.', false);
      }
    });
  }

  // RBAC Tests
  const testAdminMetricsBtn = document.getElementById('testAdminMetricsBtn');
  if (testAdminMetricsBtn) {
    testAdminMetricsBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/admin/metrics');
      updateBadge('badge-admin-metrics', res.status, res.data.error || 'Metrics retrieved');
    });
  }

  const testManageUsersBtn = document.getElementById('testManageUsersBtn');
  if (testManageUsersBtn) {
    testManageUsersBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/admin/users');
      updateBadge('badge-manage-users', res.status, res.data.error || 'Users directory retrieved');
    });
  }

  const testCreateProductBtn = document.getElementById('testCreateProductBtn');
  if (testCreateProductBtn) {
    testCreateProductBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/products', {
        method: 'POST',
        body: JSON.stringify({
          name: 'Interactive Test Item',
          price: 150000,
          category: 'electronics',
          is_vip_exclusive: 0
        })
      });
      updateBadge('badge-create-product', res.status, res.data.error || 'Product created');
    });
  }

  const testPublicCatalogBtn = document.getElementById('testPublicCatalogBtn');
  if (testPublicCatalogBtn) {
    testPublicCatalogBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/products');
      updateBadge('badge-public-catalog', res.status, 'Catalog loaded');
    });
  }

  // ABAC Tests
  const testVipDealsBtn = document.getElementById('testVipDealsBtn');
  if (testVipDealsBtn) {
    testVipDealsBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/products/vip-deals');
      updateBadge('badge-vip-deals', res.status, res.data.error || 'VIP deals retrieved');
    });
  }

  const testViewOrderBtn = document.getElementById('testViewOrderBtn');
  if (testViewOrderBtn) {
    testViewOrderBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/orders/1');
      updateBadge('badge-view-order', res.status, res.data.error || 'Order #1 retrieved');
    });
  }

  const testCancelPendingBtn = document.getElementById('testCancelPendingBtn');
  if (testCancelPendingBtn) {
    testCancelPendingBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/orders/1/cancel', { method: 'POST' });
      updateBadge('badge-cancel-pending', res.status, res.data.error || res.data.message);
    });
  }

  const testCancelShippedBtn = document.getElementById('testCancelShippedBtn');
  if (testCancelShippedBtn) {
    testCancelShippedBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/orders/2/cancel', { method: 'POST' });
      updateBadge('badge-cancel-shipped', res.status, res.data.error || res.data.message);
    });
  }

  // Combined Tests (Product Deletion)
  const testDeleteAdminBtn = document.getElementById('testDeleteAdminBtn');
  if (testDeleteAdminBtn) {
    testDeleteAdminBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/products/4', { method: 'DELETE' });
      updateBadge('badge-delete-admin', res.status, res.data.error || res.data.message);
    });
  }

  const testDeleteSellerZeroOrdersBtn = document.getElementById('testDeleteSellerZeroOrdersBtn');
  if (testDeleteSellerZeroOrdersBtn) {
    testDeleteSellerZeroOrdersBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/products/2', { method: 'DELETE' });
      updateBadge('badge-delete-seller-zero', res.status, res.data.error || res.data.message);
    });
  }

  const testDeleteSellerActiveOrdersBtn = document.getElementById('testDeleteSellerActiveOrdersBtn');
  if (testDeleteSellerActiveOrdersBtn) {
    testDeleteSellerActiveOrdersBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/products/1', { method: 'DELETE' });
      updateBadge('badge-delete-seller-active', res.status, res.data.error || res.data.message);
    });
  }

  const testDeleteOtherSellerBtn = document.getElementById('testDeleteOtherSellerBtn');
  if (testDeleteOtherSellerBtn) {
    testDeleteOtherSellerBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/products/1', { method: 'DELETE' });
      updateBadge('badge-delete-other-seller', res.status, res.data.error || res.data.message);
    });
  }

  const testDeleteCustomerBtn = document.getElementById('testDeleteCustomerBtn');
  if (testDeleteCustomerBtn) {
    testDeleteCustomerBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/products/1', { method: 'DELETE' });
      updateBadge('badge-delete-customer', res.status, res.data.error || res.data.message);
    });
  }

  // Combined Tests (Refund Approval)
  const testRefundSellerUnderLimitBtn = document.getElementById('testRefundSellerUnderLimitBtn');
  if (testRefundSellerUnderLimitBtn) {
    testRefundSellerUnderLimitBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/orders/3/approve-refund', { method: 'POST' });
      updateBadge('badge-refund-seller-under', res.status, res.data.error || res.data.message);
    });
  }

  const testRefundSellerOverLimitBtn = document.getElementById('testRefundSellerOverLimitBtn');
  if (testRefundSellerOverLimitBtn) {
    testRefundSellerOverLimitBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/orders/4/approve-refund', { method: 'POST' });
      updateBadge('badge-refund-seller-over', res.status, res.data.error || res.data.message);
    });
  }

  const testRefundAdminOverLimitBtn = document.getElementById('testRefundAdminOverLimitBtn');
  if (testRefundAdminOverLimitBtn) {
    testRefundAdminOverLimitBtn.addEventListener('click', async () => {
      const res = await fetchWithAuth('/api/orders/4/approve-refund', { method: 'POST' });
      updateBadge('badge-refund-admin-over', res.status, res.data.error || res.data.message);
    });
  }

  // Logout button & handler
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', handleLogout);
  }

  // Client-Side Route Guarding
  if (typeof window !== 'undefined') {
    const isLoginPage = window.location.pathname.endsWith('login.html');
    const urlParams = new URLSearchParams(window.location.search);
    const tokenInUrl = urlParams.get('token');

    if (tokenInUrl) {
      localStorage.setItem('token', tokenInUrl);
      localStorage.setItem('ecommerce_jwt_token', tokenInUrl);
      currentToken = tokenInUrl;
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    // If not logged in and not on login.html: redirect to login
    if (!currentToken && !isLoginPage) {
      window.location.href = 'login.html';
      return;
    }

    // If logged in and on login.html: redirect to storefront
    if (currentToken && isLoginPage) {
      window.location.href = 'index.html';
      return;
    }

    // Initialize authenticated session
    if (currentToken) {
      const parsed = parseJwt(currentToken);
      if (parsed) {
        updateSessionUI(parsed, currentToken);
        if (document.getElementById('productsGrid')) {
          switchNavTab('storefront');
        }
      } else {
        handleLogout();
        return;
      }
    }
  }

  if (document.getElementById('productsGrid')) {
    switchNavTab('storefront');
  }
  checkRoleAccess();
});

/**
 * Global Logout Handler: Clears session and redirects to login.html
 */
function handleLogout() {
  if (typeof localStorage !== 'undefined') {
    localStorage.removeItem('token');
    localStorage.removeItem('ecommerce_jwt_token');
  }
  currentToken = null;
  currentUser = null;
  currentPersonaKey = null;
  if (typeof window !== 'undefined') {
    window.location.href = 'login.html';
  }
}
