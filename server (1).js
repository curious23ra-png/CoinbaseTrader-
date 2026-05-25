'use strict';
/**
 * DAEDALUS TRADING BACKEND v1.0.0
 * ================================
 * Render-hosted Node.js service that handles HMAC-SHA256 signing
 * of Coinbase Advanced Trade API requests.
 *
 * WHY THIS EXISTS:
 * Coinbase API secrets cannot be safely stored or used in a browser —
 * any JavaScript visible to the user can leak them. This server holds
 * the signing logic so API secrets never leave a secure environment.
 *
 * ENDPOINTS:
 *   GET  /health          — status check (used by Daedalus connection test)
 *   POST /api/balance     — fetch Coinbase account USD balance
 *   POST /api/order       — place a market or limit order
 *   POST /api/cancel-order — cancel an open order by ID
 *   POST /api/orders       — list open orders
 */

const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ────────────────────────────────────────────────────
app.use(express.json());
app.use(cors({
  origin: '*',                              // Tighten to your GitHub Pages URL in production
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}));

// ── Optional backend API key (protect this server from public use) ──
const BACKEND_API_KEY = process.env.BACKEND_API_KEY || null;

function verifyApiKey(req, res, next) {
  if (!BACKEND_API_KEY) return next();           // No key set → allow all (dev mode)
  const k = req.headers['x-api-key']
         || (req.headers['authorization'] || '').replace('Bearer ', '');
  if (k !== BACKEND_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized — invalid API key' });
  }
  next();
}

// ── HMAC-SHA256 signer for Coinbase Advanced Trade API ────────────
function buildCoinbaseHeaders(apiKey, apiSecret, method, path, bodyStr = '') {
  const timestamp  = Math.floor(Date.now() / 1000).toString();
  const prehash    = timestamp + method.toUpperCase() + path + bodyStr;
  const signature  = crypto
    .createHmac('sha256', apiSecret)
    .update(prehash)
    .digest('hex');
  return {
    'CB-ACCESS-KEY'       : apiKey,
    'CB-ACCESS-SIGN'      : signature,
    'CB-ACCESS-TIMESTAMP' : timestamp,
    'Content-Type'        : 'application/json',
    'User-Agent'          : 'Daedalus/1.0.0',
  };
}

// ── Coinbase API helper ───────────────────────────────────────────
async function cbRequest(apiKey, apiSecret, method, path, body = null) {
  const bodyStr  = body ? JSON.stringify(body) : '';
  const headers  = buildCoinbaseHeaders(apiKey, apiSecret, method, path, bodyStr);
  const response = await fetch(`https://api.coinbase.com${path}`, {
    method,
    headers,
    ...(bodyStr ? { body: bodyStr } : {}),
  });
  const data = await response.json();
  if (!response.ok) {
    const msg = data?.error_details || data?.message || data?.error || `HTTP ${response.status}`;
    throw new Error(msg);
  }
  return data;
}

// Resolve credentials: per-request body → env vars → error
function resolveCredentials(body) {
  const key    = body?.apiKey    || process.env.COINBASE_API_KEY    || null;
  const secret = body?.apiSecret || process.env.COINBASE_API_SECRET || null;
  if (!key || !secret) throw new Error('Coinbase API credentials not found. Provide apiKey/apiSecret in request body or set COINBASE_API_KEY/COINBASE_API_SECRET environment variables on Render.');
  return { key, secret };
}

// ── Routes ────────────────────────────────────────────────────────

// Health check — Daedalus calls this to verify connection
app.get('/health', (req, res) => {
  res.json({
    status            : 'ok',
    service           : 'Daedalus Render Backend',
    version           : '1.0.0',
    timestamp         : new Date().toISOString(),
    coinbase_env_set  : !!(process.env.COINBASE_API_KEY && process.env.COINBASE_API_SECRET),
  });
});

app.get('/', (req, res) => {
  res.json({ service: 'Daedalus Trading Backend v1.0.0', status: 'running' });
});

// ── GET /api/balance ──────────────────────────────────────────────
app.post('/api/balance', verifyApiKey, async (req, res) => {
  try {
    const { key, secret } = resolveCredentials(req.body);
    const data     = await cbRequest(key, secret, 'GET', '/api/v3/brokerage/accounts');
    const accounts = data.accounts || [];
    const usdAcct  = accounts.find(a => a.currency === 'USD');
    const balance  = usdAcct?.available_balance?.value || '0';

    res.json({
      success  : true,
      balance,
      currency : 'USD',
      accounts : accounts.map(a => ({
        currency : a.currency,
        balance  : a.available_balance?.value,
        hold     : a.hold?.value,
        uuid     : a.uuid,
      })),
    });
  } catch (err) {
    console.error('[/api/balance]', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── POST /api/order ───────────────────────────────────────────────
app.post('/api/order', verifyApiKey, async (req, res) => {
  try {
    const { key, secret } = resolveCredentials(req.body);
    const { symbol, side, qty, orderType = 'market', limitPrice } = req.body;

    if (!symbol) throw new Error('symbol is required (e.g. "BTC" or "BTC-USD")');
    if (!side)   throw new Error('side is required: "BUY" or "SELL"');
    if (!qty)    throw new Error('qty is required');

    const productId      = symbol.includes('-') ? symbol.toUpperCase() : `${symbol.toUpperCase()}-USD`;
    const clientOrderId  = `daedalus-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const qtyStr         = parseFloat(qty).toString();

    // Build order configuration
    let orderConfig;
    if (orderType === 'limit' && limitPrice) {
      orderConfig = {
        limit_limit_gtc: {
          base_size  : qtyStr,
          limit_price: parseFloat(limitPrice).toString(),
          post_only  : false,
        },
      };
    } else {
      // Market order — BUY uses quote_size (USD), SELL uses base_size (coin qty)
      orderConfig = {
        market_market_ioc: {
          [side.toUpperCase() === 'BUY' ? 'quote_size' : 'base_size']: qtyStr,
        },
      };
    }

    const orderBody = {
      client_order_id   : clientOrderId,
      product_id        : productId,
      side              : side.toUpperCase(),
      order_configuration: orderConfig,
    };

    console.log(`[ORDER] ${side.toUpperCase()} ${qty} ${productId} (${orderType})`);

    const data = await cbRequest(key, secret, 'POST', '/api/v3/brokerage/orders', orderBody);

    res.json({
      success       : true,
      clientOrderId,
      order         : data,
      productId,
    });
  } catch (err) {
    console.error('[/api/order]', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── POST /api/cancel-order ────────────────────────────────────────
app.post('/api/cancel-order', verifyApiKey, async (req, res) => {
  try {
    const { key, secret } = resolveCredentials(req.body);
    const { orderId }     = req.body;
    if (!orderId) throw new Error('orderId is required');

    const data = await cbRequest(key, secret, 'POST', '/api/v3/brokerage/orders/batch_cancel', {
      order_ids: [orderId],
    });

    res.json({ success: true, result: data });
  } catch (err) {
    console.error('[/api/cancel-order]', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── POST /api/orders (list open) ──────────────────────────────────
app.post('/api/orders', verifyApiKey, async (req, res) => {
  try {
    const { key, secret } = resolveCredentials(req.body);
    const { symbol }      = req.body;
    const filter          = symbol ? `&product_id=${symbol.toUpperCase()}-USD` : '';
    const data = await cbRequest(
      key, secret, 'GET',
      `/api/v3/brokerage/orders/historical/batch?order_status=OPEN${filter}`
    );
    res.json({ success: true, orders: data.orders || [] });
  } catch (err) {
    console.error('[/api/orders]', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Start ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🏛️  Daedalus Backend v1.0.0 running on port ${PORT}`);
  console.log(`   Coinbase env credentials: ${process.env.COINBASE_API_KEY ? '✓ SET' : '✗ not set (pass per-request)'}`);
  console.log(`   Backend API key guard:    ${BACKEND_API_KEY ? '✓ ENABLED' : '⚠ DISABLED (set BACKEND_API_KEY env var)'}\n`);
});
