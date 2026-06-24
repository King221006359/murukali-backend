// ════════════════════════════════════════════════════════════
//  MURUKALI BACKEND — Express + PostgreSQL (Neon)
//  Serves both Murukali Finance and Murukali Performance Tracker
// ════════════════════════════════════════════════════════════
//
// SETUP:
//   1. npm install express pg bcryptjs jsonwebtoken cors dotenv
//   2. Create a .env file (see .env.example below) with your
//      Neon connection string and a JWT secret
//   3. Run schema.sql once on your Neon database
//   4. Create your admin user (see bottom of this file for a
//      one-time script) OR use the /api/auth/bootstrap endpoint
//      described below
//   5. node server.js  (or `npm start` if you add that script)
//
// ════════════════════════════════════════════════════════════

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const BOOTSTRAP_KEY = process.env.BOOTSTRAP_KEY; // one-time setup protection

if (!process.env.DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is not set. Check your .env file.');
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set. Check your .env file.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // required for Neon
});

// ────────────────────────────────────────────────
// DATE NORMALIZATION
// node-postgres returns DATE columns as full JS Date objects
// (serialized to ISO timestamps like "2026-06-24T00:00:00.000Z"
// in JSON), but every frontend comparison expects a plain
// "YYYY-MM-DD" string. This converts any Date-typed field on a
// row (or array of rows) to that plain string before it's sent.
// ────────────────────────────────────────────────
function normalizeDates(rowOrRows) {
  const fix = (row) => {
    if (!row || typeof row !== 'object') return row;
    for (const key of Object.keys(row)) {
      const val = row[key];
      if (val instanceof Date) {
        row[key] = val.toISOString().slice(0, 10); // "YYYY-MM-DD"
      }
    }
    return row;
  };
  return Array.isArray(rowOrRows) ? rowOrRows.map(fix) : fix(rowOrRows);
}

// ────────────────────────────────────────────────
// AUTH MIDDLEWARE
// ────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.admin = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ────────────────────────────────────────────────
// AUTH ROUTES
// ────────────────────────────────────────────────

// One-time bootstrap: create the first admin user.
// Protected by BOOTSTRAP_KEY env var so randoms can't create admins.
// Call this ONCE, then you can remove BOOTSTRAP_KEY from your env if you want.
app.post('/api/auth/bootstrap', async (req, res) => {
  try {
    const { email, password, key } = req.body;
    if (!BOOTSTRAP_KEY || key !== BOOTSTRAP_KEY) {
      return res.status(403).json({ error: 'Invalid bootstrap key' });
    }
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    const existing = await pool.query('SELECT id FROM admin_users LIMIT 1');
    if (existing.rows.length > 0) {
      return res.status(403).json({ error: 'Admin already exists. Bootstrap can only run once.' });
    }
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO admin_users (email, password_hash) VALUES ($1, $2)', [email, hash]);
    res.json({ ok: true, message: 'Admin user created. You can now log in.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM admin_users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, email: user.email });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ────────────────────────────────────────────────
// GENERIC TABLE HELPERS
// (mirrors the simple get/insert/patch/delete pattern
//  your frontend already expects)
// ────────────────────────────────────────────────
function makeCrudRoutes(tableName, routeBase, columns) {
  // GET all rows
  app.get(`/api/${routeBase}`, async (req, res) => {
    try {
      const result = await pool.query(`SELECT * FROM ${tableName} ORDER BY id ASC`);
      res.json(normalizeDates(result.rows));
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Query failed' });
    }
  });

  // POST insert (admin only)
  app.post(`/api/${routeBase}`, requireAdmin, async (req, res) => {
    try {
      const body = req.body;
      const cols = columns.filter(c => body[c] !== undefined);
      const vals = cols.map(c => body[c]);
      const placeholders = cols.map((_, i) => `${i + 1}`).join(',');
      const result = await pool.query(
        `INSERT INTO ${tableName} (${cols.join(',')}) VALUES (${placeholders}) RETURNING *`,
        vals
      );
      res.json(normalizeDates(result.rows[0]));
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Insert failed', detail: e.message });
    }
  });

  // PATCH update by id (admin only)
  app.patch(`/api/${routeBase}/:id`, requireAdmin, async (req, res) => {
    try {
      const body = req.body;
      const cols = columns.filter(c => body[c] !== undefined);
      const vals = cols.map(c => body[c]);
      const setClause = cols.map((c, i) => `${c} = ${i + 1}`).join(',');
      const result = await pool.query(
        `UPDATE ${tableName} SET ${setClause} WHERE id = ${cols.length + 1} RETURNING *`,
        [...vals, req.params.id]
      );
      if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
      res.json(normalizeDates(result.rows[0]));
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Update failed', detail: e.message });
    }
  });

  // DELETE by id (admin only)
  app.delete(`/api/${routeBase}/:id`, requireAdmin, async (req, res) => {
    try {
      await pool.query(`DELETE FROM ${tableName} WHERE id = $1`, [req.params.id]);
      res.json({ ok: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Delete failed' });
    }
  });
}

// ────────────────────────────────────────────────
// MURUKALI FINANCE ROUTES
// ────────────────────────────────────────────────
makeCrudRoutes('fin_transactions', 'finance/transactions',
  ['client_id','client_name','date','momo_out','cred_out','fix_out','cash_out','momo_in','cred_in','fix_in','cash_in','notes']);

makeCrudRoutes('fin_expenses', 'finance/expenses',
  ['description','category','date','amount','pay_method']);

makeCrudRoutes('fin_stock', 'finance/stock',
  ['item_name','date','qty','cost_unit','payment','no_sold','remaining','sell_cost']);

makeCrudRoutes('fin_opening_balances', 'finance/opening-balances',
  ['date','momo','cash','fix_momo','cred_dpo']);

makeCrudRoutes('fin_fund_movements', 'finance/fund-movements',
  ['description','date','from_acct','to_acct','amount']);

makeCrudRoutes('fin_liquidity', 'finance/liquidity',
  ['date','momo','cash','fix_momo']);

// ────────────────────────────────────────────────
// MURUKALI PERFORMANCE TRACKER ROUTES
// ────────────────────────────────────────────────
makeCrudRoutes('agents', 'tracker/agents', ['name','role']);
makeCrudRoutes('roles', 'tracker/roles', ['name']);
makeCrudRoutes('tracker_orders', 'tracker/orders',
  ['agent_id','year','month','date_key','num','products','refunded','worse']);

// ────────────────────────────────────────────────
// HEALTH CHECK
// ────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.listen(PORT, () => {
  console.log(`Murukali backend running on port ${PORT}`);
});