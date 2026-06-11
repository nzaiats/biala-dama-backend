/**
 * server.js — Dworek Biała Dama
 * Express backend: session auth + REST API + SQLite storage.
 *
 * Start:  node server.js
 * URL:    http://localhost:3000
 *
 * Place all frontend files in ./public/
 */
'use strict';

const express  = require('express');
const session  = require('express-session');
const bcrypt   = require('bcrypt');
const path     = require('path');

const { db, initDatabase, DEFAULT_LAYOUTS } = require('./database');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());

// ── CORS: pozwala frontendowi na Vercel komunikować się z tym backendem ─────
// Konfiguracja przez zmienną środowiskową FRONTEND_URL (np. https://biala-dama.vercel.app)
const ALLOWED_ORIGINS = [
    process.env.FRONTEND_URL,                  // produkcja (Vercel)
    'http://localhost:3000',                   // lokalny frontend
    'http://localhost:5500',                   // VS Code Live Server
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5500',
].filter(Boolean);

app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (ALLOWED_ORIGINS.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ── Konfiguracja sesji: cross-origin wymaga sameSite='none' + secure ────────
const isProduction = process.env.NODE_ENV === 'production';
app.use(session({
    secret: process.env.SESSION_SECRET || 'biala-dama-klucz-2026',
    resave: false,
    saveUninitialized: false,
    proxy: isProduction,   // Render działa za proxy
    cookie: {
        maxAge: 8 * 60 * 60 * 1000,
        sameSite: isProduction ? 'none' : 'strict',
        secure: isProduction,
        httpOnly: true,
    }
}));

function auth(req, res, next) {
    if (!req.session.userId) return res.status(401).json({ error: 'Wymagane logowanie' });
    next();
}

// ── Helper: migrate .t → .top in table rows ───────────────────────────────────
function migrateTables(arr) {
    return (arr || []).map(t => {
        if (t.top === undefined && t.t !== undefined) {
            const { t: topVal, ...rest } = t; return { ...rest, top: topVal };
        }
        return t;
    });
}

// ============================================================
// AUTH
// ============================================================
app.post('/api/login', (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Brakuje danych' });
    db.get('SELECT * FROM users WHERE username=?', [username], (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Nieprawidłowy login lub hasło' });
        bcrypt.compare(password, user.password_hash, (err, ok) => {
            if (err || !ok) return res.status(401).json({ error: 'Nieprawidłowy login lub hasło' });
            req.session.userId   = user.id;
            req.session.username = user.username;
            req.session.role     = user.role;
            res.json({ success: true, user: { username: user.username, role: user.role } });
        });
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/auth/status', (req, res) => {
    if (req.session.userId)
        res.json({ authenticated: true, user: { username: req.session.username, role: req.session.role } });
    else
        res.json({ authenticated: false });
});

// ============================================================
// USERS
// ============================================================
app.get('/api/users', auth, (req, res) => {
    db.all('SELECT id,username,role,created_at FROM users ORDER BY id', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

app.post('/api/users', auth, (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Brak uprawnień' });
    const { username, password } = req.body || {};
    if (!username || !password || password.length < 6)
        return res.status(400).json({ error: 'Nieprawidłowe dane' });
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: err.message });
        db.run('INSERT INTO users (username,password_hash,role) VALUES(?,?,?)',
            [username, hash, 'staff'], function(err) {
                if (err) return res.status(400).json({ error: 'Użytkownik już istnieje' });
                res.json({ success: true });
            });
    });
});

app.put('/api/users/:username/password', auth, (req, res) => {
    if (req.params.username !== req.session.username)
        return res.status(403).json({ error: 'Brak uprawnień' });
    const { oldPassword, newPassword } = req.body || {};
    if (!oldPassword || !newPassword || newPassword.length < 6)
        return res.status(400).json({ error: 'Nieprawidłowe dane' });
    db.get('SELECT * FROM users WHERE username=?', [req.params.username], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'Nie znaleziono' });
        bcrypt.compare(oldPassword, user.password_hash, (err, ok) => {
            if (!ok) return res.status(401).json({ error: 'Aktualne hasło nieprawidłowe' });
            bcrypt.hash(newPassword, 10, (err, hash) => {
                if (err) return res.status(500).json({ error: err.message });
                db.run('UPDATE users SET password_hash=? WHERE username=?',
                    [hash, req.params.username],
                    err => err ? res.status(500).json({ error: err.message }) : res.json({ success: true }));
            });
        });
    });
});

// ============================================================
// RESERVATIONS
// ============================================================
// Public: guests POST reservations without login
app.post('/api/reservations', (req, res) => {
    const r = req.body || {};
    if (!r.id || !r.hall || !r.date || !r.time)
        return res.status(400).json({ error: 'Brakuje wymaganych pól' });
    db.run(`INSERT OR IGNORE INTO reservations
        (id,hall,hall_name,table_num,table_capacity,date,time,duration,guests,
         fname,lname,phone,email,notes,status,source,person_meals,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [r.id, r.hall, r.hallName||'', r.tableNum, r.tableCapacity,
         r.date, r.time, r.duration||2, r.guests||1,
         r.fname||'', r.lname||'', r.phone||'', r.email||'', r.notes||'',
         r.status||'pending', r.source||'online',
         JSON.stringify(r.personMeals||{}),
         r.createdAt||new Date().toISOString()],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: r.id });
        });
});

app.get('/api/reservations', auth, (req, res) => {
    const { status, hall } = req.query;
    let sql = 'SELECT * FROM reservations WHERE 1=1';
    const p = [];
    if (status) { sql += ' AND status=?'; p.push(status); }
    if (hall)   { sql += ' AND hall=?';   p.push(hall); }
    sql += ' ORDER BY created_at DESC';
    db.all(sql, p, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json((rows||[]).map(r => ({
            ...r, tableNum: r.table_num, tableCapacity: r.table_capacity,
            hallName: r.hall_name, createdAt: r.created_at,
            personMeals: r.person_meals ? JSON.parse(r.person_meals) : {}
        })));
    });
});

app.get('/api/reservations/search', auth, (req, res) => {
    const { q, hall } = req.query;
    let sql = 'SELECT * FROM reservations WHERE 1=1';
    const p = [];
    if (hall) { sql += ' AND hall=?'; p.push(hall); }
    if (q) {
        sql += ' AND (LOWER(id) LIKE ? OR LOWER(fname||" "||lname) LIKE ? OR phone LIKE ?)';
        const like = '%' + q.toLowerCase() + '%';
        p.push(like, like, like);
    }
    sql += ' ORDER BY created_at DESC';
    db.all(sql, p, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json((rows||[]).map(r => ({
            ...r, tableNum: r.table_num, tableCapacity: r.table_capacity,
            hallName: r.hall_name, createdAt: r.created_at,
            personMeals: r.person_meals ? JSON.parse(r.person_meals) : {}
        })));
    });
});

app.put('/api/reservations/:id/status', auth, (req, res) => {
    const { status } = req.body || {};
    db.run('UPDATE reservations SET status=? WHERE id=?', [status, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ============================================================
// FLOOR LAYOUTS — public read (needed for user reservation map)
// ============================================================
app.get('/api/layouts/:hall', (req, res) => {
    db.get('SELECT tables_json FROM floor_layouts WHERE hall=?', [req.params.hall], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.json(DEFAULT_LAYOUTS[req.params.hall] || []);
        try { res.json(migrateTables(JSON.parse(row.tables_json))); }
        catch { res.json(DEFAULT_LAYOUTS[req.params.hall] || []); }
    });
});

app.post('/api/layouts/:hall', auth, (req, res) => {
    const json = JSON.stringify(req.body.tables || []);
    db.run(`INSERT INTO floor_layouts(hall,tables_json) VALUES(?,?)
            ON CONFLICT(hall) DO UPDATE SET tables_json=excluded.tables_json`,
        [req.params.hall, json],
        err => err ? res.status(500).json({ error: err.message }) : res.json({ success: true }));
});

// ============================================================
// FLOOR ELEMENTS — public read
// ============================================================
app.get('/api/elements/:hall', (req, res) => {
    db.get('SELECT elements_json FROM floor_elements WHERE hall=?', [req.params.hall], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.json([]);
        try { res.json(JSON.parse(row.elements_json)); }
        catch { res.json([]); }
    });
});

app.post('/api/elements/:hall', auth, (req, res) => {
    const json = JSON.stringify(req.body.elements || []);
    db.run(`INSERT INTO floor_elements(hall,elements_json) VALUES(?,?)
            ON CONFLICT(hall) DO UPDATE SET elements_json=excluded.elements_json`,
        [req.params.hall, json],
        err => err ? res.status(500).json({ error: err.message }) : res.json({ success: true }));
});

// ============================================================
// LAYOUT TEMPLATES
// ============================================================
app.get('/api/templates/:hall', auth, (req, res) => {
    db.all('SELECT slot,name,tables_json,elements_json FROM layout_templates WHERE hall=? ORDER BY slot',
        [req.params.hall], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            const slots = [null, null, null];
            (rows||[]).forEach(r => {
                slots[r.slot] = {
                    name: r.name,
                    tables:   migrateTables(r.tables_json   ? JSON.parse(r.tables_json)   : []),
                    elements: r.elements_json ? JSON.parse(r.elements_json) : []
                };
            });
            res.json(slots);
        });
});

app.post('/api/templates/:hall/:slot', auth, (req, res) => {
    const { name, tables, elements } = req.body || {};
    const slot = parseInt(req.params.slot);
    db.run(`INSERT INTO layout_templates(hall,slot,name,tables_json,elements_json) VALUES(?,?,?,?,?)
            ON CONFLICT(hall,slot) DO UPDATE SET
              name=excluded.name,
              tables_json=excluded.tables_json,
              elements_json=excluded.elements_json`,
        [req.params.hall, slot, name||`Szablon ${slot+1}`,
         JSON.stringify(tables||[]), JSON.stringify(elements||[])],
        err => err ? res.status(500).json({ error: err.message }) : res.json({ success: true }));
});

// ── Catch-all: serve index.html for SPA routes ────────────────────────────────
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Monthly database cleanup ─────────────────────────────────────────────────
// Runs automatically: on server start + every 24 hours.
// Deletes reservations older than 1 month (31 days) from the 'history' —
// i.e., expired reservations (end time + 31 days < now).
// Keeps all current and future reservations.
function runMonthlyCleanup() {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - 31);   // 31 days ago
    const cutoffStr = cutoff.toISOString().slice(0, 10);   // 'YYYY-MM-DD'

    // Delete reservations whose date is older than 31 days
    // (regardless of status — they are historical records)
    db.run(
        `DELETE FROM reservations WHERE date < ?`,
        [cutoffStr],
        function(err) {
            if (err) {
                console.error('Monthly cleanup error:', err.message);
            } else if (this.changes > 0) {
                console.log(`🗑️  Monthly cleanup: deleted ${this.changes} old reservation(s) older than ${cutoffStr}`);
            }
        }
    );
}

// Schedule: run on startup, then every 24 hours
function scheduleCleanup() {
    runMonthlyCleanup();
    setInterval(runMonthlyCleanup, 24 * 60 * 60 * 1000);  // 24h
}

// ── Start ─────────────────────────────────────────────────────────────────────
initDatabase(() => {
    scheduleCleanup();   // start monthly cleanup scheduler

    app.listen(PORT, () => {
        console.log(`
╔════════════════════════════════════════╗
║    🏛  DWOREK BIAŁA DAMA — SERVER     ║
╠════════════════════════════════════════╣
║  URL : http://localhost:${PORT}           ║
║  DB  : data/bialadama.db               ║
║  Pliki: ./public/                       ║
╚════════════════════════════════════════╝
        `);
    });
});