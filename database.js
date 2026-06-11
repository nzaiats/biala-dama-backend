/**
 * database.js — Dworek Biała Dama
 * Relational SQLite schema.
 *
 * Relations:
 *   users ──────────────────────────────── (staff accounts)
 *   reservations ──────────────────────── (guest + manual blocks)
 *   floor_layouts   (1 row per hall)  ──── active table layout
 *   floor_elements  (1 row per hall)  ──── entrance/window/bar labels
 *   layout_templates (3 slots/hall)   ──── saved layout presets
 */
'use strict';
 
const sqlite3 = require('sqlite3').verbose();
const bcrypt  = require('bcrypt');
const path    = require('path');
const fs      = require('fs');

// ── Ścieżka bazy danych ──────────────────────────────────────────────────────
// Konfiguracja przez zmienną DB_PATH (Render Disk: /var/data) lub lokalnie ./data
const DATA_DIR = process.env.DB_DIR || path.join(__dirname, 'data');
const DB_PATH  = path.join(DATA_DIR, 'bialadama.db');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new sqlite3.Database(DB_PATH, err => {
    if (err) { console.error('DB error:', err.message); process.exit(1); }
    console.log('✓ SQLite connected:', DB_PATH);
});

db.run('PRAGMA journal_mode = WAL;');
db.run('PRAGMA foreign_keys = ON;');

const DEFAULT_LAYOUTS = {
    kominkowa: [
        {n:1, cap:2,l:'5%', top:'18%',w:'12%',h:'13%'},{n:2, cap:2,l:'21%',top:'18%',w:'12%',h:'13%'},
        {n:3, cap:4,l:'38%',top:'18%',w:'18%',h:'12%'},{n:4, cap:4,l:'60%',top:'18%',w:'18%',h:'12%'},
        {n:5, cap:6,l:'5%', top:'42%',w:'23%',h:'12%'},{n:6, cap:4,l:'33%',top:'42%',w:'18%',h:'12%'},
        {n:7, cap:4,l:'55%',top:'42%',w:'18%',h:'12%'},{n:8, cap:8,l:'77%',top:'42%',w:'18%',h:'12%'},
        {n:9, cap:2,l:'5%', top:'66%',w:'12%',h:'13%'},{n:10,cap:6,l:'22%',top:'66%',w:'23%',h:'12%'},
        {n:11,cap:6,l:'50%',top:'66%',w:'23%',h:'12%'},
    ],
    lesna: [
        {n:1,cap:2,l:'6%', top:'14%',w:'12%',h:'13%'},{n:2,cap:2,l:'22%',top:'14%',w:'12%',h:'13%'},
        {n:3,cap:4,l:'40%',top:'14%',w:'18%',h:'12%'},{n:4,cap:4,l:'63%',top:'14%',w:'18%',h:'12%'},
        {n:5,cap:2,l:'6%', top:'44%',w:'12%',h:'13%'},{n:6,cap:4,l:'25%',top:'44%',w:'30%',h:'12%'},
        {n:7,cap:2,l:'70%',top:'44%',w:'12%',h:'13%'},
    ],
    taras: [
        {n:1,cap:4,l:'5%', top:'18%',w:'18%',h:'12%'},{n:2,cap:4,l:'29%',top:'18%',w:'18%',h:'12%'},
        {n:3,cap:6,l:'55%',top:'18%',w:'23%',h:'12%'},{n:4,cap:4,l:'5%', top:'54%',w:'18%',h:'12%'},
        {n:5,cap:4,l:'29%',top:'54%',w:'18%',h:'12%'},
    ],
};

function initDatabase(cb) {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id            INTEGER  PRIMARY KEY AUTOINCREMENT,
            username      TEXT     UNIQUE NOT NULL,
            password_hash TEXT     NOT NULL,
            role          TEXT     DEFAULT 'staff',
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS reservations (
            id             TEXT PRIMARY KEY,
            hall           TEXT NOT NULL,
            hall_name      TEXT,
            table_num      INTEGER,
            table_capacity INTEGER,
            date           TEXT NOT NULL,
            time           TEXT NOT NULL,
            duration       REAL    DEFAULT 2,
            guests         INTEGER DEFAULT 1,
            fname          TEXT,
            lname          TEXT,
            phone          TEXT,
            email          TEXT,
            notes          TEXT,
            status         TEXT    DEFAULT 'pending',
            source         TEXT    DEFAULT 'online',
            person_meals   TEXT    DEFAULT '{}',
            created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS floor_layouts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            hall        TEXT    UNIQUE NOT NULL,
            tables_json TEXT    NOT NULL DEFAULT '[]'
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS floor_elements (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            hall          TEXT    UNIQUE NOT NULL,
            elements_json TEXT    NOT NULL DEFAULT '[]'
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS layout_templates (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            hall          TEXT    NOT NULL,
            slot          INTEGER NOT NULL,
            name          TEXT    DEFAULT 'Szablon',
            tables_json   TEXT    DEFAULT '[]',
            elements_json TEXT    DEFAULT '[]',
            UNIQUE(hall, slot)
        )`);

        // Seed admin
        db.get('SELECT id FROM users WHERE username=?', ['bialadama'], (err, row) => {
            if (!row) {
                bcrypt.hash('bialadama123', 10, (err, hash) => {
                    if (err) return;
                    db.run('INSERT INTO users (username,password_hash,role) VALUES(?,?,?)',
                        ['bialadama', hash, 'admin'],
                        () => console.log('✓ Admin seeded — login: bialadama / bialadama123'));
                });
            }
        });

        console.log('✓ Database schema ready');
        if (cb) cb();
    });
}

module.exports = { db, initDatabase, DEFAULT_LAYOUTS };