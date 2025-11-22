const express = require('express');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const session = require('express-session');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const port = 3000;

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  port: process.env.DB_PORT
});

const API_PREFIX = 'sk-sm-v1-';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// session untuk admin
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret-176-apikey',
    resave: false,
    saveUninitialized: false
  })
);

// middleware auth admin
function isAuthenticated(req, res, next) {
  if (!req.session.adminId) {
    return res.status(401).redirect('/admin.html');
  }
  next();
}

// halaman utama
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =============================
// 1. CREATE API KEY
// =============================
app.post('/create', async (req, res) => {
  try {
    const apiKey =
      API_PREFIX + crypto.randomBytes(24).toString('hex').toUpperCase();

    res.json({ apiKey });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal membuat API key' });
  }
});

// =============================
// 2. CEK API KEY
// =============================
app.post('/cekapi', async (req, res) => {
  try {
    const fromHeader = (req.headers.authorization || '')
      .replace(/^Bearer\s+/i, '')
      .trim();
    const apiKey = req.body && req.body.apiKey ? String(req.body.apiKey) : fromHeader;

    if (!apiKey) {
      return res.status(400).json({
        valid: false,
        error: 'apiKey wajib dikirim (body.apiKey atau Authorization: Bearer ...)'
      });
    }
    if (!apiKey.startsWith(API_PREFIX)) {
      return res
        .status(400)
        .json({ valid: false, error: 'Format apiKey tidak valid' });
    }

    const [rows] = await pool.execute(
      'SELECT id, is_active, created_at, last_used_at FROM api_key WHERE api_key = ? LIMIT 1',
      [apiKey]
    );

    if (rows.length === 0) {
      return res
        .status(401)
        .json({ valid: false, error: 'API key belum dibuat, silakan buat dan simpan user terlebih dahulu' });
    }

    const keyRow = rows[0];

    if (!keyRow.is_active) {
      return res
        .status(403)
        .json({ valid: false, error: 'API key nonaktif' });
    }

    // update last_used_at setiap kali dipakai
    await pool.execute('UPDATE api_key SET last_used_at = NOW() WHERE id = ?', [
      keyRow.id
    ]);

    return res.json({ valid: true });
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ valid: false, error: 'Terjadi kesalahan saat verifikasi' });
  }
});

// =============================
// 3. SIMPAN DATA USER + BUAT API KEY DI DB
// =============================
app.post('/user', async (req, res) => {
  let conn;
  try {
    const { first_name, last_name, email_address, apiKey } = req.body || {};

    if (!first_name || !last_name || !email_address || !apiKey) {
      return res.status(400).json({
        error:
          'first_name, last_name, email_address, dan apiKey wajib diisi'
      });
    }

    // pastikan format apiKey benar
    if (!apiKey.startsWith(API_PREFIX)) {
      return res.status(400).json({
        error: 'Format apiKey tidak valid'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    // 1. Simpan / ambil user
    let userId;

    try {
      const [result] = await conn.execute(
        'INSERT INTO user (first_name, last_name, email_address) VALUES (?, ?, ?)',
        [first_name, last_name, email_address]
      );
      userId = result.insertId;
    } catch (err) {
      // kemungkinan kena UNIQUE KEY
      if (err.code === 'ER_DUP_ENTRY') {
        // Ambil user yang sudah ada (pakai email sebagai kunci utama)
        const [rows] = await conn.execute(
          'SELECT id FROM user WHERE email_address = ? LIMIT 1',
          [email_address]
        );
        if (!rows.length) {
          // kalau ternyata nggak ada juga, baru lempar error asli
          throw err;
        }
        userId = rows[0].id;
      } else {
        throw err;
      }
    }

    // 2. Simpan API key terkait user itu
    try {
      await conn.execute(
        'INSERT INTO api_key (user_id, api_key, is_active) VALUES (?, ?, 1)',
        [userId, apiKey]
      );
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        // api_key harus unik, kalau user generate ulang dan pakai key yang sama
        await conn.rollback();
        return res.status(400).json({
          error: 'API key tersebut sudah ada di database, silakan generate lagi.'
        });
      }
      throw err;
    }

    await conn.commit();

    res.json({
      message: 'User dan API key berhasil disimpan.',
      user_id: userId,
      api_key: apiKey
    });
  } catch (err) {
    console.error(err);
    if (conn) {
      try {
        await conn.rollback();
      } catch (e) {
        console.error('Rollback error:', e);
      }
    }
    res.status(500).json({ error: 'Terjadi kesalahan saat menyimpan user dan API key' });
  } finally {
    if (conn) conn.release();
  }
});

// =============================
// 4. ADMIN: REGISTER
// =============================
app.post('/admin/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res
        .status(400)
        .json({ error: 'Email dan password wajib diisi' });
    }

    const hashed = await bcrypt.hash(password, 10);
    try {
      await pool.execute(
        'INSERT INTO admin (email, password) VALUES (?, ?)',
        [email, hashed]
      );
    } catch (err) {
      console.error(err);
      return res.status(400).json({ error: 'Email admin sudah terdaftar' });
    }

    res.json({ message: 'Admin berhasil diregistrasi. Silakan login.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal registrasi admin' });
  }
});

// =============================
// 5. ADMIN: LOGIN
// =============================
app.post('/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res
        .status(400)
        .json({ error: 'Email dan password wajib diisi' });
    }

    const [rows] = await pool.execute(
      'SELECT id, password FROM admin WHERE email = ? LIMIT 1',
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Email atau password salah' });
    }

    const admin = rows[0];
    const match = await bcrypt.compare(password, admin.password);
    if (!match) {
      return res.status(401).json({ error: 'Email atau password salah' });
    }

    req.session.adminId = admin.id;

    res.json({ message: 'Login berhasil', redirect: '/admin/dashboard' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal login admin' });
  }
});

// =============================
// 6. ADMIN: LOGOUT
// =============================
app.post('/admin/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Gagal logout' });
    }
    res.redirect('/admin.html');
  });
});

// fungsi bantu hitung status online/offline
function computeStatus(row) {
  const isActive = row.is_active === 1 || row.is_active === true;

  // kalau tidak aktif, langsung offline
  if (!isActive) return 'offline';

  const now = new Date();
  const refDate = row.last_used_at || row.created_at;

  if (!refDate) return 'offline';

  const diffMs = now - refDate;
  const diffDays = diffMs / (1000 * 60 * 60 * 24);

  if (diffDays > 30) return 'offline';
  return 'online';
}

// =============================
// 7. ADMIN: DASHBOARD (LIST USER + API KEY + STATUS)
// =============================
app.get('/admin/dashboard', isAuthenticated, async (req, res) => {
  try {
    const [users] = await pool.execute(
      'SELECT id, first_name, last_name, email_address FROM user ORDER BY id DESC'
    );
    const [keys] = await pool.execute(
      'SELECT id, api_key, user_id, is_active, created_at, last_used_at, out_of_date FROM api_key ORDER BY id DESC'
    );

    let userRows = '';
    for (const u of users) {
      userRows += `
        <tr>
          <td>${u.id}</td>
          <td>${u.first_name}</td>
          <td>${u.last_name}</td>
          <td>${u.email_address}</td>
        </tr>`;
    }

    let keyRows = '';
    for (const k of keys) {
      const status = computeStatus(k);
      const statusClass =
        status === 'online' ? 'status-online' : 'status-offline';
      keyRows += `
        <tr>
          <td>${k.id}</td>
          <td class="apikey-cell">${k.api_key}</td>
          <td>${k.user_id || '-'}</td>
          <td>${k.is_active ? '1' : '0'}</td>
          <td>${k.created_at || '-'}</td>
          <td>${k.last_used_at || '-'}</td>
          <td>${k.out_of_date || '-'}</td>
          <td><span class="status-pill ${statusClass}">${status}</span></td>
          <td>
            <button type="button" class="btn btn-delete" onclick="deleteApiKey(${k.id})">
              Delete
            </button>
          </td>
        </tr>`;
    }

    const html = `
      <!DOCTYPE html>
      <html lang="id">
      <head>
        <meta charset="UTF-8" />
        <title>Admin Dashboard - API Key</title>
        <style>
          * {
            box-sizing: border-box;
          }

          body {
            font-family: "Poppins", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            margin: 0;
            padding: 0;
            background:
              radial-gradient(circle at top, #5a0008, transparent 60%),
              radial-gradient(circle at bottom, #1a0004, transparent 60%),
              #060002;
            color: #fce4ec;
          }

          .page-shell {
            min-height: 100vh;
            display: flex;
            align-items: flex-start;
            justify-content: center;
            padding: 24px 12px;
          }

          .wrapper {
            width: 100%;
            max-width: 1150px;
            background:
              radial-gradient(circle at top left, rgba(255, 82, 82, 0.22), transparent 55%),
              radial-gradient(circle at bottom right, rgba(255, 214, 0, 0.2), transparent 55%),
              #220008;
            border-radius: 20px;
            padding: 22px 26px 26px;
            box-shadow:
              0 16px 40px rgba(0, 0, 0, 0.95),
              0 0 30px rgba(255, 82, 82, 0.7);
            border: 1px solid #b71c1c;
            position: relative;
            overflow: hidden;
          }

          .wrapper::before {
            content: "";
            position: absolute;
            top: 0;
            left: -8%;
            width: 116%;
            height: 30px;
            background-image: repeating-linear-gradient(
              90deg,
              #ffeb3b 0 18px,
              #f44336 18px 36px
            );
            box-shadow: 0 4px 12px rgba(0,0,0,0.9);
          }

          .wrapper-inner {
            position: relative;
            z-index: 1;
          }

          .top-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            margin-top: 18px;
          }

          h1 {
            margin: 0;
            font-size: 26px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: #ff5252;
            text-shadow:
              0 0 6px rgba(255, 82, 82, 0.9),
              0 0 16px rgba(255, 214, 0, 0.8);
          }

          .tagline {
            margin: 2px 0 0;
            font-size: 12px;
            color: #ffe082;
            letter-spacing: 0.18em;
            text-transform: uppercase;
            text-shadow: 0 0 6px rgba(0,0,0,0.9);
          }

          .header-left {
            display: flex;
            flex-direction: column;
            gap: 2px;
          }

          .btn {
            border: none;
            cursor: pointer;
            font-family: inherit;
          }

          .btn-logout {
            padding: 8px 16px;
            border-radius: 999px;
            background-image: linear-gradient(90deg, #f50057, #ffca28);
            background-size: 200% 200%;
            color: #1a0004;
            font-size: 13px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            box-shadow:
              0 6px 14px rgba(0,0,0,0.95),
              0 0 14px rgba(255, 64, 129, 0.9);
            transition: background-position 0.25s ease, transform 0.12s ease, box-shadow 0.12s ease;
          }

          .btn-logout:hover {
            background-position: 100% 0;
            transform: translateY(-1px);
            box-shadow:
              0 8px 16px rgba(0,0,0,1),
              0 0 18px rgba(255, 128, 171, 1);
          }

          .btn-logout:active {
            transform: translateY(1px) scale(0.98);
          }

          h2 {
            margin-top: 20px;
            margin-bottom: 8px;
            font-size: 18px;
            color: #ffeb3b;
            text-transform: uppercase;
            letter-spacing: 0.14em;
            text-shadow: 0 0 6px rgba(0,0,0,0.9);
          }

          .section-divider {
            height: 1px;
            background: linear-gradient(90deg, transparent, #ff5252, transparent);
            margin-bottom: 8px;
            opacity: 0.8;
          }

          table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 6px;
            margin-bottom: 18px;
            font-size: 13px;
            background-color: rgba(6,0,2,0.9);
            border-radius: 12px;
            overflow: hidden;
          }

          thead {
            background: linear-gradient(90deg, #b71c1c, #880e4f);
          }

          th, td {
            border: 1px solid #4e0a12;
            padding: 8px 10px;
            text-align: left;
          }

          th {
            color: #ffebee;
            font-weight: 600;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            font-size: 11px;
            white-space: nowrap;
          }

          tbody tr:nth-child(even) {
            background-color: rgba(24,0,6,0.95);
          }

          tbody tr:nth-child(odd) {
            background-color: rgba(18,0,4,0.95);
          }

          tbody tr:hover {
            background-color: rgba(74,20,40,0.9);
          }

          td {
            color: #ffebee;
            vertical-align: top;
          }

          .apikey-cell {
            font-family: "Fira Code", "JetBrains Mono", monospace;
            font-size: 12px;
            word-break: break-all;
          }

          .status-pill {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
          }

          .status-online {
            background-color: rgba(46, 125, 50, 0.2);
            color: #b9f6ca;
            border: 1px solid #2e7d32;
            box-shadow: 0 0 8px rgba(56,142,60,0.9);
          }

          .status-offline {
            background-color: rgba(183, 28, 28, 0.3);
            color: #ff8a80;
            border: 1px solid #d32f2f;
            box-shadow: 0 0 8px rgba(211,47,47,0.9);
          }

          .btn-delete {
            padding: 6px 12px;
            border-radius: 999px;
            background-image: linear-gradient(90deg, #f50057, #ff7043);
            color: #fff;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            box-shadow:
              0 4px 10px rgba(0,0,0,0.9),
              0 0 10px rgba(244,81,108,0.9);
            transition: transform 0.12s ease, box-shadow 0.12s ease, background-position 0.25s ease;
          }

          .btn-delete:hover {
            transform: translateY(-1px);
            box-shadow:
              0 6px 12px rgba(0,0,0,1),
              0 0 12px rgba(255,138,128,1);
          }

          .btn-delete:active {
            transform: translateY(1px) scale(0.97);
          }

          .empty-row {
            text-align: center;
            color: #ffcdd2;
          }

          @media (max-width: 900px) {
            .wrapper {
              padding: 18px 14px 18px;
              border-radius: 16px;
            }
            h1 {
              font-size: 20px;
            }
            table {
              font-size: 12px;
            }
            th, td {
              padding: 6px 6px;
            }
          }
        </style>
      </head>
      <body>
        <div class="page-shell">
          <div class="wrapper">
            <div class="wrapper-inner">
              <div class="top-bar">
                <div class="header-left">
                  <h1>Admin Dashboard</h1>
                  <p class="tagline">Monitor User & API Key Jackpot</p>
                </div>
                <form id="logoutForm" method="post" action="/admin/logout">
                  <button type="submit" class="btn btn-logout">Logout</button>
                </form>
              </div>

              <h2>Daftar User</h2>
              <div class="section-divider"></div>
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>First Name</th>
                    <th>Last Name</th>
                    <th>Email</th>
                  </tr>
                </thead>
                <tbody>
                  ${userRows || '<tr><td colspan="4" class="empty-row">Belum ada user.</td></tr>'}
                </tbody>
              </table>

              <h2>Daftar API Key & Status</h2>
              <div class="section-divider"></div>
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>API Key</th>
                    <th>User ID</th>
                    <th>is_active</th>
                    <th>created_at</th>
                    <th>last_used_at</th>
                    <th>out_of_date</th>
                    <th>Status</th>
                    <th>Aksi</th>
                  </tr>
                </thead>
                <tbody>
                  ${keyRows || '<tr><td colspan="9" class="empty-row">Belum ada API key.</td></tr>'}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <script>
          async function deleteApiKey(id) {
            const yakin = confirm('Yakin mau hapus API key dengan ID ' + id + '?');
            if (!yakin) return;

            try {
              const res = await fetch('/admin/apikey/' + id, {
                method: 'DELETE'
              });

              const data = await res.json();

              if (!res.ok) {
                throw new Error(data.error || 'Gagal menghapus API key');
              }

              alert('API key berhasil dihapus.');
              window.location.reload();
            } catch (err) {
              alert('Error: ' + err.message);
            }
          }
        </script>
      </body>
      </html>
    `;

    res.send(html);
  } catch (err) {
    console.error(err);
    res.status(500).send('Gagal memuat dashboard admin');
  }
});

// =============================
// 8. ADMIN: HAPUS API KEY
// =============================
app.delete('/admin/apikey/:id', isAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;

    // optional: validasi angka
    const apiKeyId = Number(id);
    if (!Number.isInteger(apiKeyId) || apiKeyId <= 0) {
      return res.status(400).json({ error: 'ID API key tidak valid' });
    }

    const [result] = await pool.execute(
      'DELETE FROM api_key WHERE id = ?',
      [apiKeyId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'API key tidak ditemukan' });
    }

    res.json({ message: 'API key berhasil dihapus' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal menghapus API key' });
  }
});

app.listen(port, () => {
  console.log(`Server berjalan di http://localhost:${port}`);
});
