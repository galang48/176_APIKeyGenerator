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
    secret: process.env.SESSION_SECRET || 'dev-secret-166-apikey',
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

    // bikin HTML sederhana
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
          <td>${k.api_key}</td>
          <td>${k.user_id || '-'}</td>
          <td>${k.is_active ? '1' : '0'}</td>
          <td>${k.created_at || '-'}</td>
          <td>${k.last_used_at || '-'}</td>
          <td>${k.out_of_date || '-'}</td>
          <td class="${statusClass}">${status}</td>
          <td>
            <button type="button" onclick="deleteApiKey(${k.id})">
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
          body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
          }
          .wrapper {
            max-width: 1100px;
            margin: 20px auto;
            background: #ffffff;
            border-radius: 10px;
            padding: 20px 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
          }
          h1, h2 {
            margin-top: 0;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            margin-bottom: 20px;
            font-size: 14px;
          }
          th, td {
            border: 1px solid #ddd;
            padding: 8px;
          }
          th {
            background-color: #f0f0f0;
          }
          .status-online {
            color: green;
            font-weight: bold;
          }
          .status-offline {
            color: red;
            font-weight: bold;
          }
          .top-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
          }
          button {
            padding: 6px 12px;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            background-color: #ff4081;
            color: #fff;
          }
        </style>
      </head>
      <body>
        <div class="wrapper">
          <div class="top-bar">
            <h1>Admin Dashboard</h1>
            <form id="logoutForm" method="post" action="/admin/logout">
              <button type="submit">Logout</button>
            </form>
          </div>

          <h2>Daftar User</h2>
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
              ${userRows || '<tr><td colspan="4">Belum ada user.</td></tr>'}
            </tbody>
          </table>

          <h2>Daftar API Key & Status</h2>
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
              ${keyRows || '<tr><td colspan="9">Belum ada API key.</td></tr>'}
            </tbody>
          </table>
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