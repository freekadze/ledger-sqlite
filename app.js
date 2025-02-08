// app.js
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const LineStrategy = require('passport-line').Strategy;
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;

// 從環境變數讀取設定
const LINE_CHANNEL_ID = process.env.LINE_CHANNEL_ID;
const LINE_CHANNEL_SECRET = process.env.LINE_CHANNEL_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL;
const SESSION_SECRET = process.env.SESSION_SECRET || 'your-session-secret';
const DATABASE_URL = process.env.DATABASE_URL; // Render 提供的 PostgreSQL 連線字串

// 建立 PostgreSQL 連線池，Render 部署時通常需要 ssl 設定
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// 初始化資料庫架構（使用 PostgreSQL 語法）
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        line_id TEXT UNIQUE,
        displayname TEXT
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ledger (
        id SERIAL PRIMARY KEY,
        name TEXT,
        owner TEXT,
        FOREIGN KEY (owner) REFERENCES users(line_id) ON DELETE SET NULL
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ledger_members (
        ledger_id INTEGER,
        user_id INTEGER,
        PRIMARY KEY (ledger_id, user_id),
        FOREIGN KEY (ledger_id) REFERENCES ledger(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        ledger_id INTEGER,
        payer INTEGER,
        amount NUMERIC,
        currency TEXT,
        description TEXT,
        creator INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (ledger_id) REFERENCES ledger(id) ON DELETE CASCADE,
        FOREIGN KEY (payer) REFERENCES users(id),
        FOREIGN KEY (creator) REFERENCES users(id)
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS transaction_splitters (
        transaction_id INTEGER,
        user_id INTEGER,
        PRIMARY KEY (transaction_id, user_id),
        FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ledger_invites (
        ledger_id INTEGER,
        token TEXT PRIMARY KEY,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        used INTEGER DEFAULT 0,
        FOREIGN KEY (ledger_id) REFERENCES ledger(id) ON DELETE CASCADE
      );
    `);
    console.log('Database schema created or verified.');
  } catch (err) {
    console.error('Error creating database schema:', err);
  }
})();

// ========== Passport 與 LINE Login 設定 ==========
passport.use(new LineStrategy({
  channelID: LINE_CHANNEL_ID,
  channelSecret: LINE_CHANNEL_SECRET,
  callbackURL: CALLBACK_URL,
  scope: ['profile']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const user = await getOrCreateUser(profile);
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  try {
    const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    const user = res.rows[0];
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ========== Express 與 Session 設定 ==========
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// 輔助函式：根據 LINE profile 取得或建立使用者
async function getOrCreateUser(profile) {
  const res = await pool.query('SELECT * FROM users WHERE line_id = $1', [profile.id]);
  if (res.rows.length > 0) {
    return res.rows[0];
  } else {
    const insertRes = await pool.query(
      'INSERT INTO users (line_id, displayname) VALUES ($1, $2) RETURNING *',
      [profile.id, profile.displayName]
    );
    return insertRes.rows[0];
  }
}

// Middleware：檢查是否登入
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

// ========== 路由設定 ==========

// 登入頁面（請自行建立 views/login.ejs，可參考簡單範例）
app.get('/login', (req, res) => {
  res.render('login', { message: null });
});

// 登出（passport v0.6+ 使用 callback 方式）
app.get('/logout', (req, res, next) => {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/login');
  });
});

// LINE Login 認證路由
app.get('/auth/line', passport.authenticate('line'));
app.get('/auth/line/callback',
  passport.authenticate('line', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/');
  }
);

// 首頁：顯示本人擁有的帳本與參與的帳本
app.get('/', ensureAuthenticated, async (req, res) => {
  try {
    const ownedRes = await pool.query('SELECT * FROM ledger WHERE owner = $1', [req.user.line_id]);
    const ownedLedgers = ownedRes.rows;
    const memberRes = await pool.query(`
      SELECT l.* FROM ledger l 
      JOIN ledger_members lm ON l.id = lm.ledger_id 
      WHERE lm.user_id = $1 AND l.owner <> $2
    `, [req.user.id, req.user.line_id]);
    const memberLedgers = memberRes.rows;
    res.render('index', { user: req.user, ownedLedgers, memberLedgers });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 建立新帳本（建立後自動加入建立者為成員）
app.post('/ledger', ensureAuthenticated, async (req, res) => {
  const ledgerName = req.body.ledgerName || 'Untitled Ledger';
  try {
    const ledgerRes = await pool.query(
      'INSERT INTO ledger (name, owner) VALUES ($1, $2) RETURNING id',
      [ledgerName, req.user.line_id]
    );
    const ledgerId = ledgerRes.rows[0].id;
    await pool.query('INSERT INTO ledger_members (ledger_id, user_id) VALUES ($1, $2)', [ledgerId, req.user.id]);
    res.redirect(`/ledger/${ledgerId}`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 【僅限 owner】建立邀請連結
app.post('/ledger/:id/invite', ensureAuthenticated, async (req, res) => {
  const ledgerId = req.params.id;
  try {
    const ledgerRes = await pool.query('SELECT * FROM ledger WHERE id = $1', [ledgerId]);
    const ledger = ledgerRes.rows[0];
    if (!ledger) return res.status(404).send('找不到該帳本');
    if (ledger.owner !== req.user.line_id) return res.status(403).send('只有帳本擁有者可以邀請新成員');
    
    const token = crypto.randomBytes(16).toString('hex');
    await pool.query('INSERT INTO ledger_invites (ledger_id, token) VALUES ($1, $2)', [ledgerId, token]);
    const inviteLink = `${req.protocol}://${req.get('host')}/ledger/invite?token=${token}`;
    res.redirect(`/ledger/${ledgerId}?inviteLink=${encodeURIComponent(inviteLink)}`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 處理邀請連結：驗證 token 並加入帳本
app.get('/ledger/invite', ensureAuthenticated, async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send('無效的邀請連結');
  try {
    const inviteRes = await pool.query('SELECT * FROM ledger_invites WHERE token = $1 AND used = 0', [token]);
    const invite = inviteRes.rows[0];
    if (!invite) return res.status(400).send('邀請連結無效或已使用。請點此 <a href="/ledger/' + invite.ledger_id + '">返回帳本</a>');
    
    const ledgerRes = await pool.query('SELECT * FROM ledger WHERE id = $1', [invite.ledger_id]);
    const ledger = ledgerRes.rows[0];
    if (ledger.owner === req.user.line_id) {
      return res.send('你是該帳本的擁有者，因此不需要使用邀請連結。');
    }
    
    const membershipRes = await pool.query('SELECT * FROM ledger_members WHERE ledger_id = $1 AND user_id = $2', [invite.ledger_id, req.user.id]);
    if (membershipRes.rows.length === 0) {
      await pool.query('INSERT INTO ledger_members (ledger_id, user_id) VALUES ($1, $2)', [invite.ledger_id, req.user.id]);
    }
    await pool.query('UPDATE ledger_invites SET used = 1 WHERE token = $1', [token]);
    res.send('已成功加入帳本。請點此 <a href="/ledger/' + invite.ledger_id + '">返回帳本</a>');
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 顯示帳本頁面（包含交易紀錄、成員管理等）
app.get('/ledger/:id', ensureAuthenticated, async (req, res) => {
  const ledgerId = req.params.id;
  try {
    const ledgerRes = await pool.query('SELECT * FROM ledger WHERE id = $1', [ledgerId]);
    const ledger = ledgerRes.rows[0];
    if (!ledger) return res.status(404).send('找不到該帳本');
    
    const membershipRes = await pool.query('SELECT * FROM ledger_members WHERE ledger_id = $1 AND user_id = $2', [ledgerId, req.user.id]);
    if (membershipRes.rows.length === 0) return res.status(403).send('你無權存取此帳本');
    
    // 查詢交易紀錄，利用 PostgreSQL 的 string_agg 彙整分攤人員
    const transactionsRes = await pool.query(`
      SELECT t.*, 
             p.displayname AS "payerName", 
             c.displayname AS "creatorName",
             COALESCE(string_agg(u.displayname, ', '), '') AS "splitPersons"
      FROM transactions t
      JOIN users p ON t.payer = p.id
      JOIN users c ON t.creator = c.id
      LEFT JOIN transaction_splitters ts ON t.id = ts.transaction_id
      LEFT JOIN users u ON ts.user_id = u.id
      WHERE t.ledger_id = $1
      GROUP BY t.id, p.displayname, c.displayname
      ORDER BY t.id ASC
    `, [ledgerId]);
    const transactions = transactionsRes.rows;
    
    const membersRes = await pool.query(`
      SELECT u.* FROM users u 
      JOIN ledger_members lm ON u.id = lm.user_id 
      WHERE lm.ledger_id = $1
    `, [ledgerId]);
    const members = membersRes.rows;
    
    const allUsersRes = await pool.query('SELECT * FROM users');
    const allUsers = allUsersRes.rows;
    
    const inviteLink = req.query.inviteLink;
    
    res.render('ledger', {
      ledger,
      ledgerId,
      transactions,
      members,
      allUsers,
      user: req.user,
      inviteLink
    });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 【僅限 owner】刪除帳本
app.post('/ledger/:id/delete', ensureAuthenticated, async (req, res) => {
  const ledgerId = req.params.id;
  try {
    const ledgerRes = await pool.query('SELECT * FROM ledger WHERE id = $1', [ledgerId]);
    const ledger = ledgerRes.rows[0];
    if (!ledger) return res.status(404).send('找不到該帳本');
    if (ledger.owner !== req.user.line_id) return res.status(403).send('只有帳本擁有者才能刪除帳本');
    
    // 由於外鍵 ON DELETE CASCADE，可直接刪除帳本
    await pool.query('DELETE FROM ledger WHERE id = $1', [ledgerId]);
    res.redirect('/');
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 新增交易（包含分攤人員選擇）
app.post('/ledger/:id/transaction', ensureAuthenticated, async (req, res) => {
  const ledgerId = req.params.id;
  const { payer, amount, currency, description, created_at } = req.body;
  let splitters = req.body.splitters;
  if (!Array.isArray(splitters)) {
    splitters = splitters ? [splitters] : [];
  }
  try {
    const ledgerRes = await pool.query('SELECT * FROM ledger WHERE id = $1', [ledgerId]);
    const ledger = ledgerRes.rows[0];
    if (!ledger) return res.status(404).send('找不到該帳本');
    const membershipRes = await pool.query('SELECT * FROM ledger_members WHERE ledger_id = $1 AND user_id = $2', [ledgerId, req.user.id]);
    if (membershipRes.rows.length === 0) return res.status(403).send('你無權存取此帳本');
    
    let transactionRes;
    if (created_at && created_at.trim() !== "") {
      const formattedCreatedAt = created_at.replace('T', ' ');
      transactionRes = await pool.query(
        'INSERT INTO transactions (ledger_id, payer, amount, currency, description, creator, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
        [ledgerId, payer, parseFloat(amount), currency, description, req.user.id, formattedCreatedAt]
      );
    } else {
      transactionRes = await pool.query(
        'INSERT INTO transactions (ledger_id, payer, amount, currency, description, creator) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
        [ledgerId, payer, parseFloat(amount), currency, description, req.user.id]
      );
    }
    const transactionId = transactionRes.rows[0].id;
    for (let userId of splitters) {
      await pool.query('INSERT INTO transaction_splitters (transaction_id, user_id) VALUES ($1, $2)', [transactionId, userId]);
    }
    res.redirect(`/ledger/${ledgerId}`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 【僅限交易建立者】刪除交易
app.post('/ledger/:ledgerId/transaction/:transactionId/delete', ensureAuthenticated, async (req, res) => {
  const { ledgerId, transactionId } = req.params;
  try {
    const txRes = await pool.query('SELECT * FROM transactions WHERE id = $1', [transactionId]);
    const transaction = txRes.rows[0];
    if (!transaction) return res.status(404).send('找不到該交易');
    if (transaction.creator !== req.user.id) return res.status(403).send('只有該交易的建立者才能刪除');
    await pool.query('DELETE FROM transaction_splitters WHERE transaction_id = $1', [transactionId]);
    await pool.query('DELETE FROM transactions WHERE id = $1', [transactionId]);
    res.redirect(`/ledger/${ledgerId}`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 分帳結算（GET）：以 TWD 為基準轉換各交易金額並計算
app.get('/ledger/:id/settle', ensureAuthenticated, async (req, res) => {
  const ledgerId = req.params.id;
  try {
    const ledgerRes = await pool.query('SELECT * FROM ledger WHERE id = $1', [ledgerId]);
    const ledger = ledgerRes.rows[0];
    if (!ledger) return res.status(404).send('找不到該帳本');
    const membershipRes = await pool.query('SELECT * FROM ledger_members WHERE ledger_id = $1 AND user_id = $2', [ledgerId, req.user.id]);
    if (membershipRes.rows.length === 0) return res.status(403).send('你無權存取此帳本');
    
    const txRes = await pool.query('SELECT * FROM transactions WHERE ledger_id = $1', [ledgerId]);
    const transactions = txRes.rows;
    
    const RATE_API_URL = 'https://open.er-api.com/v6/latest/TWD';
    const rateResponse = await axios.get(RATE_API_URL);
    let rates = rateResponse.data.rates;
    rates.TWD = 1;
    
    const membersRes = await pool.query(`
      SELECT u.* FROM users u 
      JOIN ledger_members lm ON u.id = lm.user_id 
      WHERE lm.ledger_id = $1
    `, [ledgerId]);
    const members = membersRes.rows;
    
    const payments = {};
    members.forEach(m => { payments[m.id] = 0; });
    transactions.forEach(tx => {
      const rate = rates[tx.currency] || 1;
      const amountTWD = parseFloat(tx.amount) / rate;
      payments[tx.payer] = (payments[tx.payer] || 0) + amountTWD;
    });
    
    // 建立 transaction_splitters 映射：transaction_id => [user_id,...]
    const splitterRes = await pool.query('SELECT * FROM transaction_splitters');
    const splitterMap = {};
    splitterRes.rows.forEach(s => {
      if (!splitterMap[s.transaction_id]) {
        splitterMap[s.transaction_id] = [];
      }
      splitterMap[s.transaction_id].push(s.user_id);
    });
    
    const shares = {};
    members.forEach(m => { shares[m.id] = 0; });
    transactions.forEach(tx => {
      const splitterIds = splitterMap[tx.id] || [];
      const involved = splitterIds.length ? splitterIds : [tx.payer];
      const rate = rates[tx.currency] || 1;
      const amountTWD = parseFloat(tx.amount) / rate;
      const avg = amountTWD / involved.length;
      involved.forEach(uid => {
        shares[uid] = (shares[uid] || 0) + avg;
      });
    });
    
    const net = {};
    members.forEach(m => {
      net[m.id] = payments[m.id] - shares[m.id];
    });
    
    const debtors = [];
    const creditors = [];
    members.forEach(m => {
      const diff = parseFloat(net[m.id].toFixed(2));
      // 這裡改用 m.displayname（小寫）以正確取得名稱
      if (diff < 0) {
        debtors.push({ id: m.id, displayName: m.displayname, amount: -diff });
      } else if (diff > 0) {
        creditors.push({ id: m.id, displayName: m.displayname, amount: diff });
      }
    });
    
    const settlements = [];
    let i = 0, j = 0;
    while (i < debtors.length && j < creditors.length) {
      const debtor = debtors[i];
      const creditor = creditors[j];
      const payAmount = Math.min(debtor.amount, creditor.amount);
      settlements.push({
        from: debtor.displayName,
        to: creditor.displayName,
        amount: parseFloat(payAmount.toFixed(2))
      });
      debtor.amount -= payAmount;
      creditor.amount -= payAmount;
      if (Math.abs(debtor.amount) < 0.01) i++;
      if (Math.abs(creditor.amount) < 0.01) j++;
    }
    
    const totalAmountTWD = transactions.reduce((sum, tx) => {
      const rate = rates[tx.currency] || 1;
      return sum + (parseFloat(tx.amount) / rate);
    }, 0);
    
    res.render('settlement', {
      ledger,
      ledgerId,
      members,
      settlements,
      totalAmount: totalAmountTWD.toFixed(2),
      payments,
      rates
    });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 分帳結算（POST）：處理使用者修改匯率後重新計算
app.post('/ledger/:id/settle', ensureAuthenticated, async (req, res) => {
  const ledgerId = req.params.id;
  try {
    const ledgerRes = await pool.query('SELECT * FROM ledger WHERE id = $1', [ledgerId]);
    const ledger = ledgerRes.rows[0];
    if (!ledger) return res.status(404).send('找不到該帳本');
    const membershipRes = await pool.query('SELECT * FROM ledger_members WHERE ledger_id = $1 AND user_id = $2', [ledgerId, req.user.id]);
    if (membershipRes.rows.length === 0) return res.status(403).send('你無權存取此帳本');
    
    const txRes = await pool.query('SELECT * FROM transactions WHERE ledger_id = $1', [ledgerId]);
    const transactions = txRes.rows;
    
    const RATE_API_URL = 'https://open.er-api.com/v6/latest/TWD';
    const rateResponse = await axios.get(RATE_API_URL);
    let rates = rateResponse.data.rates;
    rates.TWD = 1;
    
    // 依照表單更新匯率
    for (const key in req.body) {
      if (key.startsWith('rate_')) {
        const cur = key.replace('rate_', '');
        const newRate = parseFloat(req.body[key]);
        if (!isNaN(newRate) && newRate > 0) {
          rates[cur] = newRate;
        }
      }
    }
    
    const membersRes = await pool.query(`
      SELECT u.* FROM users u 
      JOIN ledger_members lm ON u.id = lm.user_id 
      WHERE lm.ledger_id = $1
    `, [ledgerId]);
    const members = membersRes.rows;
    
    const payments = {};
    members.forEach(m => { payments[m.id] = 0; });
    transactions.forEach(tx => {
      const rate = rates[tx.currency] || 1;
      const amountTWD = parseFloat(tx.amount) / rate;
      payments[tx.payer] = (payments[tx.payer] || 0) + amountTWD;
    });
    
    const splitterRes = await pool.query('SELECT * FROM transaction_splitters');
    const splitterMap = {};
    splitterRes.rows.forEach(s => {
      if (!splitterMap[s.transaction_id]) {
        splitterMap[s.transaction_id] = [];
      }
      splitterMap[s.transaction_id].push(s.user_id);
    });
    
    const shares = {};
    members.forEach(m => { shares[m.id] = 0; });
    transactions.forEach(tx => {
      const splitterIds = splitterMap[tx.id] || [];
      const involved = splitterIds.length ? splitterIds : [tx.payer];
      const rate = rates[tx.currency] || 1;
      const amountTWD = parseFloat(tx.amount) / rate;
      const avg = amountTWD / involved.length;
      involved.forEach(uid => {
        shares[uid] = (shares[uid] || 0) + avg;
      });
    });
    
    const net = {};
    members.forEach(m => {
      net[m.id] = payments[m.id] - shares[m.id];
    });
    
    const debtors = [];
    const creditors = [];
    members.forEach(m => {
      const diff = parseFloat(net[m.id].toFixed(2));
      // 改用 m.displayname 以正確取得名稱
      if (diff < 0) {
        debtors.push({ id: m.id, displayName: m.displayname, amount: -diff });
      } else if (diff > 0) {
        creditors.push({ id: m.id, displayName: m.displayname, amount: diff });
      }
    });
    
    const settlements = [];
    let i = 0, j = 0;
    while (i < debtors.length && j < creditors.length) {
      const debtor = debtors[i];
      const creditor = creditors[j];
      const payAmount = Math.min(debtor.amount, creditor.amount);
      settlements.push({
        from: debtor.displayName,
        to: creditor.displayName,
        amount: parseFloat(payAmount.toFixed(2))
      });
      debtor.amount -= payAmount;
      creditor.amount -= payAmount;
      if (Math.abs(debtor.amount) < 0.01) i++;
      if (Math.abs(creditor.amount) < 0.01) j++;
    }
    
    const totalAmountTWD = transactions.reduce((sum, tx) => {
      const rate = rates[tx.currency] || 1;
      return sum + (parseFloat(tx.amount) / rate);
    }, 0);
    
    res.render('settlement', {
      ledger,
      ledgerId,
      members,
      settlements,
      totalAmount: totalAmountTWD.toFixed(2),
      payments,
      rates
    });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 啟動伺服器
app.listen(port, () => {
  console.log(`帳本 App 已啟動，請至 http://localhost:${port}`);
});
