// app.js
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const LineStrategy = require('passport-line').Strategy;
const axios = require('axios');
const path = require('path');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const crypto = require('crypto'); // 用於產生隨機 token

const app = express();
const port = 3000;

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

// ========== Passport 與 LINE Login 設定 ==========
const LINE_CHANNEL_ID = process.env.LINE_CHANNEL_ID;
const LINE_CHANNEL_SECRET = process.env.LINE_CHANNEL_SECRET;
// 注意：這邊可以設定預設值，但建議在 Render 上以環境變數傳入正確值
const CALLBACK_URL = process.env.CALLBACK_URL ;

passport.use(new LineStrategy({
  channelID: LINE_CHANNEL_ID,
  channelSecret: LINE_CHANNEL_SECRET,
  callbackURL: CALLBACK_URL,
  scope: ['profile']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // 使用 profile.id 作為 LINE ID
    const user = await getOrCreateUser(profile);
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// 序列化/反序列化使用者
passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  try {
    const user = await db.get('SELECT * FROM users WHERE id = ?', id);
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
  secret: 'your-session-secret',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// ========== 資料庫初始化 ==========
let db;
(async () => {
  db = await open({
    filename: './ledger.db',
    driver: sqlite3.Database
  });
  // 使用者資料表
  await db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      line_id TEXT UNIQUE,
      displayName TEXT
    )
  `);
  // 帳本（ledger）表，owner 改為 TEXT，存放使用者的 LINE ID
  await db.run(`
    CREATE TABLE IF NOT EXISTS ledger (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      owner TEXT,
      FOREIGN KEY(owner) REFERENCES users(line_id)
    )
  `);
  // 帳本成員（ledger_members）
  await db.run(`
    CREATE TABLE IF NOT EXISTS ledger_members (
      ledger_id INTEGER,
      user_id INTEGER,
      PRIMARY KEY(ledger_id, user_id),
      FOREIGN KEY(ledger_id) REFERENCES ledger(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
  // 交易記錄（transactions），新增 created_at 欄位，預設 CURRENT_TIMESTAMP
  await db.run(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ledger_id INTEGER,
      payer INTEGER,
      amount REAL,
      currency TEXT,
      description TEXT,
      creator INTEGER,
      created_at DATETIME DEFAULT (datetime('now', 'localtime')),
      FOREIGN KEY(ledger_id) REFERENCES ledger(id),
      FOREIGN KEY(payer) REFERENCES users(id),
      FOREIGN KEY(creator) REFERENCES users(id)
    )
  `);
  // 記錄哪些使用者參與該筆交易的分帳
  await db.run(`
    CREATE TABLE IF NOT EXISTS transaction_splitters (
      transaction_id INTEGER,
      user_id INTEGER,
      PRIMARY KEY(transaction_id, user_id),
      FOREIGN KEY(transaction_id) REFERENCES transactions(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
  // 帳本邀請表，用來記錄邀請連結，避免隨意加入
  await db.run(`
    CREATE TABLE IF NOT EXISTS ledger_invites (
      ledger_id INTEGER,
      token TEXT PRIMARY KEY,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      used INTEGER DEFAULT 0,
      FOREIGN KEY(ledger_id) REFERENCES ledger(id)
    )
  `);
})();

// 輔助函式：取得或建立使用者（以 LINE ID 為唯一識別）
async function getOrCreateUser(profile) {
  let user = await db.get('SELECT * FROM users WHERE line_id = ?', profile.id);
  if (!user) {
    const result = await db.run(
      'INSERT INTO users (line_id, displayName) VALUES (?, ?)', 
      profile.id, 
      profile.displayName
    );
    user = { id: result.lastID, line_id: profile.id, displayName: profile.displayName };
  }
  return user;
}

// Middleware：檢查是否登入
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

// ========== 路由設定 ==========

// 登入頁面
app.get('/login', (req, res) => {
  res.render('login');
});

// 登出
app.get('/logout', (req, res) => {
  req.logout(() => {
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
    // 查詢 owner 為本人（以 LINE ID 存放）的帳本
    const ownedLedgers = await db.all('SELECT * FROM ledger WHERE owner = ?', req.user.line_id);
    const memberLedgers = await db.all(`
      SELECT l.* FROM ledger l 
      JOIN ledger_members lm ON l.id = lm.ledger_id 
      WHERE lm.user_id = ? AND l.owner <> ?
    `, req.user.id, req.user.id);
    res.render('index', { user: req.user, ownedLedgers, memberLedgers });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 建立新帳本（登入者可建立，新建後自動加入成員）
// 注意：owner 欄位存入的是使用者的 LINE ID
app.post('/ledger', ensureAuthenticated, async (req, res) => {
  const ledgerName = req.body.ledgerName || 'Untitled Ledger';
  try {
    const result = await db.run('INSERT INTO ledger (name, owner) VALUES (?, ?)', ledgerName, req.user.line_id);
    const ledgerId = result.lastID;
    // 自動將 owner（登入者）加入該帳本成員
    await db.run('INSERT INTO ledger_members (ledger_id, user_id) VALUES (?, ?)', ledgerId, req.user.id);
    res.redirect(`/ledger/${ledgerId}`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 【僅限 owner】建立邀請連結（用於邀請新成員加入帳本）
app.post('/ledger/:id/invite', ensureAuthenticated, async (req, res) => {
  const ledgerId = req.params.id;
  try {
    const ledger = await db.get('SELECT * FROM ledger WHERE id = ?', ledgerId);
    if (!ledger) return res.status(404).send('找不到該帳本');
    if (ledger.owner !== req.user.line_id) return res.status(403).send('只有帳本擁有者可以邀請新成員');

    // 產生一個隨機 token
    const token = crypto.randomBytes(16).toString('hex');
    await db.run('INSERT INTO ledger_invites (ledger_id, token) VALUES (?, ?)', ledgerId, token);

    // 產生邀請連結（這裡使用完整網址，可依實際部署情況調整）
    const inviteLink = `${req.protocol}://${req.get('host')}/ledger/invite?token=${token}`;
    res.redirect(`/ledger/${ledgerId}?inviteLink=${encodeURIComponent(inviteLink)}`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 處理邀請連結：被邀請人點擊後，驗證 token 並加入帳本
app.get('/ledger/invite', ensureAuthenticated, async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send('無效的邀請連結');
  try {
    const invite = await db.get('SELECT * FROM ledger_invites WHERE token = ? AND used = 0', token);
    if (!invite) return res.status(400).send('邀請連結無效或已使用。請點此 <a href="/ledger/' + invite.ledger_id + '">返回帳本</a>');

    // 取得該帳本資訊
    const ledger = await db.get('SELECT * FROM ledger WHERE id = ?', invite.ledger_id);
    // 如果點擊者是該帳本擁有者，則視同未使用邀請連結
    if (ledger.owner === req.user.line_id) {
      return res.send('你是該帳本的擁有者，因此不需要使用邀請連結。');
    }

    // 若該使用者尚未加入帳本，則加入成員
    const membership = await db.get('SELECT * FROM ledger_members WHERE ledger_id = ? AND user_id = ?', invite.ledger_id, req.user.id);
    if (!membership) {
      await db.run('INSERT INTO ledger_members (ledger_id, user_id) VALUES (?, ?)', invite.ledger_id, req.user.id);
    }
    // 標記邀請連結為已使用
    await db.run('UPDATE ledger_invites SET used = 1 WHERE token = ?', token);
    res.send('已成功加入帳本。請點此 <a href="/ledger/' + invite.ledger_id + '">返回帳本</a>');
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 顯示帳本頁面，包含交易記錄與成員管理（僅 owner 可管理成員）
app.get('/ledger/:id', ensureAuthenticated, async (req, res) => {
  const ledgerId = req.params.id;
  try {
    const ledger = await db.get('SELECT * FROM ledger WHERE id = ?', ledgerId);
    if (!ledger) return res.status(404).send('找不到該帳本');

    // 檢查該使用者是否為該帳本成員（owner 或被加入）
    const isMember = await db.get('SELECT * FROM ledger_members WHERE ledger_id = ? AND user_id = ?', ledgerId, req.user.id);
    if (!isMember) return res.status(403).send('你無權存取此帳本');

    // 查詢交易：取得付款人、建立者與分帳人（利用 GROUP_CONCAT 取得分帳人姓名）
    const transactions = await db.all(`
      SELECT t.*, 
             p.displayName AS payerName, 
             c.displayName AS creatorName,
             GROUP_CONCAT(u.displayName, ', ') AS splitPersons
      FROM transactions t
      JOIN users p ON t.payer = p.id
      JOIN users c ON t.creator = c.id
      LEFT JOIN transaction_splitters ts ON t.id = ts.transaction_id
      LEFT JOIN users u ON ts.user_id = u.id
      WHERE t.ledger_id = ?
      GROUP BY t.id
      ORDER BY t.id ASC
    `, ledgerId);
    
    // 查詢該帳本的成員（用於新增交易時選擇分帳人員、owner 管理成員）
    const members = await db.all(`
      SELECT u.* FROM users u 
      JOIN ledger_members lm ON u.id = lm.user_id 
      WHERE lm.ledger_id = ?
    `, ledgerId);

    // 查詢系統中所有使用者（供 owner 加入新成員使用，目前已由邀請方式取代）
    const allUsers = await db.all('SELECT * FROM users');

    // 若有邀請連結參數，取出後傳遞到頁面顯示
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
    const ledger = await db.get('SELECT * FROM ledger WHERE id = ?', ledgerId);
    if (!ledger) return res.status(404).send('找不到該帳本');
    if (ledger.owner !== req.user.line_id) return res.status(403).send('只有帳本擁有者才能刪除帳本');
    // 刪除相關資料：分帳紀錄、交易、成員，再刪除帳本
    await db.run('DELETE FROM transaction_splitters WHERE transaction_id IN (SELECT id FROM transactions WHERE ledger_id = ?)', ledgerId);
    await db.run('DELETE FROM transactions WHERE ledger_id = ?', ledgerId);
    await db.run('DELETE FROM ledger_members WHERE ledger_id = ?', ledgerId);
    await db.run('DELETE FROM ledger WHERE id = ?', ledgerId);
    res.redirect('/');
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 新增交易紀錄（包含分帳人員選項），支援使用者自訂交易時間
app.post('/ledger/:id/transaction', ensureAuthenticated, async (req, res) => {
  const ledgerId = req.params.id;
  const { payer, amount, currency, description, created_at } = req.body;
  let splitters = req.body.splitters;
  if (!Array.isArray(splitters)) {
    splitters = splitters ? [splitters] : [];
  }
  try {
    const ledger = await db.get('SELECT * FROM ledger WHERE id = ?', ledgerId);
    if (!ledger) return res.status(404).send('找不到該帳本');
    const isMember = await db.get('SELECT * FROM ledger_members WHERE ledger_id = ? AND user_id = ?', ledgerId, req.user.id);
    if (!isMember) return res.status(403).send('你無權存取此帳本');

    if (created_at && created_at.trim() !== "") {
      // 使用 datetime-local 格式，前端格式通常為 "YYYY-MM-DDTHH:MM" 或 "YYYY-MM-DDTHH:MM:SS"
      // 轉換成 "YYYY-MM-DD HH:MM:SS" 格式，若沒有秒則補上 ":00"
      let formattedCreatedAt = created_at.replace('T', ' ');
      if (formattedCreatedAt.length === 16) {
        formattedCreatedAt += ":00";
      }
      await db.run(
        'INSERT INTO transactions (ledger_id, payer, amount, currency, description, creator, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        ledgerId, payer, parseFloat(amount), currency, description, req.user.id, formattedCreatedAt
      );
    } else {
      await db.run(
        'INSERT INTO transactions (ledger_id, payer, amount, currency, description, creator) VALUES (?, ?, ?, ?, ?, ?)',
        ledgerId, payer, parseFloat(amount), currency, description, req.user.id
      );
    }
    const transactionId = (await db.get('SELECT last_insert_rowid() as id')).id;
    for (let userId of splitters) {
      await db.run('INSERT INTO transaction_splitters (transaction_id, user_id) VALUES (?, ?)', transactionId, userId);
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
    const transaction = await db.get('SELECT * FROM transactions WHERE id = ?', transactionId);
    if (!transaction) return res.status(404).send('找不到該交易');
    if (transaction.creator !== req.user.id) return res.status(403).send('只有該交易的建立者才能刪除');
    await db.run('DELETE FROM transaction_splitters WHERE transaction_id = ?', transactionId);
    await db.run('DELETE FROM transactions WHERE id = ?', transactionId);
    res.redirect(`/ledger/${ledgerId}`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// 分帳結算功能：以 TWD 為基準轉換所有交易，再進行計算
app.get('/ledger/:id/settle', ensureAuthenticated, async (req, res) => {
  const ledgerId = req.params.id;
  try {
    const ledger = await db.get('SELECT * FROM ledger WHERE id = ?', ledgerId);
    if (!ledger) return res.status(404).send('找不到該帳本');
    const isMember = await db.get('SELECT * FROM ledger_members WHERE ledger_id = ? AND user_id = ?', ledgerId, req.user.id);
    if (!isMember) return res.status(403).send('你無權存取此帳本');

    const transactions = await db.all('SELECT * FROM transactions WHERE ledger_id = ?', ledgerId);

    // 取得最新匯率資料（以 TWD 為基準）
    const RATE_API_URL = 'https://open.er-api.com/v6/latest/TWD';
    const rateResponse = await axios.get(RATE_API_URL);
    const rates = rateResponse.data.rates;
    rates.TWD = 1;

    const members = await db.all(`
      SELECT u.* FROM users u 
      JOIN ledger_members lm ON u.id = lm.user_id 
      WHERE lm.ledger_id = ?
    `, ledgerId);

    const payments = {};
    members.forEach(m => { payments[m.id] = 0; });
    transactions.forEach(tx => {
      const rate = rates[tx.currency] || 1;
      const amountTWD = tx.amount / rate;
      payments[tx.payer] = (payments[tx.payer] || 0) + amountTWD;
    });

    const splitterMap = {};
    const splitters = await db.all('SELECT * FROM transaction_splitters');
    splitters.forEach(s => {
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
      const amountTWD = tx.amount / rate;
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
      if (diff < 0) {
        debtors.push({ id: m.id, displayName: m.displayName, amount: -diff });
      } else if (diff > 0) {
        creditors.push({ id: m.id, displayName: m.displayName, amount: diff });
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
      return sum + (tx.amount / rate);
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

// 處理使用者修改匯率後重新計算結算結果
app.post('/ledger/:id/settle', ensureAuthenticated, async (req, res) => {
  const ledgerId = req.params.id;
  try {
    const ledger = await db.get('SELECT * FROM ledger WHERE id = ?', ledgerId);
    if (!ledger) return res.status(404).send('找不到該帳本');
    const isMember = await db.get('SELECT * FROM ledger_members WHERE ledger_id = ? AND user_id = ?', ledgerId, req.user.id);
    if (!isMember) return res.status(403).send('你無權存取此帳本');

    const transactions = await db.all('SELECT * FROM transactions WHERE ledger_id = ?', ledgerId);

    const RATE_API_URL = 'https://open.er-api.com/v6/latest/TWD';
    const rateResponse = await axios.get(RATE_API_URL);
    let rates = rateResponse.data.rates;
    rates.TWD = 1;

    for (const key in req.body) {
      if (key.startsWith('rate_')) {
        const cur = key.replace('rate_', '');
        const newRate = parseFloat(req.body[key]);
        if (!isNaN(newRate) && newRate > 0) {
          rates[cur] = newRate;
        }
      }
    }

    const members = await db.all(`
      SELECT u.* FROM users u 
      JOIN ledger_members lm ON u.id = lm.user_id 
      WHERE lm.ledger_id = ?
    `, ledgerId);

    const payments = {};
    members.forEach(m => { payments[m.id] = 0; });
    transactions.forEach(tx => {
      const rate = rates[tx.currency] || 1;
      const amountTWD = tx.amount / rate;
      payments[tx.payer] = (payments[tx.payer] || 0) + amountTWD;
    });

    const splitterMap = {};
    const splitters = await db.all('SELECT * FROM transaction_splitters');
    splitters.forEach(s => {
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
      const amountTWD = tx.amount / rate;
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
      if (diff < 0) {
        debtors.push({ id: m.id, displayName: m.displayName, amount: -diff });
      } else if (diff > 0) {
        creditors.push({ id: m.id, displayName: m.displayName, amount: diff });
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
      return sum + (tx.amount / rate);
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
