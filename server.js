'use strict';
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const required = ['DATABASE_URL','SESSION_SECRET','DISCORD_CLIENT_ID','DISCORD_CLIENT_SECRET','DISCORD_REDIRECT_URI'];
for (const key of required) if (!process.env[key]) { console.error(`Missing required environment variable: ${key}`); process.exit(1); }
if (process.env.SESSION_SECRET.length < 32) { console.error('SESSION_SECRET must be at least 32 characters.'); process.exit(1); }
const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false } });
const ROLES = ['Администратор','Куратор','Мастер','Саппорт'];
const PORT = Number(process.env.PORT || 3000);
const prod = process.env.NODE_ENV === 'production';
if (prod) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(session({
  name: 'vyshka.sid',
  store: new PgSession({ pool, tableName: 'oauth_sessions', createTableIfMissing: true, pruneSessionInterval: 15 * 60 }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, secure: prod, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
}));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const mutationLimiter = rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: true, legacyHeaders: false });

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS whitelist_users (
    discord_id VARCHAR(20) PRIMARY KEY, username TEXT, global_name TEXT, avatar_url TEXT,
    role TEXT NOT NULL CHECK (role IN ('Администратор','Куратор','Мастер','Саппорт')),
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS oauth_sessions (sid VARCHAR NOT NULL PRIMARY KEY, sess JSON NOT NULL, expire TIMESTAMP(6) NOT NULL)`);
  await pool.query('CREATE INDEX IF NOT EXISTS oauth_sessions_expire_idx ON oauth_sessions (expire)');
  const bootstrap = String(process.env.BOOTSTRAP_ADMIN_DISCORD_ID || '').trim();
  if (/^\d{17,20}$/.test(bootstrap)) {
    await pool.query(`INSERT INTO whitelist_users (discord_id, role) VALUES ($1, 'Администратор') ON CONFLICT (discord_id) DO NOTHING`, [bootstrap]);
    console.log('Explicit bootstrap admin ID checked; existing role was not overwritten.');
  }
}
function pageShell(title, message, buttonLabel, buttonHref, danger = false) {
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>
  :root{color-scheme:dark;--bg:#070b18;--panel:#0e152b;--line:rgba(100,139,255,.25);--text:#f1f5ff;--muted:#9aa9cc;--accent:#4c8dff;--purple:#a879ff}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:radial-gradient(ellipse at top,#14244a,#070b18 60%);color:var(--text);font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}.card{width:min(460px,100%);padding:30px;border:1px solid var(--line);border-radius:24px;background:rgba(14,21,43,.96);box-shadow:0 20px 70px #0006;text-align:center}.logo{font-size:42px}.muted{color:var(--muted)}h1{font-size:25px;margin:12px 0}p{margin:12px 0 22px}.btn{display:block;width:100%;padding:13px 16px;border-radius:12px;background:linear-gradient(110deg,var(--accent),var(--purple));color:white;text-decoration:none;font-weight:800;border:0;cursor:pointer}.btn.alt{background:#202d4e;border:1px solid var(--line)}.warn{color:#ff9bad}.small{font-size:12px;margin-top:18px;color:var(--muted)}
  </style></head><body><main class="card"><div class="logo">🐰</div><h1>${title}</h1><p class="${danger?'warn':'muted'}">${message}</p><a class="btn ${danger?'alt':''}" href="${buttonHref}">${buttonLabel}</a><div class="small">Вышка саппортов · защищённый вход</div></main></body></html>`;
}
function isAllowedPathAsset(p) { return p.startsWith('/assets/') && !p.includes('..'); }
app.use('/assets', (req,res,next) => { if (req.path.includes('..')) return res.sendStatus(404); next(); }, express.static(path.join(__dirname, 'assets'), { fallthrough: false }));
app.get('/auth/discord', authLimiter, (req,res) => {
  const state = crypto.randomBytes(32).toString('hex');
  req.session.oauthState = state;
  req.session.deniedUser = null;
  const url = new URL('https://discord.com/oauth2/authorize');
  url.searchParams.set('client_id', process.env.DISCORD_CLIENT_ID);
  url.searchParams.set('redirect_uri', process.env.DISCORD_REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'identify');
  url.searchParams.set('state', state);
  res.redirect(url.toString());
});
app.get('/auth/callback', authLimiter, async (req,res) => {
  const state = String(req.query.state || '');
  const expected = req.session.oauthState;
  delete req.session.oauthState; // one-time state, even on failure
  if (!expected || !state || Buffer.byteLength(state)!==Buffer.byteLength(expected) || !crypto.timingSafeEqual(Buffer.from(state), Buffer.from(expected))) return res.status(400).send(pageShell('Не удалось войти','Проверка безопасности не пройдена. Начни вход заново.','Вернуться ко входу','/'));
  if (req.query.error || !req.query.code) return res.redirect('/');
  try {
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST', headers: { 'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json' },
      body: new URLSearchParams({ client_id:process.env.DISCORD_CLIENT_ID, client_secret:process.env.DISCORD_CLIENT_SECRET, grant_type:'authorization_code', code:String(req.query.code), redirect_uri:process.env.DISCORD_REDIRECT_URI })
    });
    const token = await tokenResponse.json();
    if (!tokenResponse.ok || !token.access_token) throw new Error('Discord token exchange failed');
    const userResponse = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${token.access_token}` } });
    const user = await userResponse.json();
    if (!userResponse.ok || !/^\d{17,20}$/.test(String(user.id || ''))) throw new Error('Discord profile could not be verified');
    const found = await pool.query('SELECT discord_id, username, global_name, avatar_url, role FROM whitelist_users WHERE discord_id=$1', [user.id]);
    if (!found.rowCount) {
      await new Promise((resolve,reject)=>req.session.regenerate(err=>err?reject(err):resolve()));
      req.session.deniedUser = { id:user.id, username:user.global_name || user.username || 'Discord пользователь' };
      req.session.csrf = crypto.randomBytes(32).toString('hex');
      return req.session.save(err=>err?res.status(500).send('Session error'):res.redirect('/'));
    }
    const avatarUrl = user.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${user.avatar.startsWith('a_')?'gif':'png'}?size=128` : null;
    await pool.query('UPDATE whitelist_users SET username=$2, global_name=$3, avatar_url=$4, updated_at=NOW() WHERE discord_id=$1', [user.id, user.username, user.global_name || null, avatarUrl]);
    await new Promise((resolve,reject)=>req.session.regenerate(err=>err?reject(err):resolve()));
    req.session.userId = user.id;
    req.session.csrf = crypto.randomBytes(32).toString('hex');
    await new Promise((resolve,reject)=>req.session.save(err=>err?reject(err):resolve()));
    res.redirect('/');
  } catch (e) {
    console.error('OAuth callback failed:', e.message);
    res.status(502).send(pageShell('Ошибка авторизации','Discord не удалось подтвердить вход. Попробуй ещё раз чуть позже.','Повторить вход','/'));
  }
});
app.post('/auth/logout', (req,res) => {
  const expected = req.session.csrf;
  if (req.session.userId && (!expected || req.get('X-CSRF-Token') !== expected)) return res.status(403).json({error:'Проверка CSRF не пройдена'});
  req.session.destroy(err => { res.clearCookie('vyshka.sid', { httpOnly:true, secure:prod, sameSite:'lax' }); if(err) return res.status(500).json({error:'Не удалось завершить сессию'}); res.json({ok:true}); });
});
async function getCurrentUser(req) {
  if (!req.session.userId) return null;
  const q = await pool.query('SELECT discord_id, username, global_name, avatar_url, role FROM whitelist_users WHERE discord_id=$1', [req.session.userId]);
  if (!q.rowCount) { req.session.destroy(()=>{}); return null; }
  const u=q.rows[0]; return { discordId:u.discord_id, username:u.global_name || u.username || 'Discord', avatar:u.avatar_url, role:u.role, csrf:req.session.csrf };
}
async function requireAuth(req,res,next) { try { const u=await getCurrentUser(req); if(!u) return res.status(401).json({error:'Требуется авторизация через Discord'}); req.authUser=u; next(); } catch(e) { next(e); } }
function requireAdmin(req,res,next) { if(req.authUser?.role!=='Администратор') return res.status(403).json({error:'Доступ разрешён только администратору'}); next(); }
function requireCsrf(req,res,next) { if(!req.session.csrf || req.get('X-CSRF-Token')!==req.session.csrf) return res.status(403).json({error:'Проверка CSRF не пройдена'}); next(); }
app.get('/api/me', async (req,res,next)=>{ try { const user=await getCurrentUser(req); if(user) return res.json({authenticated:true,user}); if(req.session.deniedUser) return res.status(403).json({authenticated:false,denied:true}); return res.json({authenticated:false}); } catch(e){next(e);} });
app.get('/api/admin/whitelist', requireAuth, requireAdmin, async (req,res,next)=>{try{const q=await pool.query('SELECT discord_id, username, global_name, avatar_url, role, added_at FROM whitelist_users ORDER BY added_at DESC');res.json({users:q.rows.map(u=>({discordId:u.discord_id,username:u.global_name||u.username,avatar:u.avatar_url,role:u.role,addedAt:u.added_at}))});}catch(e){next(e);}});
app.post('/api/admin/whitelist', mutationLimiter, requireAuth, requireAdmin, requireCsrf, async (req,res,next)=>{try{const id=String(req.body.discordId||'').trim(), role=String(req.body.role||'');if(!/^\d{17,20}$/.test(id))return res.status(400).json({error:'Discord ID должен содержать 17–20 цифр'});if(!ROLES.includes(role))return res.status(400).json({error:'Недопустимая роль'});if(role==='Администратор' && req.authUser.discordId!==String(process.env.BOOTSTRAP_ADMIN_DISCORD_ID||'') && req.authUser.role!=='Администратор')return res.status(403).json({error:'Недостаточно прав'});await pool.query('INSERT INTO whitelist_users (discord_id, role) VALUES ($1,$2) ON CONFLICT (discord_id) DO NOTHING',[id,role]);res.status(201).json({ok:true});}catch(e){next(e);}});
app.patch('/api/admin/whitelist/:id', mutationLimiter, requireAuth, requireAdmin, requireCsrf, async (req,res,next)=>{try{const id=String(req.params.id),role=String(req.body.role||'');if(!ROLES.includes(role))return res.status(400).json({error:'Недопустимая роль'});if(id===req.authUser.discordId && role!=='Администратор')return res.status(400).json({error:'Нельзя снять собственную роль администратора здесь'});const q=await pool.query('UPDATE whitelist_users SET role=$2, updated_at=NOW() WHERE discord_id=$1 RETURNING discord_id',[id,role]);if(!q.rowCount)return res.status(404).json({error:'Пользователь не найден'});res.json({ok:true});}catch(e){next(e);}});
app.delete('/api/admin/whitelist/:id', mutationLimiter, requireAuth, requireAdmin, requireCsrf, async (req,res,next)=>{try{const id=String(req.params.id);if(id===req.authUser.discordId)return res.status(400).json({error:'Нельзя удалить собственный аккаунт администратора'});const q=await pool.query('DELETE FROM whitelist_users WHERE discord_id=$1',[id]);if(!q.rowCount)return res.status(404).json({error:'Пользователь не найден'});res.json({ok:true});}catch(e){next(e);}});
app.get('/auth/denied-logout', (req,res)=>{req.session.destroy(()=>{res.clearCookie('vyshka.sid',{httpOnly:true,secure:prod,sameSite:'lax'});res.redirect('/');});});
app.get('/', async (req,res,next)=>{try{
  if(req.session.deniedUser && !req.session.userId) return res.status(403).send(pageShell('Доступ не разрешён','⛔ У вас нет доступа к сайту «Вышка саппортов». Обратитесь к администратору, чтобы получить доступ.','Выйти из аккаунта','/auth/denied-logout',true));
  const user=await getCurrentUser(req);
  if(!user) return res.send(pageShell('Вышка саппортов','Войди через Discord. Доступ получают только пользователи, заранее добавленные администратором в белый список.','Войти через Discord','/auth/discord'));
  const safeUserJson=JSON.stringify(user).replace(/</g,'\\u003c').replace(/>/g,'\\u003e').replace(/&/g,'\\u0026');
  const html=fs.readFileSync(path.join(__dirname,'index.html'),'utf8').replaceAll('window.__VYSHKA_USER__||null',safeUserJson);
  res.set('Cache-Control','no-store');res.type('html').send(html);
}catch(e){next(e);}});
app.get('/index.html',(req,res)=>res.redirect(302,'/'));
app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(500).json({error:'Внутренняя ошибка сервера'});});
initDb().then(()=>app.listen(PORT,()=>console.log(`Вышка backend listening on port ${PORT}`))).catch(e=>{console.error('Database initialization failed:',e);process.exit(1);});
