// 学习系统全站 Worker（Pages Advanced Mode）多用户版
// - /api/register、/api/login、/api/ai、/api/sync/:code 由本 Worker 处理
// - 用户体系：KV user:{用户名} = {h(密码哈希), name(姓名)}；tok:{token} = 用户名（60天）
// - 云同步按用户隔离：sync:{用户名}
// - 其余路径转发给 Pages 静态资源（env.ASSETS）

const APP_VERSION = '2026.07.24.2';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(obj, status = 200) {
  return new Response(typeof obj === 'string' ? obj : JSON.stringify(obj), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json; charset=utf-8' },
  });
}

async function sha256hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function passHash(user, pass) {
  return sha256hex(pass + ':' + user.toLowerCase());
}

function validUser(u) { return /^[A-Za-z0-9_一-龥-]{3,32}$/.test(u); }
function validPass(p) { return typeof p === 'string' && p.length >= 6 && p.length <= 64; }
const GRADES = ['初一','初二','初三','高一','高二','高三'];
function validGrade(g) { return GRADES.includes(g); }

async function issueToken(env, user) {
  const token = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().slice(0, 8);
  await env.STUDY_SYNC.put('tok:' + token, user, { expirationTtl: 60 * 24 * 3600 });
  return token;
}

// 返回 { user, admin } 或 null
async function authed(request, env) {
  const h = request.headers.get('Authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/);
  if (!m) return null;
  const token = m[1].trim();
  if (env.API_TOKEN && token === env.API_TOKEN) return { user: 'admin', admin: true };
  if (!env.STUDY_SYNC) return null;
  const u = await env.STUDY_SYNC.get('tok:' + token);
  if (!u) return null;
  return { user: u, admin: false };
}

async function handleRegister(request, env) {
  if (request.method !== 'POST') return json('{"error":"method not allowed"}', 405);
  if (!env.STUDY_SYNC) return json('{"error":"kv not bound"}', 500);
  let body = {};
  try { body = await request.json(); } catch { return json('{"error":"bad json"}', 400); }
  const u = String(body.user || '').trim();
  const p = String(body.pass || '');
  const name = String(body.name || '').trim().slice(0, 16);
  const grade = String(body.grade || '').trim();
  if (!validUser(u)) return json('{"error":"用户名需为3-32位字母、数字或中文"}', 400);
  if (!validPass(p)) return json('{"error":"密码至少6位"}', 400);
  if (!name) return json('{"error":"请填写姓名（同学称呼）"}', 400);
  if (!validGrade(grade)) return json('{"error":"请选择年级"}', 400);
  // 付费产品：注册必须持有效邀请码
  const code = String(body.code || '').trim().toUpperCase();
  if (!code) return json('{"error":"请填写邀请码（向已购课家长或管理员索取）"}', 400);
  const invRaw = await env.STUDY_SYNC.get('invite:' + code);
  if (!invRaw) return json('{"error":"邀请码无效，请核对后重试"}', 400);
  let inv;
  try { inv = JSON.parse(invRaw); } catch { inv = null; }
  if (!inv || (inv.used || 0) >= (inv.max || 1)) return json('{"error":"邀请码已用完，请索取新的邀请码"}', 400);
  if (env.LOGIN_USER && u === env.LOGIN_USER) return json('{"error":"该用户名已被占用"}', 409);
  const existed = await env.STUDY_SYNC.get('user:' + u.toLowerCase());
  if (existed) return json('{"error":"该用户名已注册，直接登录即可"}', 409);
  const h = await passHash(u, p);
  await env.STUDY_SYNC.put('user:' + u.toLowerCase(), JSON.stringify({ h, name, grade, t: Date.now() }));
  inv.used = (inv.used || 0) + 1;
  await env.STUDY_SYNC.put('invite:' + code, JSON.stringify(inv));
  const token = await issueToken(env, u.toLowerCase());
  return json({ ok: true, token, name, grade });
}

async function handleLogin(request, env) {
  if (request.method !== 'POST') return json('{"error":"method not allowed"}', 405);
  let body = {};
  try { body = await request.json(); } catch { return json('{"error":"bad json"}', 400); }
  const u = String(body.user || '').trim();
  const p = String(body.pass || '');
  // 管理员（环境变量）优先
  if (env.LOGIN_USER && env.LOGIN_PASS && u === env.LOGIN_USER && p === env.LOGIN_PASS) {
    const name = String(body.name || '').trim().slice(0, 16);
    return json({ ok: true, token: env.API_TOKEN || '', admin: true, name });
  }
  // 普通注册用户
  if (!env.STUDY_SYNC) return json('{"error":"kv not bound"}', 500);
  const rec = await env.STUDY_SYNC.get('user:' + u.toLowerCase());
  if (!rec) return json('{"error":"账号不存在，请先注册"}', 401);
  let user;
  try { user = JSON.parse(rec); } catch { return json('{"error":"account broken"}', 500); }
  const h = await passHash(u, p);
  if (h !== user.h) return json('{"error":"密码错误"}', 401);
  const token = await issueToken(env, u.toLowerCase());
  return json({ ok: true, token, name: user.name || '', grade: user.grade || '' });
}

// 邀请码管理：仅管理员令牌可用
function genCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let c = '';
  for (let i = 0; i < 6; i++) c += chars[Math.floor(Math.random() * chars.length)];
  return c;
}

async function handleInvite(request, env) {
  const h = request.headers.get('Authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/);
  if (!m || !env.API_TOKEN || m[1].trim() !== env.API_TOKEN) return json('{"error":"仅管理员可用"}', 401);
  if (!env.STUDY_SYNC) return json('{"error":"kv not bound"}', 500);

  if (request.method === 'POST') {
    let body = {};
    try { body = await request.json(); } catch { body = {}; }
    const max = Math.min(50, Math.max(1, parseInt(body.max || '1') || 1));
    const note = String(body.note || '').trim().slice(0, 40);
    const code = genCode();
    const rec = { max, used: 0, note, t: Date.now() };
    await env.STUDY_SYNC.put('invite:' + code, JSON.stringify(rec));
    return json({ ok: true, code, max, note });
  }
  if (request.method === 'GET') {
    const list = await env.STUDY_SYNC.list({ prefix: 'invite:' });
    const out = [];
    for (const k of list.keys) {
      const v = await env.STUDY_SYNC.get(k.name);
      try { out.push(Object.assign({ code: k.name.slice(7) }, JSON.parse(v))); } catch {}
    }
    out.sort((a, b) => (b.t || 0) - (a.t || 0));
    return json({ ok: true, invites: out.slice(0, 100) });
  }
  return json('{"error":"method not allowed"}', 405);
}

// 限流：登录用户 300 次/天/人，游客 15 次/天/IP，保护付费密钥
async function rateOk(env, key, limit) {
  const cur = await env.STUDY_SYNC.get(key);
  const n = parseInt(cur || '0') || 0;
  if (n >= limit) return false;
  await env.STUDY_SYNC.put(key, String(n + 1), { expirationTtl: 60 * 60 * 36 });
  return true;
}

async function handleAi(request, env) {
  if (request.method !== 'POST') return json('{"error":"method not allowed"}', 405);
  const who = await authed(request, env);
  const day = new Date().toISOString().slice(0, 10);
  if (who) {
    if (!(await rateOk(env, 'rl:u:' + who.user + ':' + day, 300))) {
      return json('{"error":"今日 AI 使用次数已达上限（300次），明天再来吧"}', 429);
    }
  } else {
    // 游客体验：按 IP 每天 15 次
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    if (!(await rateOk(env, 'rl:ip:' + ip + ':' + day, 15))) {
      return json('{"error":"游客体验次数已用完（每日15次），注册账号解锁完整功能"}', 429);
    }
  }
  if (!env.DEEPSEEK_KEY) return json('{"error":"ai not configured"}', 500);
  const body = await request.text();
  if (!body || body.length > 1024 * 1024) return json('{"error":"bad body"}', 400);
  const upstream = await fetch('https://api.deepseek.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${env.DEEPSEEK_KEY}`,
    },
    body,
  });
  // 流式/非流式都直接透传响应体
  return new Response(upstream.body, {
    status: upstream.status,
    headers: {
      ...CORS,
      'Content-Type': upstream.headers.get('Content-Type') || 'application/json; charset=utf-8',
    },
  });
}

async function handleSync(request, env, code) {
  const who = await authed(request, env);
  if (!who) return json('{"error":"unauthorized"}', 401);
  if (!env.STUDY_SYNC) return json('{"error":"kv not bound"}', 500);
  // 按用户隔离：管理员用 :code 原样，普通用户强制 u_{user}_{code}
  const key = who.admin ? code : ('u_' + who.user + '_' + code);

  if (request.method === 'GET') {
    const v = await env.STUDY_SYNC.get(key);
    return json(v === null ? 'null' : v);
  }

  if (request.method === 'PUT') {
    const body = await request.text();
    if (!body || body.length < 2) return json('{"error":"empty body"}', 400);
    if (body.length > 512 * 1024) return json('{"error":"too large"}', 413);
    try {
      const parsed = JSON.parse(body);
      if (typeof parsed !== 'object' || parsed === null) throw new Error('bad');
    } catch {
      return json('{"error":"invalid json"}', 400);
    }
    await env.STUDY_SYNC.put(key, body);
    return json('{"ok":true}');
  }

  return json('{"error":"method not allowed"}', 405);
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    const url = new URL(request.url);

    // API 路由
    if (url.pathname === '/api/register') return handleRegister(request, env);
    if (url.pathname === '/api/login') return handleLogin(request, env);
    if (url.pathname === '/api/ai') return handleAi(request, env);
    if (url.pathname === '/api/invite') return handleInvite(request, env);

    const m = url.pathname.match(/^\/api\/sync\/([A-Za-z0-9_-]{2,48})$/);
    if (m) return handleSync(request, env, m[1]);

    if (url.pathname === '/api' || url.pathname === '/api/health') {
      return json(JSON.stringify({ ok: true, service: 'study-sync', version: APP_VERSION }));
    }

    // 其余全部交给静态资源（SPA：/ 自动落到 index.html）
    return env.ASSETS.fetch(request);
  },
};
