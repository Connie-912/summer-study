// 学习系统全站 Worker（Pages Advanced Mode）
// - /api/login、/api/ai、/api/sync/:code 由本 Worker 处理
// - 其余路径转发给 Pages 静态资源（env.ASSETS）

const APP_VERSION = '2026.07.23.2';

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

function authed(request, env) {
  // 未配置 API_TOKEN 时视为开放，配置后强制校验
  if (!env.API_TOKEN) return true;
  const h = request.headers.get('Authorization') || '';
  return h === `Bearer ${env.API_TOKEN}`;
}

async function handleLogin(request, env) {
  if (request.method !== 'POST') return json('{"error":"method not allowed"}', 405);
  let body = {};
  try { body = await request.json(); } catch { return json('{"error":"bad json"}', 400); }
  const u = String(body.user || '');
  const p = String(body.pass || '');
  if (!env.LOGIN_USER || !env.LOGIN_PASS) return json('{"error":"login not configured"}', 500);
  if (u === env.LOGIN_USER && p === env.LOGIN_PASS) {
    return json({ ok: true, token: env.API_TOKEN || '' });
  }
  return json('{"error":"账号或密码错误"}', 401);
}

async function handleAi(request, env) {
  if (request.method !== 'POST') return json('{"error":"method not allowed"}', 405);
  if (!authed(request, env)) return json('{"error":"unauthorized"}', 401);
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
  if (!authed(request, env)) return json('{"error":"unauthorized"}', 401);
  if (!env.STUDY_SYNC) return json('{"error":"kv not bound"}', 500);

  if (request.method === 'GET') {
    const v = await env.STUDY_SYNC.get(code);
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
    await env.STUDY_SYNC.put(code, body);
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
    if (url.pathname === '/api/login') return handleLogin(request, env);
    if (url.pathname === '/api/ai') return handleAi(request, env);

    const m = url.pathname.match(/^\/api\/sync\/([A-Za-z0-9_-]{4,32})$/);
    if (m) return handleSync(request, env, m[1]);

    if (url.pathname === '/api' || url.pathname === '/api/health') {
      return json(JSON.stringify({ ok: true, service: 'study-sync', version: APP_VERSION }));
    }

    // 其余全部交给静态资源（SPA：/ 自动落到 index.html）
    return env.ASSETS.fetch(request);
  },
};
