const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');

function getDb() {
  return neon(process.env.DATABASE_URL);
}

function verifyToken(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return false;
  const expected = crypto
    .createHmac('sha256', process.env.SECRET)
    .update(process.env.PASSWORD)
    .digest('hex');
  return token === expected;
}

function isSafeUrl(url) {
  try {
    const u = new URL(url.startsWith('http') ? url : 'https://' + url);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch { return false; }
}

module.exports = async (req, res) => {
  const origin = req.headers['origin'];
  const allowed = process.env.ALLOWED_ORIGIN || 'https://plax-eta.vercel.app';
  if (origin && origin !== allowed) {
    res.setHeader('Access-Control-Allow-Origin', allowed);
  } else {
    res.setHeader('Access-Control-Allow-Origin', allowed);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const sql = getDb();

  await sql`
    CREATE TABLE IF NOT EXISTS posts (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT,
      image_url TEXT,
      link_url TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;

  // GET은 인증 불필요 (읽기는 로그인 후에만 가능 — 프론트에서 토큰 검사)
  if (req.method === 'GET') {
    if (!verifyToken(req)) return res.status(401).json({ error: 'unauthorized' });
    const rows = await sql`
      SELECT id, title, body, image_url, link_url, created_at
      FROM posts ORDER BY created_at DESC LIMIT 100
    `;
    return res.status(200).json(rows);
  }

  if (req.method === 'POST') {
    if (!verifyToken(req)) return res.status(401).json({ error: 'unauthorized' });

    const { title, body, image_base64, link_url } = req.body;
    if (!title) return res.status(400).json({ error: 'title required' });
    if (link_url && !isSafeUrl(link_url)) return res.status(400).json({ error: 'invalid url' });

    const image_url = image_base64 || null;
    const rows = await sql`
      INSERT INTO posts (title, body, image_url, link_url)
      VALUES (${title}, ${body || null}, ${image_url}, ${link_url || null})
      RETURNING *
    `;
    return res.status(201).json(rows[0]);
  }

  if (req.method === 'DELETE') {
    if (!verifyToken(req)) return res.status(401).json({ error: 'unauthorized' });
    const id = req.query?.id || new URL(req.url, 'http://x').searchParams.get('id');
    if (!id) return res.status(400).json({ error: 'id required' });
    await sql`DELETE FROM posts WHERE id = ${id}`;
    return res.status(200).json({ ok: true });
  }

  res.status(405).json({ error: 'Method not allowed' });
};
