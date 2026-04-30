const crypto = require('crypto');

// 메모리 기반 간단 rate limit (Vercel 인스턴스 재시작 시 초기화됨)
const attempts = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  const entry = attempts.get(ip) || { count: 0, first: now };
  if (now - entry.first > 60_000) {
    attempts.set(ip, { count: 1, first: now });
    return false;
  }
  if (entry.count >= 10) return true;
  attempts.set(ip, { count: entry.count + 1, first: entry.first });
  return false;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).end();

  const ip = req.headers['x-forwarded-for']?.split(',')[0] || 'unknown';
  if (isRateLimited(ip)) {
    return res.status(429).json({ error: 'too many attempts' });
  }

  const { password } = req.body;
  const correct = process.env.PASSWORD;
  const secret  = process.env.SECRET;

  if (!correct || !secret) return res.status(500).json({ error: 'server config error' });
  if (password !== correct) return res.status(401).json({ error: 'wrong password' });

  const token = crypto.createHmac('sha256', secret).update(password).digest('hex');
  return res.status(200).json({ token });
};
