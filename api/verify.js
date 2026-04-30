const crypto = require('crypto');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).end();

  const { token } = req.body;
  const password = process.env.PASSWORD;
  const secret   = process.env.SECRET;

  if (!password || !secret) return res.status(500).json({ valid: false });

  const expected = crypto.createHmac('sha256', secret).update(password).digest('hex');
  const valid = token === expected;

  return res.status(valid ? 200 : 401).json({ valid });
};
