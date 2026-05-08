function getIp(req) {
  return (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
}

function detectDevice(ua) {
  if (!ua) return 'unknown';
  const u = ua.toLowerCase();
  if (/bot|crawl|spider|slurp|facebot/.test(u)) return 'bot';
  if (/mobile|android|iphone|ipad/.test(u)) return 'mobile';
  return 'desktop';
}

module.exports = { getIp, detectDevice };
