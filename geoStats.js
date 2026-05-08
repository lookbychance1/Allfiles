/**
 * geoStats.js — Geo-Specific Traffic Analytics
 * Parses server access logs + MongoDB user/session data
 * Returns country/city breakdown, top pages, device types, auth method stats
 */

require('dotenv').config();
const express  = require('express');
const fs       = require('fs');
const path     = require('path');
const readline = require('readline');
const mongoose = require('mongoose');

const router = express.Router();

// ─── Lightweight IP → Country via ip-api.com (self-hosted fallback) ───────────
// Uses ip-api.com batch API. Replace with MaxMind GeoLite2 for offline use.
const GEO_BATCH_URL = 'http://ip-api.com/batch?fields=status,country,countryCode,regionName,city,lat,lon,query';

async function geoLookupBatch(ips) {
  try {
    const uniqueIps = [...new Set(ips)].slice(0, 100); // ip-api batch limit
    const res = await fetch(GEO_BATCH_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(uniqueIps),
      signal:  AbortSignal.timeout(5000),
    });
    if (!res.ok) return {};
    const data = await res.json();
    return Object.fromEntries(data.map(d => [d.query, d]));
  } catch { return {}; }
}

// ─── Log Cache Schema ─────────────────────────────────────────────────────────
const StatsSnapshotSchema = new mongoose.Schema({
  date:        { type: String, index: true },  // YYYY-MM-DD
  totalReqs:   Number,
  uniqueIPs:   Number,
  countries:   mongoose.Schema.Types.Mixed,    // { IN: 412, US: 88, ... }
  cities:      mongoose.Schema.Types.Mixed,
  topPaths:    mongoose.Schema.Types.Mixed,
  statusCodes: mongoose.Schema.Types.Mixed,
  devices:     mongoose.Schema.Types.Mixed,    // { mobile, desktop, bot }
  authMethods: mongoose.Schema.Types.Mixed,    // { email_otp, google, github, apple, legacy }
  heatmap:     mongoose.Schema.Types.Mixed,    // { lat_lon: count }
  createdAt:   { type: Date, default: Date.now },
}, { collection: 'admin_stats_snapshots' });

const StatsSnapshot = mongoose.models.StatsSnapshot || mongoose.model('StatsSnapshot', StatsSnapshotSchema);

// ─── Parse Apache/Combined log format ────────────────────────────────────────
// Format: IP - - [date] "METHOD /path HTTP/1.1" status bytes "ref" "UA"
function parseLogLine(line) {
  const m = line.match(/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"/);
  if (!m) return null;
  return {
    ip:        m[1],
    timestamp: m[2],
    method:    m[3],
    path:      m[4],
    status:    parseInt(m[5]),
    bytes:     m[6] === '-' ? 0 : parseInt(m[6]),
    referrer:  m[7],
    ua:        m[8],
  };
}

function detectDevice(ua) {
  if (!ua) return 'unknown';
  const u = ua.toLowerCase();
  if (/bot|crawl|spider|slurp|facebot/.test(u)) return 'bot';
  if (/mobile|android|iphone|ipad/.test(u)) return 'mobile';
  return 'desktop';
}

async function parseLogFile(logPath, dateFilter) {
  const stats = {
    totalReqs: 0, ips: new Set(),
    countries: {}, cities: {}, topPaths: {}, statusCodes: {}, devices: {}, heatmap: {},
    ipList: [],
  };

  if (!fs.existsSync(logPath)) return stats;

  const rl = readline.createInterface({ input: fs.createReadStream(logPath), crlfDelay: Infinity });
  for await (const line of rl) {
    const entry = parseLogLine(line);
    if (!entry) continue;
    if (dateFilter && !entry.timestamp.startsWith(dateFilter)) continue;

    stats.totalReqs++;
    stats.ips.add(entry.ip);
    stats.ipList.push(entry.ip);

    const cleanPath = entry.path.split('?')[0].slice(0, 80);
    stats.topPaths[cleanPath]        = (stats.topPaths[cleanPath] || 0) + 1;
    stats.statusCodes[entry.status]  = (stats.statusCodes[entry.status] || 0) + 1;
    const dev = detectDevice(entry.ua);
    stats.devices[dev] = (stats.devices[dev] || 0) + 1;
  }

  stats.uniqueIPs = stats.ips.size;
  return stats;
}

// ─── Merge geo data ───────────────────────────────────────────────────────────
function mergeGeo(rawStats, geoMap) {
  const countries = {}, cities = {}, heatmap = {};
  for (const ip of rawStats.ipList) {
    const geo = geoMap[ip];
    if (!geo || geo.status !== 'success') continue;
    countries[geo.countryCode] = (countries[geo.countryCode] || 0) + 1;
    const city = `${geo.city}, ${geo.regionName}`;
    cities[city] = (cities[city] || 0) + 1;
    if (geo.lat && geo.lon) {
      const key = `${geo.lat.toFixed(1)},${geo.lon.toFixed(1)}`;
      heatmap[key] = (heatmap[key] || 0) + 1;
    }
  }
  return { countries, cities, heatmap };
}

// ─── Auth method stats from MongoDB ──────────────────────────────────────────
async function getAuthStats(startDate, endDate) {
  try {
    const db    = mongoose.connection.db;
    const users = db.collection('users');
    const pipeline = [
      { $match: { createdAt: { $gte: startDate, $lte: endDate } } },
      { $group: { _id: '$authMethod', count: { $sum: 1 } } },
    ];
    const result = await users.aggregate(pipeline).toArray();
    return Object.fromEntries(result.map(r => [r._id || 'unknown', r.count]));
  } catch { return {}; }
}

// ─── GET /api/admin/geo-stats/live ───────────────────────────────────────────
router.get('/live', async (req, res) => {
  try {
    const logPath = process.env.MAIN_ACCESS_LOG || path.join(__dirname, 'logs', 'access.log');
    const today   = new Date().toLocaleDateString('en-US', { day: '2-digit', month: 'short', year: 'numeric' });

    const rawStats = await parseLogFile(logPath, null); // last 1000 lines effectively
    const geoMap   = await geoLookupBatch(rawStats.ipList.slice(-500)); // last 500 unique IPs
    const { countries, cities, heatmap } = mergeGeo(rawStats, geoMap);

    // Top paths: sort and limit 20
    const topPaths = Object.entries(rawStats.topPaths)
      .sort((a, b) => b[1] - a[1]).slice(0, 20)
      .map(([path, count]) => ({ path, count }));

    res.json({
      totalReqs:   rawStats.totalReqs,
      uniqueIPs:   rawStats.uniqueIPs,
      countries,
      cities:      Object.entries(cities).sort((a,b) => b[1]-a[1]).slice(0,20).map(([city,count])=>({city,count})),
      topPaths,
      statusCodes: rawStats.statusCodes,
      devices:     rawStats.devices,
      heatmap,
      generatedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error('[geoStats/live]', err);
    res.status(500).json({ error: 'Stats generation failed.' });
  }
});

// ─── GET /api/admin/geo-stats/daily?date=YYYY-MM-DD ──────────────────────────
router.get('/daily', async (req, res) => {
  try {
    const date = req.query.date || new Date().toISOString().slice(0, 10);

    // Check cache
    const cached = await StatsSnapshot.findOne({ date }).lean();
    if (cached) return res.json(cached);

    const logPath  = process.env.MAIN_ACCESS_LOG || path.join(__dirname, 'logs', 'access.log');
    const rawStats = await parseLogFile(logPath, null);
    const geoMap   = await geoLookupBatch(rawStats.ipList);
    const { countries, cities, heatmap } = mergeGeo(rawStats, geoMap);

    const startDate = new Date(date);
    const endDate   = new Date(date); endDate.setDate(endDate.getDate() + 1);
    const authMethods = await getAuthStats(startDate, endDate);

    const topPaths = Object.entries(rawStats.topPaths)
      .sort((a, b) => b[1] - a[1]).slice(0, 20)
      .map(([p, c]) => ({ path: p, count: c }));

    const snapshot = {
      date,
      totalReqs:   rawStats.totalReqs,
      uniqueIPs:   rawStats.uniqueIPs,
      countries,
      cities,
      topPaths,
      statusCodes: rawStats.statusCodes,
      devices:     rawStats.devices,
      authMethods,
      heatmap,
    };

    await StatsSnapshot.findOneAndUpdate({ date }, snapshot, { upsert: true, new: true });
    res.json(snapshot);
  } catch (err) {
    console.error('[geoStats/daily]', err);
    res.status(500).json({ error: 'Daily stats failed.' });
  }
});

// ─── GET /api/admin/geo-stats/range?from=YYYY-MM-DD&to=YYYY-MM-DD ────────────
router.get('/range', async (req, res) => {
  try {
    const from = req.query.from || new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);
    const to   = req.query.to   || new Date().toISOString().slice(0, 10);

    const snapshots = await StatsSnapshot.find({
      date: { $gte: from, $lte: to },
    }).sort({ date: 1 }).lean();

    const summary = {
      range: { from, to },
      days:  snapshots.map(s => ({
        date:      s.date,
        totalReqs: s.totalReqs,
        uniqueIPs: s.uniqueIPs,
        devices:   s.devices,
      })),
      totalReqs:    snapshots.reduce((a, s) => a + (s.totalReqs || 0), 0),
      topCountries: mergeObjects(snapshots.map(s => s.countries || {})),
      topDevices:   mergeObjects(snapshots.map(s => s.devices   || {})),
      authMethods:  mergeObjects(snapshots.map(s => s.authMethods || {})),
    };

    res.json(summary);
  } catch (err) {
    res.status(500).json({ error: 'Range stats failed.' });
  }
});

function mergeObjects(arr) {
  const result = {};
  for (const obj of arr) {
    for (const [k, v] of Object.entries(obj || {})) {
      result[k] = (result[k] || 0) + v;
    }
  }
  return Object.entries(result).sort((a,b) => b[1]-a[1]).slice(0,20)
    .reduce((o, [k, v]) => ({ ...o, [k]: v }), {});
}

module.exports = router;
