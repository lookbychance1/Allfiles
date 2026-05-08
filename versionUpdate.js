/**
 * versionUpdate.js — App Version Management
 * Track frontend/backend versions, force-update flags,
 * changelog entries, and rollout control
 */

require('dotenv').config();
const express  = require('express');
const mongoose = require('mongoose');
const semver   = require('semver');

const router = express.Router();
const { requireRole } = require('./adminMiddleware');

// ─── Schemas ──────────────────────────────────────────────────────────────────
const VersionSchema = new mongoose.Schema({
  platform:       { type: String, enum: ['web', 'android', 'ios', 'backend'], required: true },
  version:        { type: String, required: true },       // semver e.g. "2.1.0"
  minVersion:     { type: String, required: true },       // force-update below this
  isLatest:       { type: Boolean, default: true },
  isMandatory:    { type: Boolean, default: false },      // force update flag
  downloadUrl:    { type: String, default: '' },          // APK/IPA/store link
  releaseNotes:   { type: String, default: '' },
  rolloutPercent: { type: Number, default: 100, min: 0, max: 100 },
  publishedBy:    { type: String, default: 'admin' },
  publishedAt:    { type: Date, default: Date.now },
}, { collection: 'app_versions' });

const ChangelogSchema = new mongoose.Schema({
  platform:   { type: String, enum: ['web', 'android', 'ios', 'backend', 'all'] },
  version:    String,
  type:       { type: String, enum: ['feature', 'fix', 'security', 'breaking', 'maintenance'] },
  title:      String,
  body:       String,
  author:     String,
  publishedAt:{ type: Date, default: Date.now },
}, { collection: 'changelog' });

const AppVersion = mongoose.models.AppVersion || mongoose.model('AppVersion', VersionSchema);
const Changelog  = mongoose.models.Changelog  || mongoose.model('Changelog', ChangelogSchema);

// ─── GET /api/admin/version/list ─────────────────────────────────────────────
router.get('/list', async (req, res) => {
  try {
    const versions = await AppVersion.find().sort({ publishedAt: -1 }).lean();
    res.json(versions);
  } catch { res.status(500).json({ error: 'Fetch failed.' }); }
});

// ─── GET /api/admin/version/current ──────────────────────────────────────────
// Returns latest version per platform (used by clients to check for updates)
router.get('/current', async (req, res) => {
  try {
    const platforms = ['web', 'android', 'ios', 'backend'];
    const result = {};
    await Promise.all(platforms.map(async p => {
      const v = await AppVersion.findOne({ platform: p, isLatest: true }).sort({ publishedAt: -1 }).lean();
      result[p] = v || null;
    }));
    res.json(result);
  } catch { res.status(500).json({ error: 'Fetch failed.' }); }
});

// ─── POST /api/admin/version/check ───────────────────────────────────────────
// Client posts its current version; server returns update info
router.post('/check', async (req, res) => {
  try {
    const { platform, currentVersion } = req.body;
    if (!platform || !currentVersion) return res.status(400).json({ error: 'platform and currentVersion required.' });

    const latest = await AppVersion.findOne({ platform, isLatest: true }).sort({ publishedAt: -1 }).lean();
    if (!latest) return res.json({ updateAvailable: false });

    const updateAvailable = semver.lt(currentVersion, latest.version);
    const forceUpdate     = semver.lt(currentVersion, latest.minVersion);

    res.json({
      updateAvailable,
      forceUpdate,
      isMandatory:    latest.isMandatory || forceUpdate,
      latestVersion:  latest.version,
      minVersion:     latest.minVersion,
      downloadUrl:    latest.downloadUrl,
      releaseNotes:   latest.releaseNotes,
      rolloutPercent: latest.rolloutPercent,
    });
  } catch (err) {
    res.status(500).json({ error: 'Version check failed.', detail: err.message });
  }
});

// ─── POST /api/admin/version/publish ─────────────────────────────────────────
router.post('/publish', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const { platform, version, minVersion, isMandatory, downloadUrl, releaseNotes, rolloutPercent } = req.body;

    if (!platform || !version || !minVersion) {
      return res.status(400).json({ error: 'platform, version, minVersion required.' });
    }
    if (!semver.valid(version) || !semver.valid(minVersion)) {
      return res.status(400).json({ error: 'Invalid semver version format.' });
    }
    if (semver.gt(minVersion, version)) {
      return res.status(400).json({ error: 'minVersion cannot be greater than version.' });
    }

    // Unmark previous latest for this platform
    await AppVersion.updateMany({ platform, isLatest: true }, { isLatest: false });

    const newVersion = await AppVersion.create({
      platform, version, minVersion,
      isMandatory:    Boolean(isMandatory),
      downloadUrl:    downloadUrl || '',
      releaseNotes:   releaseNotes || '',
      rolloutPercent: rolloutPercent ?? 100,
      isLatest:       true,
      publishedBy:    req.admin.username,
    });

    // Auto-create changelog entry
    await Changelog.create({
      platform, version,
      type:   'feature',
      title:  `Version ${version} released`,
      body:   releaseNotes || '',
      author: req.admin.username,
    });

    res.status(201).json(newVersion);
  } catch (err) {
    res.status(500).json({ error: 'Publish failed.', detail: err.message });
  }
});

// ─── PATCH /api/admin/version/:id ────────────────────────────────────────────
router.patch('/:id', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const allowed = ['isMandatory', 'downloadUrl', 'releaseNotes', 'rolloutPercent', 'minVersion'];
    const updates = {};
    for (const k of allowed) if (req.body[k] !== undefined) updates[k] = req.body[k];

    const v = await AppVersion.findByIdAndUpdate(req.params.id, updates, { new: true });
    if (!v) return res.status(404).json({ error: 'Version not found.' });
    res.json(v);
  } catch { res.status(500).json({ error: 'Update failed.' }); }
});

// ─── DELETE /api/admin/version/:id ───────────────────────────────────────────
router.delete('/:id', requireRole('superadmin'), async (req, res) => {
  try {
    await AppVersion.findByIdAndDelete(req.params.id);
    res.json({ message: 'Version deleted.' });
  } catch { res.status(500).json({ error: 'Delete failed.' }); }
});

// ─── GET /api/admin/version/changelog ────────────────────────────────────────
router.get('/changelog', async (req, res) => {
  try {
    const platform = req.query.platform;
    const filter   = platform ? { platform: { $in: [platform, 'all'] } } : {};
    const entries  = await Changelog.find(filter).sort({ publishedAt: -1 }).limit(50).lean();
    res.json(entries);
  } catch { res.status(500).json({ error: 'Changelog fetch failed.' }); }
});

// ─── POST /api/admin/version/changelog ───────────────────────────────────────
router.post('/changelog', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const { platform, version, type, title, body } = req.body;
    if (!platform || !version || !title) return res.status(400).json({ error: 'platform, version, title required.' });

    const entry = await Changelog.create({
      platform, version, type: type || 'feature', title, body: body || '',
      author: req.admin.username,
    });
    res.status(201).json(entry);
  } catch (err) {
    res.status(500).json({ error: 'Changelog creation failed.' });
  }
});

module.exports = router;
