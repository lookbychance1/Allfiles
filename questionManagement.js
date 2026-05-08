/**
 * questionManagement.js — Complete Question Management Routes
 * CRUD for questions, options, explanations, images
 * Supports subject/topic taxonomy, bulk import, re-encryption
 */

require('dotenv').config();
const express  = require('express');
const mongoose = require('mongoose');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');

const router = express.Router();
const { requireRole } = require('./adminMiddleware');

// ─── Image Upload Config ──────────────────────────────────────────────────────
const UPLOAD_DIR = process.env.QUESTION_IMG_DIR || path.join(__dirname, 'uploads', 'questions');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename:    (_, file, cb) => {
    const ext  = path.extname(file.originalname).toLowerCase();
    const name = crypto.randomBytes(16).toString('hex') + ext;
    cb(null, name);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  fileFilter: (_, file, cb) => {
    if (['.jpg','.jpeg','.png','.gif','.webp'].includes(path.extname(file.originalname).toLowerCase()))
      return cb(null, true);
    cb(new Error('Only image files allowed.'));
  },
});

// ─── Question Schema ──────────────────────────────────────────────────────────
const OptionSchema = new mongoose.Schema({
  text:       { type: String, required: true },
  imageUrl:   { type: String, default: '' },
  isCorrect:  { type: Boolean, default: false },
});

const QuestionSchema = new mongoose.Schema({
  subject:        { type: String, required: true, index: true },
  topic:          { type: String, required: true, index: true },
  subtopic:       { type: String, default: '' },
  questionText:   { type: String, required: true },
  questionImage:  { type: String, default: '' },
  options:        { type: [OptionSchema], validate: v => v.length >= 2 && v.length <= 5 },
  explanation:    { type: String, default: '' },
  explanationImg: { type: String, default: '' },
  difficulty:     { type: String, enum: ['easy', 'medium', 'hard'], default: 'medium' },
  examTags:       { type: [String], default: [] }, // ['NEET PG', 'INICET', 'UPSC CMS']
  year:           { type: Number, default: null },  // PYQ year
  isActive:       { type: Boolean, default: true },
  isEncrypted:    { type: Boolean, default: false },
  reportCount:    { type: Number, default: 0 },
  reports:        [{
    userId:   String,
    reason:   String,
    timestamp:{ type: Date, default: Date.now },
  }],
  createdBy:  { type: String, default: 'admin' },
  createdAt:  { type: Date, default: Date.now },
  updatedAt:  { type: Date, default: Date.now },
}, { collection: 'questions' });

QuestionSchema.index({ subject: 1, topic: 1 });
QuestionSchema.index({ examTags: 1 });
QuestionSchema.index({ '$**': 'text' }); // full-text search

const Question = mongoose.models.Question || mongoose.model('Question', QuestionSchema);

// ─── GET /api/admin/questions ─────────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const page    = Math.max(1, parseInt(req.query.page) || 1);
    const limit   = Math.min(100, parseInt(req.query.limit) || 20);
    const skip    = (page - 1) * limit;
    const filter  = {};

    if (req.query.subject)    filter.subject    = req.query.subject;
    if (req.query.topic)      filter.topic      = req.query.topic;
    if (req.query.difficulty) filter.difficulty = req.query.difficulty;
    if (req.query.examTag)    filter.examTags   = req.query.examTag;
    if (req.query.isActive !== undefined) filter.isActive = req.query.isActive === 'true';
    if (req.query.reported)   filter.reportCount = { $gt: 0 };
    if (req.query.search) {
      filter.$text = { $search: req.query.search };
    }

    const [questions, total] = await Promise.all([
      Question.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      Question.countDocuments(filter),
    ]);

    res.json({ questions, total, page, pages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch questions.' });
  }
});

// ─── GET /api/admin/questions/stats ──────────────────────────────────────────
router.get('/stats', async (req, res) => {
  try {
    const [total, active, reported, bySubject, byDifficulty, byExam] = await Promise.all([
      Question.countDocuments(),
      Question.countDocuments({ isActive: true }),
      Question.countDocuments({ reportCount: { $gt: 0 } }),
      Question.aggregate([{ $group: { _id: '$subject', count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
      Question.aggregate([{ $group: { _id: '$difficulty', count: { $sum: 1 } } }]),
      Question.aggregate([{ $unwind: '$examTags' }, { $group: { _id: '$examTags', count: { $sum: 1 } } }]),
    ]);
    res.json({
      total, active, reported,
      bySubject:    bySubject.map(s => ({ subject: s._id, count: s.count })),
      byDifficulty: Object.fromEntries(byDifficulty.map(d => [d._id, d.count])),
      byExam:       Object.fromEntries(byExam.map(e => [e._id, e.count])),
    });
  } catch (err) {
    res.status(500).json({ error: 'Stats failed.' });
  }
});

// ─── GET /api/admin/questions/:id ─────────────────────────────────────────────
router.get('/:id', async (req, res) => {
  try {
    const q = await Question.findById(req.params.id).lean();
    if (!q) return res.status(404).json({ error: 'Question not found.' });
    res.json(q);
  } catch {
    res.status(400).json({ error: 'Invalid ID.' });
  }
});

// ─── POST /api/admin/questions ────────────────────────────────────────────────
router.post('/', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const { subject, topic, subtopic, questionText, options, explanation, difficulty, examTags, year } = req.body;

    if (!subject || !topic || !questionText || !options?.length) {
      return res.status(400).json({ error: 'subject, topic, questionText, options are required.' });
    }
    if (!options.some(o => o.isCorrect)) {
      return res.status(400).json({ error: 'At least one option must be correct.' });
    }

    const q = await Question.create({
      subject, topic, subtopic: subtopic || '',
      questionText, options, explanation: explanation || '',
      difficulty: difficulty || 'medium',
      examTags: examTags || [],
      year: year || null,
      createdBy: req.admin.username,
    });

    res.status(201).json(q);
  } catch (err) {
    res.status(500).json({ error: 'Question creation failed.', detail: err.message });
  }
});

// ─── PUT /api/admin/questions/:id ─────────────────────────────────────────────
router.put('/:id', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const allowed = ['subject','topic','subtopic','questionText','options','explanation',
                     'difficulty','examTags','year','isActive','explanationImg','questionImage'];
    const updates = { updatedAt: new Date() };
    for (const key of allowed) {
      if (req.body[key] !== undefined) updates[key] = req.body[key];
    }
    const q = await Question.findByIdAndUpdate(req.params.id, updates, { new: true, runValidators: true });
    if (!q) return res.status(404).json({ error: 'Question not found.' });
    res.json(q);
  } catch (err) {
    res.status(500).json({ error: 'Update failed.', detail: err.message });
  }
});

// ─── DELETE /api/admin/questions/:id ─────────────────────────────────────────
router.delete('/:id', requireRole('superadmin'), async (req, res) => {
  try {
    await Question.findByIdAndDelete(req.params.id);
    res.json({ message: 'Question deleted.' });
  } catch {
    res.status(500).json({ error: 'Deletion failed.' });
  }
});

// ─── POST /api/admin/questions/:id/image ──────────────────────────────────────
router.post('/:id/image', requireRole('superadmin', 'admin'), upload.single('image'), async (req, res) => {
  try {
    const field = req.body.field || 'questionImage'; // or 'explanationImg'
    if (!['questionImage', 'explanationImg'].includes(field)) {
      return res.status(400).json({ error: 'Invalid field.' });
    }
    const imgUrl = `/question-images/${req.file.filename}`;
    const q = await Question.findByIdAndUpdate(req.params.id, { [field]: imgUrl, updatedAt: new Date() }, { new: true });
    if (!q) return res.status(404).json({ error: 'Question not found.' });
    res.json({ imageUrl: imgUrl, question: q });
  } catch (err) {
    res.status(500).json({ error: 'Image upload failed.', detail: err.message });
  }
});

// ─── POST /api/admin/questions/bulk-import ───────────────────────────────────
router.post('/bulk-import', requireRole('superadmin'), async (req, res) => {
  try {
    const { questions } = req.body;
    if (!Array.isArray(questions) || !questions.length) {
      return res.status(400).json({ error: 'questions array required.' });
    }

    const toInsert = questions.map(q => ({ ...q, createdBy: req.admin.username, createdAt: new Date(), updatedAt: new Date() }));
    const result   = await Question.insertMany(toInsert, { ordered: false });
    res.json({ inserted: result.length, total: questions.length });
  } catch (err) {
    res.status(500).json({ error: 'Bulk import failed.', detail: err.message });
  }
});

// ─── GET /api/admin/questions/subjects/list ───────────────────────────────────
router.get('/subjects/list', async (req, res) => {
  try {
    const subjects = await Question.distinct('subject');
    res.json(subjects.sort());
  } catch {
    res.status(500).json({ error: 'Failed to fetch subjects.' });
  }
});

// ─── GET /api/admin/questions/reports/list ───────────────────────────────────
router.get('/reports/list', async (req, res) => {
  try {
    const questions = await Question.find({ reportCount: { $gt: 0 } })
      .sort({ reportCount: -1 }).limit(50)
      .select('questionText subject topic reportCount reports')
      .lean();
    res.json(questions);
  } catch {
    res.status(500).json({ error: 'Failed to fetch reports.' });
  }
});

// ─── POST /api/admin/questions/:id/dismiss-reports ───────────────────────────
router.post('/:id/dismiss-reports', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    await Question.findByIdAndUpdate(req.params.id, { reportCount: 0, reports: [] });
    res.json({ message: 'Reports dismissed.' });
  } catch {
    res.status(500).json({ error: 'Failed.' });
  }
});

module.exports = router;
