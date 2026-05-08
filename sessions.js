/**
 * sessions.js — Redis-backed version
 * Replaces in-memory Map with Redis so all PM2 cluster workers
 * share the same exam session state.
 *
 * Redis key layout:
 *   sess:{sessionId}          → JSON session object    TTL = SESSION_TTL
 *   fetchlog:{sessionId}      → JSON array of timestamps  TTL = SESSION_TTL
 *
 * v8: server-authoritative section timers + batch section question fetch
 *     + media fields (images/audio/video) + section access enforcement
 *     + filtered sessions: 'incorrect', 'skipped', 'all' filter support
 *
 * REBOOT SURVIVAL: Sessions survive full server reboots when Redis is
 * configured with AOF persistence (appendonly yes). See redis.conf notes
 * in the README. startedAt timestamps are wall-clock epoch ms, so section
 * timers automatically account for any downtime after restart.
 */

const { v4: uuidv4 } = require('uuid');
const { createClient } = require('redis');
const { getTopicLength, getQuestionAtIndex } = require('./dataLoader');

const SESSION_TTL    = 4 * 60 * 60 * 1000;  // 4 hours in ms
const MAX_Q_PER_MIN  = 120;
const SECS_PER_Q     = 63;
const MAX_SEC_SIZE   = 40;

// ── Redis client ──────────────────────────────────────────────────────────────
const redis = createClient({
  url: process.env.REDIS_URL || 'redis://127.0.0.1:6379',
  socket: { reconnectStrategy: retries => Math.min(retries * 100, 3000) }
});

redis.on('error', err => console.error('[Redis] sessions error:', err.message));
redis.on('connect', () => console.log('[Redis] sessions connected'));

async function initRedis() {
  if (!redis.isOpen) await redis.connect();
}

// ── Redis helpers ─────────────────────────────────────────────────────────────
function sessKey(id)  { return `sess:${id}`; }
function logKey(id)   { return `fetchlog:${id}`; }

async function loadSession(sessionId) {
  try {
    const raw = await redis.get(sessKey(sessionId));
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

async function saveSession(s) {
  const ttl = Math.max(SESSION_TTL - (Date.now() - s.startTime), 60000);
  await redis.set(sessKey(s.id), JSON.stringify(s), { PX: ttl });
}

async function deleteSession(sessionId) {
  await redis.del(sessKey(sessionId));
  await redis.del(logKey(sessionId));
}

// ── Section builders ──────────────────────────────────────────────────────────
function buildSections(total) {
  const sections = [];
  let remaining = total;
  for (let i = 0; remaining > 0; i++) {
    const size = Math.min(MAX_SEC_SIZE, remaining);
    sections.push({ index: i, start: i * MAX_SEC_SIZE, total: size, startedAt: null, expired: false });
    remaining -= size;
  }
  return sections;
}

function buildFilteredSections(indexMap) {
  const total = indexMap.length;
  const sections = [];
  let remaining = total;
  for (let i = 0; remaining > 0; i++) {
    const size = Math.min(MAX_SEC_SIZE, remaining);
    sections.push({ index: i, start: i * MAX_SEC_SIZE, total: size, startedAt: null, expired: false });
    remaining -= size;
  }
  return sections;
}

// ── Rate limit helper ─────────────────────────────────────────────────────────
async function checkRateLimit(sessionId, count = 1) {
  try {
    const raw  = await redis.get(logKey(sessionId));
    const now  = Date.now();
    const log  = raw ? JSON.parse(raw) : [];
    const recent = log.filter(t => now - t < 60000);
    if (recent.length + count > MAX_Q_PER_MIN) {
      await redis.set(logKey(sessionId), JSON.stringify(recent), { PX: 61000 });
      return false;
    }
    for (let i = 0; i < count; i++) recent.push(now);
    await redis.set(logKey(sessionId), JSON.stringify(recent), { PX: 61000 });
    return true;
  } catch { return true; } // fail open on Redis error
}

function resolveGlobalIndex(session, localIndex) {
  if (session.indexMap) return session.indexMap[localIndex];
  return localIndex;
}

// ── Public API ────────────────────────────────────────────────────────────────

async function createSession(userId, subjKey, topicId, mode, filter = 'all', topicStats = null) {
  const allTotal = getTopicLength(subjKey, topicId);
  if (!allTotal) return null;

  let indexMap = null;
  if (filter === 'incorrect' || filter === 'skipped') {
    const stats = topicStats?.questions || {};
    indexMap = [];
    for (let i = 0; i < allTotal; i++) {
      const q  = stats[String(i)] || stats[i];
      if (!q) continue;
      const st = q.state;
      if (filter === 'incorrect' && (st ? st === 'incorrect' : (q.incorrect || 0) > 0)) indexMap.push(i);
      if (filter === 'skipped'   && (st ? st === 'skipped'   : (q.skipped   || 0) > 0)) indexMap.push(i);
    }
    if (indexMap.length === 0) indexMap = null;
  }

  const total     = indexMap ? indexMap.length : allTotal;
  const sessionId = uuidv4();

  const s = {
    id: sessionId,
    userId,
    subjKey,
    topicId,
    mode,
    filter,
    indexMap,
    total,
    sections: mode === 'real' ? (indexMap ? buildFilteredSections(indexMap) : buildSections(total)) : [],
    activeSec:    0,
    current:      0,
    answers:      {},
    submitted:    {},
    marked:       {},
    startTime:    Date.now(),
    lastActivity: Date.now(),
    finished:     false
  };

  await saveSession(s);
  return sessionId;
}

async function getSession(sessionId) {
  const s = await loadSession(sessionId);
  if (!s) return null;
  // Redis TTL is the authoritative expiry — it survives reboots when AOF
  // persistence is enabled. We do NOT re-check lastActivity here because
  // that would incorrectly expire sessions that were idle during a reboot.
  s.lastActivity = Date.now();
  await saveSession(s);
  return s;
}

async function fetchQuestion(sessionId, index) {
  const session = await getSession(sessionId);
  if (!session) return { error: 'Session expired or invalid' };
  if (session.finished) return { error: 'Session already finished' };
  if (index < 0 || index >= session.total) return { error: 'Question index out of bounds' };

  if (index >= session.current && !await checkRateLimit(sessionId, 1)) {
    return { error: 'Rate limited - please slow down' };
  }

  if (session.mode === 'real') {
    const secIdx = Math.floor(index / MAX_SEC_SIZE);
    if (secIdx !== session.activeSec) return { error: 'Section not yet accessible' };
  }

  const globalIdx = resolveGlobalIndex(session, index);
  const q = getQuestionAtIndex(session.subjKey, session.topicId, globalIdx);
  if (!q) return { error: 'Question not found' };

  if (index + 1 > session.current) session.current = index + 1;
  await saveSession(session);

  const isAnswered   = session.submitted[index] !== undefined;
  const revealAnswer = session.mode === 'test' && isAnswered;

  return {
    question: {
      id: q.id, number: index + 1, total: session.total, globalIndex: globalIdx,
      text: q.text,
      options: q.options.map(o => ({ label: o.label, text: o.text })),
      images: q.images || [], audio: q.audio || '', video: q.video || '',
      ...(revealAnswer ? { correct: q.correct, explanation: q.explanation, explImages: q.explImages || [] } : {})
    },
    sessionInfo: {
      mode: session.mode, filter: session.filter,
      current: session.current, answered: Object.keys(session.submitted).length
    }
  };
}

async function fetchSectionBatch(sessionId, secIndex) {
  const session = await getSession(sessionId);
  if (!session) return { error: 'Session expired or invalid' };
  if (session.finished) return { error: 'Session already finished' };
  if (session.mode !== 'real') return { error: 'Batch fetch only available in real exam mode' };
  if (secIndex !== session.activeSec) return { error: 'This section is not yet accessible. Complete the current section first.' };

  const sec = session.sections[secIndex];
  if (!sec) return { error: 'Invalid section index' };

  if (!await checkRateLimit(sessionId, sec.total)) return { error: 'Rate limited' };

  if (!sec.startedAt) sec.startedAt = Date.now();

  const questions = [];
  for (let i = 0; i < sec.total; i++) {
    const localIdx  = sec.start + i;
    const globalIdx = resolveGlobalIndex(session, localIdx);
    const q = getQuestionAtIndex(session.subjKey, session.topicId, globalIdx);
    if (!q) continue;
    if (localIdx + 1 > session.current) session.current = localIdx + 1;
    questions.push({
      id: q.id, number: localIdx + 1, total: session.total, globalIndex: globalIdx,
      text: q.text,
      options: q.options.map(o => ({ label: o.label, text: o.text })),
      images: q.images || [], audio: q.audio || '', video: q.video || ''
    });
  }

  await saveSession(session);

  const totalSecs = sec.total * SECS_PER_Q;
  const elapsed   = Math.floor((Date.now() - sec.startedAt) / 1000);
  const timeLeft  = Math.max(0, totalSecs - elapsed);

  return {
    section: { index: secIndex, start: sec.start, total: sec.total, expired: sec.expired, activeSec: session.activeSec, totalSections: session.sections.length },
    questions,
    timer: { totalSecs, elapsed, timeLeft, startedAt: sec.startedAt }
  };
}

async function getSectionTimer(sessionId, secIndex) {
  const session = await getSession(sessionId);
  if (!session) return { error: 'Session expired or invalid' };
  if (session.mode !== 'real') return { error: 'Timer only in real mode' };

  const sec = session.sections[secIndex];
  if (!sec) return { error: 'Invalid section' };

  if (!sec.startedAt) return {
    timeLeft: sec.total * SECS_PER_Q, totalSecs: sec.total * SECS_PER_Q,
    elapsed: 0, started: false, activeSec: session.activeSec, totalSections: session.sections.length
  };

  const totalSecs = sec.total * SECS_PER_Q;
  const elapsed   = Math.floor((Date.now() - sec.startedAt) / 1000);
  const timeLeft  = Math.max(0, totalSecs - elapsed);

  if (timeLeft <= 0 && !sec.expired) {
    sec.expired = true;
    if (session.activeSec === secIndex && secIndex + 1 < session.sections.length) {
      session.activeSec = secIndex + 1;
    }
    await saveSession(session);
  }

  return { timeLeft, totalSecs, elapsed, started: true, expired: sec.expired, activeSec: session.activeSec, totalSections: session.sections.length };
}

async function expireSection(sessionId, secIndex) {
  const session = await getSession(sessionId);
  if (!session) return { error: 'Session expired or invalid' };
  if (session.mode !== 'real') return { error: 'Real mode only' };

  const sec = session.sections[secIndex];
  if (!sec) return { error: 'Invalid section index' };

  if (!sec.expired) sec.expired = true;
  if (session.activeSec === secIndex && secIndex + 1 < session.sections.length) {
    session.activeSec = secIndex + 1;
    const nextSec = session.sections[session.activeSec];
    if (nextSec && !nextSec.startedAt) nextSec.startedAt = Date.now();
  }

  await saveSession(session);

  return {
    ok: true, expiredSec: secIndex, activeSec: session.activeSec,
    totalSections: session.sections.length,
    isLastSection: secIndex >= session.sections.length - 1
  };
}

async function submitAnswer(sessionId, index, selectedLabel) {
  const session = await getSession(sessionId);
  if (!session) return { error: 'Session expired or invalid' };
  if (session.finished) return { error: 'Session already finished' };
  if (index < 0 || index >= session.total) return { error: 'Invalid question index' };

  if (session.mode === 'real') {
    const secIdx = Math.floor(index / MAX_SEC_SIZE);
    if (secIdx !== session.activeSec) return { error: 'Cannot submit answer for a locked section' };
  }

  const globalIdx = resolveGlobalIndex(session, index);
  const q = getQuestionAtIndex(session.subjKey, session.topicId, globalIdx);
  if (!q) return { error: 'Question not found' };

  const correctLabel = q.options.find(o => o.is_correct)?.label;
  const isCorrect    = selectedLabel === correctLabel;

  session.answers[index]   = { selected: selectedLabel, isCorrect, correctLabel, globalIndex: globalIdx };
  session.submitted[index] = true;
  if (index + 1 > session.current) session.current = index + 1;

  await saveSession(session);

  const result = { isCorrect, correctLabel, globalIndex: globalIdx, score: computeScore(session) };

  if (session.mode === 'test') {
    result.correct      = q.correct;
    result.explanation  = q.explanation;
    result.explImages   = q.explImages || [];
    result.options      = q.options.map(o => ({ label: o.label, text: o.text, is_correct: o.is_correct }));
  }

  return result;
}

function computeScore(session) {
  let correct = 0, incorrect = 0;
  const answered = Object.keys(session.answers).length;
  for (const ans of Object.values(session.answers)) {
    if (!ans.selected) continue;
    if (ans.isCorrect) correct++; else incorrect++;
  }
  return {
    correct, incorrect,
    unattempted: session.total - answered,
    total: session.total,
    score: correct * 4 - incorrect,
    maxScore: session.total * 4
  };
}

async function finishSession(sessionId) {
  const session = await getSession(sessionId);
  if (!session) return { error: 'Session expired or invalid' };
  session.finished = true;

  const results = [];
  for (let i = 0; i < session.total; i++) {
    const globalIdx = resolveGlobalIndex(session, i);
    const q   = getQuestionAtIndex(session.subjKey, session.topicId, globalIdx);
    const ans = session.answers[i];
    results.push({
      number: i + 1, globalIndex: globalIdx,
      text: q?.text || '',
      options: q?.options?.map(o => ({ label: o.label, text: o.text })) || [],
      correct: q?.correct || '', explanation: q?.explanation || '',
      images: q?.images || [], explImages: q?.explImages || [],
      audio: q?.audio || '', video: q?.video || '',
      selected: ans?.selected || null,
      isCorrect: ans?.isCorrect || false,
      skipped: !ans || !ans.selected
    });
  }

  await saveSession(session); // save finished=true

  return {
    score: computeScore(session),
    results,
    timeTaken: Math.round((Date.now() - session.startTime) / 1000),
    filter: session.filter,
    indexMap: session.indexMap
  };
}

module.exports = { initRedis, createSession, getSession, fetchQuestion, fetchSectionBatch, getSectionTimer, expireSection, submitAnswer, finishSession };
