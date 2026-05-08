/**
 * Data loader - loads encrypted JSON files and builds subject/topic index
 * v9: file-scoped subjKey prevents cross-file subject/topic key collisions
 *     + getQuestionsAtIndices / getAllQuestionsForTopic for filtered session support
 *
 * Root cause fixed: when multiple JSON files share the same subject name
 * (e.g. "Anatomy" in both MarrowPYQ.json and MarrowEd8.json), the old code
 * slugified to the same key "anatomy" and silently dropped the second file's
 * subject entirely (skipped by `if (!subjectIndex[subjKey])`). Topic data
 * suffered the same overwrite: topicData["anatomy_1"] from the second file
 * would silently clobber the first.
 *
 * Fix: subjKey is now prefixed with a per-file slug so each file owns its
 * own namespace: "marrowpyq__anatomy", "marrowqb__anatomy", etc.
 * The frontend never constructs subjKey itself — it always comes from the
 * /api/main-subjects response — so this is a transparent rename.
 */
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { unprotect } = require('./encrypt');

const DATA_DIR = path.join(__dirname, 'data');

let subjectIndex = null;   // subjKey -> { displayName, mainSubject, topics, sourceFile }
let mainSubjectIndex = null; // mainSubject -> [subjKey, ...]
let topicData = {};

function slugify(str) {
  return str.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
}

function parseFile(file) {
  const filePath = path.join(DATA_DIR, file);
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    let decrypted;
    try {
      decrypted = unprotect(raw);
    } catch (e) {
      console.warn(`⚠️ Decryption failed for ${file}, trying raw JSON`);
      decrypted = raw;
    }
    return JSON.parse(decrypted);
  } catch (e) {
    console.error(`❌ Failed to parse file ${file}:`, e.message);
    return null;
  }
}

function loadAllData() {
  if (subjectIndex) return;

  subjectIndex = {};
  mainSubjectIndex = {};
  topicData = {};

  const files = fs.readdirSync(DATA_DIR).filter(f => f.endsWith('.json'));

  let totalQ = 0;
  let totalSubjects = 0;

  for (const file of files) {
    console.log(`\n📂 Processing file: ${file}`);

    const data = parseFile(file);
    if (!data) continue;

    if (!data.subjects || typeof data.subjects !== 'object') {
      console.warn(`⚠️ Skipping ${file} (no valid subjects)`);
      continue;
    }

    // Top-level main_subject from the file (e.g. "Cerebellum PYQ")
    const fileMainSubject = data.main_subject || data.title || file.replace('.json', '');

    // Per-file namespace prefix derived from source_directory > filename stem.
    // This prevents "anatomy" in MarrowPYQ.json from colliding with "anatomy"
    // in MarrowEd8.json — they become "marrowpyq__anatomy" vs "marrowqb__anatomy".
    const filePrefix = slugify(data.source_directory || file.replace('.json', ''));

    console.log(`Subjects found:`, Object.keys(data.subjects));

    for (const [subjName, subjData] of Object.entries(data.subjects)) {
      // File-scoped key: "<filePrefix>__<subjectSlug>"
      const subjKey = `${filePrefix}__${slugify(subjName)}`;

      // Per-subject main_subject: prefer subject-level field, then fall back to file-level
      const mainSubject = subjData.main_subject || fileMainSubject;

      if (!subjectIndex[subjKey]) {
        subjectIndex[subjKey] = {
          displayName: subjName,
          mainSubject,
          topics: [],
          sourceFile: file
        };
        totalSubjects++;
      }

      // Build mainSubjectIndex
      const msKey = mainSubject;
      if (!mainSubjectIndex[msKey]) mainSubjectIndex[msKey] = [];
      if (!mainSubjectIndex[msKey].includes(subjKey)) {
        mainSubjectIndex[msKey].push(subjKey);
      }

      const topics = Array.isArray(subjData.topics) ? subjData.topics : [];

      for (const topic of topics) {
        const topicKey = `${subjKey}_${topic.topic_id}`;
        const questions = Array.isArray(topic.questions) ? topic.questions : [];

        if (!Array.isArray(topic.questions)) {
          console.warn(`⚠️ Missing questions in ${file} → ${subjName} → ${topic.topic_name}`);
        }

        console.log(`   ➤ Topic: ${topic.topic_name} | Q: ${questions.length}`);

        if (!subjectIndex[subjKey].topics.find(t => t.id === topic.topic_id)) {
          subjectIndex[subjKey].topics.push({
            id: topic.topic_id,
            name: topic.topic_name,
            count: questions.length
          });
        }

        topicData[topicKey] = questions;
        totalQ += questions.length;
      }
    }
  }

  console.log(`\n✅ Indexed ${totalSubjects} subjects across ${Object.keys(mainSubjectIndex).length} main subjects, ${totalQ} questions across ${files.length} files`);
}

function getSubjectIndex() {
  loadAllData();
  return subjectIndex;
}

/**
 * Returns grouped structure:
 * { "Cerebellum PYQ": { subjects: { subjKey: { displayName, topics } } } }
 */
function getMainSubjectIndex() {
  loadAllData();
  const result = {};
  for (const [ms, subjKeys] of Object.entries(mainSubjectIndex)) {
    result[ms] = { subjects: {} };
    for (const sk of subjKeys) {
      const s = subjectIndex[sk];
      if (s) {
        result[ms].subjects[sk] = {
          displayName: s.displayName,
          topics: s.topics.map(t => ({ id: t.id, name: t.name, count: t.count }))
        };
      }
    }
  }
  return result;
}

function getTopicLength(subjKey, topicId) {
  loadAllData();
  const key = `${subjKey}_${topicId}`;
  return topicData[key]?.length || 0;
}

function getQuestionAtIndex(subjKey, topicId, index) {
  loadAllData();
  const key = `${subjKey}_${topicId}`;
  const questions = topicData[key];
  if (!questions || index < 0 || index >= questions.length) return null;
  const q = questions[index];
  return {
    id: q.id,
    number: q.question_number,
    text: q.text,
    options: q.options,
    correct: q.correct_answer,
    explanation: q.explanation,
    images: q.question_images || [],
    explImages: q.explanation_images || [],
    audio: q.audio || '',
    video: q.video || ''
  };
}

/**
 * Get questions at specific global indices (for filtered sessions).
 * Returns array of { globalIndex, question } pairs, skipping any out-of-range indices.
 */
function getQuestionsAtIndices(subjKey, topicId, indices) {
  loadAllData();
  const key = `${subjKey}_${topicId}`;
  const questions = topicData[key];
  if (!questions) return [];
  return indices.map(idx => {
    if (idx < 0 || idx >= questions.length) return null;
    const q = questions[idx];
    return {
      globalIndex: idx,
      question: {
        id: q.id,
        number: q.question_number,
        text: q.text,
        options: q.options,
        correct: q.correct_answer,
        explanation: q.explanation,
        images: q.question_images || [],
        explImages: q.explanation_images || [],
        audio: q.audio || '',
        video: q.video || ''
      }
    };
  }).filter(Boolean);
}

/**
 * Get all raw questions for a topic (used internally for index mapping).
 */
function getAllQuestionsForTopic(subjKey, topicId) {
  loadAllData();
  const key = `${subjKey}_${topicId}`;
  return topicData[key] || [];
}

module.exports = {
  getSubjectIndex,
  getMainSubjectIndex,
  getQuestionAtIndex,
  getQuestionsAtIndices,
  getAllQuestionsForTopic,
  getTopicLength,
  loadAllData
};
