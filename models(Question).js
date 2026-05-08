const mongoose = require('mongoose');

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
  examTags:       { type: [String], default: [] },
  year:           { type: Number, default: null },
  isActive:       { type: Boolean, default: true },
  isEncrypted:    { type: Boolean, default: false },
  reportCount:    { type: Number, default: 0 },
  reports:        [{ userId: String, reason: String, timestamp:{ type: Date, default: Date.now } }],
  createdBy:  { type: String, default: 'admin' },
  createdAt:  { type: Date, default: Date.now },
  updatedAt:  { type: Date, default: Date.now },
}, { collection: 'questions' });

module.exports = mongoose.models.Question || mongoose.model('Question', QuestionSchema);
