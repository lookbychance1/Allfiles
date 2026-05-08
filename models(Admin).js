const mongoose = require('mongoose');

const AdminSchema = new mongoose.Schema({
  username:        { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash:    { type: String, required: true },
  totpSecret:      { type: String, default: null },
  totpEnabled:     { type: Boolean, default: false },
  role:            { type: String, enum: ['superadmin', 'admin', 'viewer'], default: 'admin' },
  ipWhitelist:     { type: [String], default: [] },
  isActive:        { type: Boolean, default: true },
  lastLogin:       { type: Date, default: null },
  lastLoginIP:     { type: String, default: null },
  failedAttempts:  { type: Number, default: 0 },
  lockedUntil:     { type: Date, default: null },
  refreshTokens:   { type: [String], default: [] },
  createdAt:       { type: Date, default: Date.now },
}, { collection: 'admin_users' });

module.exports = mongoose.models.Admin || mongoose.model('Admin', AdminSchema);
