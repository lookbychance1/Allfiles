const mongoose = require('mongoose');

const AuditSchema = new mongoose.Schema({
  adminId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  username:  String,
  action:    String,
  ip:        String,
  userAgent: String,
  meta:      mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now },
}, { collection: 'admin_audit_logs' });

module.exports = mongoose.models.AuditLog || mongoose.model('AuditLog', AuditSchema);
