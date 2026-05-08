const mongoose = require('mongoose');

const DevToolIncidentSchema = new mongoose.Schema({
  adminId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', default: null },
  username:  { type: String, default: 'unknown' },
  ip:        { type: String, default: '' },
  userAgent: { type: String, default: '' },
  method:    { type: String, enum: ['resize','debugger','perf','keys','beacon','unknown'], default: 'unknown' },
  sessionId: { type: String, default: '' },
  blocked:   { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now },
}, { collection: 'admin_devtool_incidents' });

module.exports = mongoose.models.DevToolIncident || mongoose.model('DevToolIncident', DevToolIncidentSchema);
