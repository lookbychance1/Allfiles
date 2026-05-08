/**
 * Run this once to encrypt all JSON files in data/
 * After running, delete originals and keep only .enc files
  // MUST be first line */
require('dotenv').config();   // MUST be first line
const fs = require('fs');
const path = require('path');
const { protect } = require('./encrypt');

const DATA_DIR = path.join(__dirname, 'data');
const files = fs.readdirSync(DATA_DIR).filter(f => f.endsWith('.json'));

for (const file of files) {
  const raw = fs.readFileSync(path.join(DATA_DIR, file), 'utf8');
  const encrypted = protect(raw);
  // Overwrite with encrypted version (still .json extension, no hint of encryption)
  fs.writeFileSync(path.join(DATA_DIR, file), encrypted, 'utf8');
  console.log(`Protected: ${file} (${raw.length} -> ${encrypted.length} bytes)`);
}
console.log('All files protected.');
