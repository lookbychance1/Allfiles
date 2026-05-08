const fs = require('fs');
const readline = require('readline');

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

module.exports = { parseLogLine };
