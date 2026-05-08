/**
 * PM2 Ecosystem File
 * Place at: /var/www/admin-dashboard/ecosystem.config.js
 *
 * Commands:
 *   pm2 start ecosystem.config.js
 *   pm2 save
 *   pm2 startup   (auto-start on reboot)
 *   pm2 monit     (live dashboard)
 *   pm2 logs admin-server --lines 100
 */

module.exports = {
  apps: [
    // ── Main SolveMCQ backend (your existing server.js) ──────────
    {
      name:         'solvemcq-main',
      script:       '/var/www/solvemcq/backend/server.js',
      instances:    2,                   // cluster mode — 2 workers
      exec_mode:    'cluster',
      watch:        false,
      max_memory_restart: '512M',
      env: {
        NODE_ENV: 'production',
        PORT:     3000,
      },
      error_file:   '/var/log/pm2/solvemcq-main-error.log',
      out_file:     '/var/log/pm2/solvemcq-main-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss IST',
      merge_logs:   true,
      restart_delay: 3000,
      exp_backoff_restart_delay: 100,
    },

    // ── Admin dashboard backend ───────────────────────────────────
    {
      name:         'admin-server',
      script:       '/var/www/admin-dashboard/backend/admin-server.js',
      instances:    1,                   // single instance — admin traffic is low
      exec_mode:    'fork',
      watch:        false,
      max_memory_restart: '256M',
      env: {
        NODE_ENV: 'production',
      },
      error_file:   '/var/log/pm2/admin-error.log',
      out_file:     '/var/log/pm2/admin-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss IST',
      merge_logs:   true,
      restart_delay: 5000,
      exp_backoff_restart_delay: 200,
      // Only bind to localhost — Nginx is the only thing that should hit this
      listen_timeout: 8000,
    },
  ],
};
