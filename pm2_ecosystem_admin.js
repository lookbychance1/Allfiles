/**
 * pm2_ecosystem_admin.js — PM2 Config for Admin Microservice
 * Run: pm2 start pm2_ecosystem_admin.js
 * Or:  pm2 startOrRestart pm2_ecosystem_admin.js
 */

module.exports = {
  apps: [
    {
      name:         'solvemcq-admin',
      script:       './admin-server.js',
      instances:    2,                        // cluster mode — 2 workers
      exec_mode:    'cluster',
      watch:        false,
      max_memory_restart: '512M',

      // ─── Environment: Production ──────────────────────────────────────────
      env_production: {
        NODE_ENV:   'production',
        ADMIN_PORT: 4000,
      },

      // ─── Environment: Development ─────────────────────────────────────────
      env_development: {
        NODE_ENV:   'development',
        ADMIN_PORT: 4001,
        DEBUG:      'admin:*',
      },

      // ─── Logging ──────────────────────────────────────────────────────────
      out_file:      './logs/admin-out.log',
      error_file:    './logs/admin-err.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs:    true,

      // ─── Auto-restart ─────────────────────────────────────────────────────
      autorestart:   true,
      restart_delay: 3000,
      max_restarts:  10,

      // ─── Graceful shutdown ────────────────────────────────────────────────
      kill_timeout:  5000,
      listen_timeout:3000,

      // ─── Cron restart (2:30 AM IST daily) ────────────────────────────────
      cron_restart:  '0 21 * * *',           // 2:30 AM IST = 21:00 UTC

      // ─── Source map support ───────────────────────────────────────────────
      source_map_support: false,

      // ─── Node.js args ─────────────────────────────────────────────────────
      node_args: '--max-old-space-size=512',
    },
  ],

  /**
   * ─── Deployment Config ────────────────────────────────────────────────────
   * pm2 deploy pm2_ecosystem_admin.js production setup
   * pm2 deploy pm2_ecosystem_admin.js production
   */
  deploy: {
    production: {
      user:         process.env.DEPLOY_USER || 'ubuntu',
      host:         process.env.DEPLOY_HOST || 'managemcq.sharepremium.in',
      ref:          'origin/main',
      repo:         process.env.DEPLOY_REPO || 'git@github.com:your-org/solvemcq-admin.git',
      path:         '/var/www/solvemcq-admin',
      'pre-deploy-local': '',
      'post-deploy': 'npm install --production && pm2 startOrRestart pm2_ecosystem_admin.js --env production',
      'pre-setup':   '',
      env: {
        NODE_ENV: 'production',
      },
    },
  },
};
