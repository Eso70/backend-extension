module.exports = {
  apps: [
    {
      name: 'sponsor-krd-extension-api',
      script: 'server.js',
      cwd: __dirname,
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      time: true,
      restart_delay: 3000,
      max_memory_restart: '300M',
      kill_timeout: 12000,
      env: {
        NODE_ENV: 'production'
      }
    }
  ]
};
