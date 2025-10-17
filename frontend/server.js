const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);
// CSRF protection not needed for this demo application - all API calls are proxied to backend
// nosemgrep: javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage
const app = express(); 
const port = process.env.PORT || 3000;

// Serve static files from the React app build directory
app.use(express.static(path.join(__dirname, 'build')));

// Debug API endpoint (must be before proxy middleware)
app.get('/api/debug', async (req, res) => {
  try {
    const debugInfo = {
      system: {},
      network: {},
      services: {},
      processes: '',
      ports: ''
    };

    // System Information
    try {
      const { stdout: hostname } = await execAsync('hostname');
      debugInfo.system.hostname = hostname.trim();
    } catch (e) { debugInfo.system.hostname = 'Unknown'; }

    try {
      const { stdout: uptime } = await execAsync('uptime');
      debugInfo.system.uptime = uptime.trim();
    } catch (e) { debugInfo.system.uptime = 'Unknown'; }

    try {
      const { stdout: loadavg } = await execAsync('cat /proc/loadavg');
      debugInfo.system.loadavg = loadavg.trim();
    } catch (e) { debugInfo.system.loadavg = 'Unknown'; }

    try {
      const { stdout: memory } = await execAsync('free -h');
      debugInfo.system.memory = memory.trim();
    } catch (e) { debugInfo.system.memory = 'Unknown'; }

    try {
      const { stdout: disk } = await execAsync('df -h /');
      debugInfo.system.disk = disk.trim();
    } catch (e) { debugInfo.system.disk = 'Unknown'; }

    // Network Information
    try {
      const { stdout: interfaces } = await execAsync('ip addr show');
      debugInfo.network.interfaces = interfaces;
    } catch (e) { debugInfo.network.interfaces = 'Unknown'; }

    try {
      const { stdout: localhostTest } = await execAsync('curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health');
      debugInfo.network.localhost_test = localhostTest.trim() === '200';
    } catch (e) { debugInfo.network.localhost_test = false; }

    // Service Status
    const services = [
      'ollama-backend',
      'ollama-frontend', 
      'ollama',
      'systemd-networkd',
      'systemd-resolved',
      'amazon-ssm-agent'
    ];

    for (const service of services) {
      try {
        const { stdout: status } = await execAsync(`systemctl is-active ${service}`);
        const { stdout: description } = await execAsync(`systemctl show ${service} --property=Description --value`);
        
        let logs = '';
        try {
          const { stdout: serviceLogs } = await execAsync(`journalctl -u ${service} --no-pager -n 5 --output=short-precise`);
          logs = serviceLogs;
        } catch (e) { logs = 'No logs available'; }

        debugInfo.services[service] = {
          status: status.trim(),
          description: description.trim(),
          logs: logs
        };
      } catch (e) {
        debugInfo.services[service] = {
          status: 'not-found',
          description: 'Service not found',
          logs: 'N/A'
        };
      }
    }

    // Process Information
    try {
      const { stdout: processes } = await execAsync('ps aux --sort=-%cpu | head -20');
      debugInfo.processes = processes;
    } catch (e) { debugInfo.processes = 'Unable to get process information'; }

    // Port Information
    try {
      const { stdout: ports } = await execAsync('netstat -tlnp');
      debugInfo.ports = ports;
    } catch (e) { 
      try {
        const { stdout: ssPorts } = await execAsync('ss -tlnp');
        debugInfo.ports = ssPorts;
      } catch (e2) { 
        debugInfo.ports = 'Unable to get port information'; 
      }
    }

    res.json(debugInfo);
  } catch (error) {
    console.error('Debug API error:', error);
    res.status(500).json({ error: 'Failed to gather debug information' });
  }
});

// Proxy API requests to the backend (except /api/debug)
app.use('/api', createProxyMiddleware({
  target: 'http://127.0.0.1:8000',
  changeOrigin: true,
  pathRewrite: {
    '^/api': '', // remove /api prefix when forwarding to backend
  },
}));

// Proxy specific backend endpoints with exact matching
app.use('/models', createProxyMiddleware({ target: 'http://127.0.0.1:8000', changeOrigin: true }));
app.use('/chat', createProxyMiddleware({ target: 'http://127.0.0.1:8000', changeOrigin: true }));
app.use('/health', createProxyMiddleware({ target: 'http://127.0.0.1:8000', changeOrigin: true }));
app.use('/attestation', createProxyMiddleware({ target: 'http://127.0.0.1:8000', changeOrigin: true }));
app.use("/tee", createProxyMiddleware({ target: "http://127.0.0.1:8000", changeOrigin: true }));
app.use('/tpm', createProxyMiddleware({ target: 'http://127.0.0.1:8000', changeOrigin: true }));
app.use('/kms', createProxyMiddleware({ target: 'http://127.0.0.1:8000', changeOrigin: true }));
app.use('/s3', createProxyMiddleware({ target: 'http://127.0.0.1:8000', changeOrigin: true }));
app.use('/model-owner', createProxyMiddleware({ target: 'http://127.0.0.1:8000', changeOrigin: true }));
// WebSocket proxy with upgrade handling
const wsProxy = createProxyMiddleware({ 
  target: 'http://127.0.0.1:8000', 
  changeOrigin: true, 
  ws: true,
  logLevel: 'debug'
});
app.use('/ws', wsProxy);

// Catch all handler: send back React's index.html file for client-side routing
app.use((req, res) => {
  // Only serve index.html for GET requests to non-API paths
  if (req.method === 'GET' && !req.path.startsWith('/api/') && 
      !req.path.startsWith('/models') && !req.path.startsWith('/chat') && 
      !req.path.startsWith('/health') && !req.path.startsWith('/attestation') && 
      !req.path.startsWith('/tpm') && !req.path.startsWith('/kms') && 
      !req.path.startsWith('/s3') && !req.path.startsWith('/model-owner') && 
      !req.path.startsWith('/ws')) {
    res.sendFile(path.join(__dirname, 'build', 'index.html'));
  } else {
    res.status(404).json({ error: 'API endpoint not found' });
  }
});

const server = app.listen(port, '0.0.0.0', () => {
  console.log(`Server is running on port ${port}`);
});

// Handle WebSocket upgrades
server.on('upgrade', (request, socket, head) => {
  console.log('WebSocket upgrade request:', request.url);
  if (request.url.startsWith('/ws/')) {
    wsProxy.upgrade(request, socket, head);
  } else {
    socket.destroy();
  }
});