import express, { Request, Response } from 'express';
import { chromium, Browser } from 'playwright';
import { analyzeClientSide } from './analyzer';

const app = express();
app.use(express.json());

const PORT = parseInt(process.env.PORT || '3001', 10);
const HOST = process.env.HOST || '0.0.0.0';
let browserInstance: Browser | null = null;
const startTime = new Date();

async function getBrowser(): Promise<Browser> {
  if (!browserInstance) {
    browserInstance = await chromium.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
      ],
    });
  }
  return browserInstance;
}

// Liveness probe (GET /health)
app.get('/health', (_req: Request, res: Response) => {
  const uptimeSeconds = (Date.now() - startTime.getTime()) / 1000;
  res.json({
    status: 'healthy',
    service: 'expose-browser-worker',
    runtime: 'Node.js / Playwright Chromium',
    version: '0.1.0',
    uptime_seconds: uptimeSeconds,
    timestamp: new Date().toISOString(),
  });
});

// Readiness probe (GET /ready)
app.get('/ready', async (_req: Request, res: Response) => {
  try {
    const browser = await getBrowser();
    const isConnected = browser.isConnected();
    if (isConnected) {
      return res.json({
        status: 'ready',
        service: 'expose-browser-worker',
        version: '0.1.0',
        timestamp: new Date().toISOString(),
        dependencies: {
          chromium: {
            status: 'UP',
            connected: true,
          },
        },
      });
    }
    return res.status(503).json({
      status: 'not_ready',
      service: 'expose-browser-worker',
      version: '0.1.0',
      timestamp: new Date().toISOString(),
      dependencies: {
        chromium: {
          status: 'DOWN',
          connected: false,
        },
      },
    });
  } catch (err: any) {
    return res.status(503).json({
      status: 'not_ready',
      service: 'expose-browser-worker',
      version: '0.1.0',
      timestamp: new Date().toISOString(),
      dependencies: {
        chromium: {
          status: 'DOWN',
          error: err?.message || 'Failed to initialize browser instance',
        },
      },
    });
  }
});

// Client-Side Security Analysis Endpoint (POST /api/v1/analyze)
app.post('/api/v1/analyze', async (req: Request, res: Response) => {
  const { url, timeout_ms } = req.body || {};
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ status: 'error', error: 'Missing target url parameter' });
  }

  // Pre-flight protocol & SSRF protection
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return res.status(400).json({ status: 'error', error: 'Invalid protocol: only http and https are allowed' });
    }
    const host = parsed.hostname.toLowerCase();
    if (
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '169.254.169.254' ||
      host === '::1' ||
      host.startsWith('10.') ||
      host.startsWith('192.168.') ||
      host.startsWith('172.16.')
    ) {
      return res.status(403).json({ status: 'error', error: 'SSRF protection: internal and metadata IP targets are prohibited' });
    }
  } catch {
    return res.status(400).json({ status: 'error', error: 'Invalid URL format' });
  }

  try {
    const browser = await getBrowser();
    const result = await analyzeClientSide(browser, url, timeout_ms || 20000);
    return res.json({ status: 'success', data: result });
  } catch (err: any) {
    console.error('[browser-worker] Analysis error:', err?.message || err);
    return res.status(500).json({ status: 'error', error: err?.message || 'Client analysis execution failed' });
  }
});

const server = app.listen(PORT, HOST, () => {
  console.log(`[expose-browser-worker] Listening on http://${HOST}:${PORT}`);
});

process.on('SIGTERM', async () => {
  console.log('[expose-browser-worker] Received SIGTERM, closing server and browser...');
  server.close(async () => {
    if (browserInstance) {
      await browserInstance.close();
    }
    process.exit(0);
  });
});
