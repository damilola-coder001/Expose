import express, { Request, Response } from 'express';
import { chromium, Browser, ConsoleMessage, Request as PlaywrightRequest } from 'playwright';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8081;
let browserInstance: Browser | null = null;

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

interface BrowserFinding {
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  status: 'CONFIRMED' | 'OBSERVED';
  description: string;
  impact_explanation: string;
  remediation: string;
  evidence: {
    type: string;
    summary: string;
    raw_data: Record<string, any>;
  };
}

app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    service: 'expose-browser-analysis-worker',
    runtime: 'Playwright / Chromium (Headless)',
    version: '0.1.0',
  });
});

app.post('/analyze', async (req: Request, res: Response) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid "url" in request body' });
  }

  const findings: BrowserFinding[] = [];
  const consoleSecurityErrors: string[] = [];
  const mixedContentRequests: string[] = [];

  try {
    const browser = await getBrowser();
    const context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Expose-Security-Intelligence/0.1.0 BrowserWorker',
      viewport: { width: 1280, height: 720 },
      ignoreHTTPSErrors: true,
    });

    const page = await context.newPage();

    // 1. Capture console security events
    page.on('console', (msg: ConsoleMessage) => {
      const text = msg.text();
      if (
        text.includes('Content Security Policy') ||
        text.includes('mixed content') ||
        text.includes('CORS') ||
        text.includes('Refused to execute')
      ) {
        consoleSecurityErrors.push(text);
      }
    });

    // 2. Capture mixed-content or insecure network requests
    page.on('request', (request: PlaywrightRequest) => {
      const reqUrl = request.url();
      if (url.startsWith('https://') && reqUrl.startsWith('http://')) {
        mixedContentRequests.push(reqUrl);
      }
    });

    // Navigate safely with strict timeout
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });

    // 3. Inspect DOM for insecure form actions
    const insecureForms = await page.$$eval('form', (forms: HTMLFormElement[]) => {
      return forms
        .map((f: HTMLFormElement) => f.getAttribute('action') || '')
        .filter((act: string) => act.startsWith('http://'));
    });

    if (insecureForms.length > 0) {
      findings.push({
        title: 'Insecure Plaintext Form Action (Mixed Content)',
        severity: 'HIGH',
        status: 'CONFIRMED',
        description: `The page contains <form> elements with insecure HTTP action targets: ${insecureForms.join(', ')}`,
        impact_explanation: 'User-submitted form data (including passwords, tokens, or personal info) will be transmitted across the network in unencrypted plaintext.',
        remediation: 'Ensure all form action targets use encrypted HTTPS endpoints.',
        evidence: {
          type: 'HTTP_EXCHANGE',
          summary: `Discovered ${insecureForms.length} insecure form action(s).`,
          raw_data: { insecure_form_actions: insecureForms },
        },
      });
    }

    // 4. Inspect Mixed Content requests
    if (mixedContentRequests.length > 0) {
      findings.push({
        title: 'Mixed Content Detected on HTTPS Page',
        severity: 'MEDIUM',
        status: 'CONFIRMED',
        description: `Page loaded over HTTPS requests unencrypted subresources over HTTP: ${mixedContentRequests.slice(0, 5).join(', ')}`,
        impact_explanation: 'Active network attackers can alter insecurely requested scripts or stylesheets to execute arbitrary malicious code inside the secure origin.',
        remediation: 'Migrate all subresource URLs (images, scripts, styles) to HTTPS.',
        evidence: {
          type: 'HTTP_EXCHANGE',
          summary: `Encountered ${mixedContentRequests.length} unencrypted subresource request(s).`,
          raw_data: { requests: mixedContentRequests.slice(0, 10) },
        },
      });
    }

    // 5. Inspect console security errors
    if (consoleSecurityErrors.length > 0) {
      findings.push({
        title: 'Browser Console Security Policy Violations',
        severity: 'LOW',
        status: 'CONFIRMED',
        description: `Browser reported ${consoleSecurityErrors.length} security violation(s) while rendering page.`,
        impact_explanation: 'Indicates either active CSP directive blocks, broken resource integrations, or cross-origin restrictions.',
        remediation: 'Review and update Content Security Policy headers or fix restricted subresource URLs.',
        evidence: {
          type: 'HTTP_EXCHANGE',
          summary: `Browser console captured ${consoleSecurityErrors.length} security error(s).`,
          raw_data: { errors: consoleSecurityErrors.slice(0, 5) },
        },
      });
    }

    // 6. Capture clean DOM screenshot
    const screenshotBuffer = await page.screenshot({ type: 'jpeg', quality: 70 });
    const screenshotBase64 = screenshotBuffer.toString('base64');

    await context.close();

    res.json({
      target_url: url,
      findings_count: findings.length,
      findings,
      screenshot_base64: screenshotBase64,
    });
  } catch (err: any) {
    res.status(500).json({
      error: `Browser analysis failed: ${err.message}`,
    });
  }
});

app.listen(PORT, () => {
  console.log(`[EXPOSE] Browser Analysis Worker (Playwright) active on http://0.0.0.0:${PORT}`);
});
