import { Browser, Page } from 'playwright';
import * as crypto from 'crypto';

export interface ScriptAnalysis {
  src: string;
  is_inline: boolean;
  integrity?: string;
  cross_origin?: string;
  is_third_party: boolean;
  has_sourcemap: boolean;
  sourcemap_url?: string;
}

export interface LinkAnalysis {
  href: string;
  text: string;
  is_external: boolean;
  protocol: string;
}

export interface FormAnalysis {
  action: string;
  method: string;
  input_types: string[];
  has_password: boolean;
  has_sensitive_data: boolean;
  is_insecure_submission: boolean;
}

export interface ResourceAnalysis {
  url: string;
  resource_type: string;
  status: number;
  domain: string;
  is_third_party: boolean;
}

export interface SourceMapAnalysis {
  script_url: string;
  sourcemap_url: string;
  is_publicly_accessible: boolean;
  status_code?: number;
}

export interface ClientSideConfigItem {
  key: string;
  value_preview: string;
  source: string;
}

export interface StandardFinding {
  id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'CONFIRMED' | 'LIKELY' | 'POTENTIAL' | 'INFORMATIONAL';
  status: 'CONFIRMED' | 'OBSERVED' | 'INFERRED' | 'NOT_ASSESSED';
  category: string;
  rule_id: string;
  owasp_mapping?: string;
  asvs_mapping?: string;
  cwe?: string;
  evidence: {
    type: string;
    summary: string;
    matched_data?: string;
    command?: string;
    timestamp: string;
  };
  impact: string;
  recommendation: {
    summary: string;
    remediation: string;
  };
  references: Array<{ name: string; url: string }>;
  verification: {
    command: string;
    tool: string;
    description: string;
  };
  created_at: string;
}

export interface ClientAnalysisResult {
  target_url: string;
  timestamp: string;
  duration_ms: number;
  scripts: ScriptAnalysis[];
  links: LinkAnalysis[];
  forms: FormAnalysis[];
  resources: ResourceAnalysis[];
  source_maps: SourceMapAnalysis[];
  client_side_configuration: ClientSideConfigItem[];
  public_api_references: string[];
  third_party_domains: string[];
  findings: StandardFinding[];
}

function generateFindingId(prefix: string, content: string): string {
  const hash = crypto.createHash('sha256').update(content).digest('hex').slice(0, 12);
  return `${prefix}_${hash}`;
}

export async function analyzeClientSide(
  browser: Browser,
  targetUrl: string,
  timeoutMs: number = 20000
): Promise<ClientAnalysisResult> {
  const startTime = Date.now();
  const parsedTarget = new URL(targetUrl);
  const targetHost = parsedTarget.hostname;

  const context = await browser.newContext({
    userAgent: 'Expose-Security-Scanner/1.0 (Headless Chromium Client-Side Analysis)',
    ignoreHTTPSErrors: true,
  });

  const page = await context.newPage();
  const resources: ResourceAnalysis[] = [];
  const findings: StandardFinding[] = [];
  const publicApiRefs = new Set<string>();
  const thirdPartyDomains = new Set<string>();

  // Intercept network requests to observe resources
  page.on('response', (response) => {
    try {
      const resUrl = response.url();
      if (!resUrl.startsWith('http')) return;
      const resHost = new URL(resUrl).hostname;
      const isThirdParty = resHost !== targetHost && !resHost.endsWith('.' + targetHost);

      if (isThirdParty) {
        thirdPartyDomains.add(resHost);
      }

      resources.push({
        url: resUrl,
        resource_type: response.request().resourceType(),
        status: response.status(),
        domain: resHost,
        is_third_party: isThirdParty,
      });
    } catch {
      // Ignore URL parsing errors
    }
  });

  // Navigate to target URL
  await page.goto(targetUrl, {
    waitUntil: 'domcontentloaded',
    timeout: timeoutMs,
  });

  // 1. Analyze Scripts in DOM
  const rawScripts = await page.$$eval('script', (elements) => {
    return elements.map((el) => {
      const src = el.getAttribute('src') || '';
      const integrity = el.getAttribute('integrity') || undefined;
      const crossOrigin = el.getAttribute('crossorigin') || undefined;
      const content = el.src ? '' : el.textContent || '';
      return { src, integrity, crossOrigin, content };
    });
  });

  const scripts: ScriptAnalysis[] = [];
  const sourceMaps: SourceMapAnalysis[] = [];

  for (const s of rawScripts) {
    const isInline = !s.src;
    let isThirdParty = false;
    let scriptHost = targetHost;

    if (s.src) {
      try {
        const scriptUrl = new URL(s.src, targetUrl);
        scriptHost = scriptUrl.hostname;
        isThirdParty = scriptHost !== targetHost && !scriptHost.endsWith('.' + targetHost);
      } catch {
        // relative or invalid URL
      }
    }

    // Check Subresource Integrity (SRI) on third-party scripts
    if (isThirdParty && s.src && !s.integrity) {
      findings.push({
        id: generateFindingId('fnd_sri', s.src),
        title: 'Missing Subresource Integrity (SRI) on External Script',
        description: `External script from third-party host '${scriptHost}' lacks an integrity attribute hash.`,
        severity: 'LOW',
        confidence: 'CONFIRMED',
        status: 'CONFIRMED',
        category: 'CLIENT_SIDE_SECURITY',
        rule_id: 'MISSING_SUBRESOURCE_INTEGRITY',
        owasp_mapping: 'A08:2021-Software and Data Integrity Failures',
        asvs_mapping: 'V14.2.3',
        cwe: 'CWE-353',
        evidence: {
          type: 'DOM_CONTENT',
          summary: `Observed <script src="${s.src}"> without integrity attribute.`,
          matched_data: s.src,
          timestamp: new Date().toISOString(),
        },
        impact: 'If the external CDN or hosting provider is compromised, malicious script payloads can execute in visitors\' browsers without detection.',
        recommendation: {
          summary: 'Add cryptographic SRI integrity hashes to all external script tags.',
          remediation: 'Use sha384 or sha512 integrity hashes (e.g. integrity="sha384-...") with crossorigin="anonymous".',
        },
        references: [
          { name: 'MDN Subresource Integrity', url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity' },
        ],
        verification: {
          command: `curl -sL "${targetUrl}" | grep -i "${s.src}"`,
          tool: 'curl',
          description: 'Inspect script tag attributes in HTML source',
        },
        created_at: new Date().toISOString(),
      });
    }

    // Check for inline source map comments or probe .map extension
    let hasSourceMap = false;
    let sourceMapUrl: string | undefined;

    if (s.src && s.src.endsWith('.js')) {
      const potentialMapUrl = s.src + '.map';
      try {
        const checkRes = await page.request.head(potentialMapUrl, { timeout: 3000 });
        if (checkRes.status() === 200) {
          hasSourceMap = true;
          sourceMapUrl = potentialMapUrl;
          sourceMaps.push({
            script_url: s.src,
            sourcemap_url: potentialMapUrl,
            is_publicly_accessible: true,
            status_code: 200,
          });

          findings.push({
            id: generateFindingId('fnd_sourcemap', potentialMapUrl),
            title: 'Public JavaScript Source Map File Disclosed',
            description: `Production JavaScript bundle exposes full source map file at '${potentialMapUrl}', disclosing unminified original source code.`,
            severity: 'LOW',
            confidence: 'CONFIRMED',
            status: 'CONFIRMED',
            category: 'INFORMATION_DISCLOSURE',
            rule_id: 'PUBLIC_SOURCEMAP_EXPOSURE',
            owasp_mapping: 'A05:2021-Security Misconfiguration',
            cwe: 'CWE-540',
            evidence: {
              type: 'SOURCE_MAP',
              summary: `HTTP 200 OK returned when requesting ${potentialMapUrl}.`,
              matched_data: potentialMapUrl,
              command: `curl -sIL "${potentialMapUrl}"`,
              timestamp: new Date().toISOString(),
            },
            impact: 'Source maps allow reverse-engineering of client application logic, internal API route definitions, comments, and proprietary algorithms.',
            recommendation: {
              summary: 'Restrict production access to source map (.map) files.',
              remediation: 'Configure bundler (Webpack, Vite, Next.js) with productionSourceMap: false, or restrict .map files at reverse proxy.',
            },
            references: [
              { name: 'CWE-540', url: 'https://cwe.mitre.org/data/definitions/540.html' },
            ],
            verification: {
              command: `curl -sI "${potentialMapUrl}" | grep -E "HTTP/[12] 200"`,
              tool: 'curl',
              description: 'Confirm source map file returns HTTP 200 OK',
            },
            created_at: new Date().toISOString(),
          });
        }
      } catch {
        // map probe error or timeout
      }
    }

    scripts.push({
      src: s.src || '[inline script]',
      is_inline: isInline,
      integrity: s.integrity,
      cross_origin: s.crossOrigin,
      is_third_party: isThirdParty,
      has_sourcemap: hasSourceMap,
      sourcemap_url: sourceMapUrl,
    });
  }

  // 2. Analyze Forms in DOM
  const forms = await page.$$eval('form', (elements) => {
    return elements.map((form) => {
      const action = form.getAttribute('action') || '';
      const method = (form.getAttribute('method') || 'GET').toUpperCase();
      const inputs = Array.from(form.querySelectorAll('input'));
      const inputTypes = inputs.map((i) => (i.getAttribute('type') || 'text').toLowerCase());
      const hasPassword = inputTypes.includes('password');

      return {
        action,
        method,
        input_types: inputTypes,
        has_password: hasPassword,
        has_sensitive_data: hasPassword || inputTypes.includes('email'),
      };
    });
  });

  const formAnalyses: FormAnalysis[] = [];
  for (const f of forms) {
    let actionUrl: URL | undefined;
    try {
      actionUrl = new URL(f.action, targetUrl);
    } catch {
      // relative action
    }

    const isInsecureAction = actionUrl ? actionUrl.protocol === 'http:' : parsedTarget.protocol === 'http:';
    const isPasswordOverGet = f.has_password && f.method === 'GET';

    if (f.has_password && isInsecureAction) {
      findings.push({
        id: generateFindingId('fnd_insecure_form', f.action),
        title: 'Insecure Password Form Submission Over Plain HTTP',
        description: `Form containing password credentials submits data to an unencrypted HTTP endpoint '${f.action}'.`,
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        status: 'CONFIRMED',
        category: 'TRANSPORT_SECURITY',
        rule_id: 'INSECURE_PASSWORD_FORM_SUBMISSION',
        owasp_mapping: 'A02:2021-Cryptographic Failures',
        asvs_mapping: 'V2.10.1',
        cwe: 'CWE-319',
        evidence: {
          type: 'DOM_CONTENT',
          summary: `Form action '${f.action}' uses unencrypted http scheme for password inputs.`,
          matched_data: f.action,
          timestamp: new Date().toISOString(),
        },
        impact: 'Passwords submitted over unencrypted HTTP can be intercepted in transit by attackers on the same network.',
        recommendation: {
          summary: 'Enforce HTTPS for all form actions.',
          remediation: 'Ensure all form action attributes explicitly specify https:// or use secure relative paths on an HTTPS-only host.',
        },
        references: [
          { name: 'OWASP Authentication Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html' },
        ],
        verification: {
          command: `curl -sL "${targetUrl}" | grep -i '<form' | grep -i 'action="http:'`,
          tool: 'curl',
          description: 'Search for unencrypted form actions in HTML source',
        },
        created_at: new Date().toISOString(),
      });
    }

    if (isPasswordOverGet) {
      findings.push({
        id: generateFindingId('fnd_password_get', f.action),
        title: 'Password Submitted via HTTP GET Method',
        description: 'Authentication form transmits password input parameters via the URL query string using HTTP GET.',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        status: 'CONFIRMED',
        category: 'CLIENT_SIDE_SECURITY',
        rule_id: 'PASSWORD_SUBMITTED_VIA_GET',
        owasp_mapping: 'A02:2021-Cryptographic Failures',
        cwe: 'CWE-598',
        evidence: {
          type: 'DOM_CONTENT',
          summary: 'Form has password input with method="GET".',
          timestamp: new Date().toISOString(),
        },
        impact: 'Passwords transmitted via query parameters leak into browser history, web server access logs, and HTTP Referer headers.',
        recommendation: {
          summary: 'Use HTTP POST for all credential forms.',
          remediation: 'Change form method attribute to method="POST".',
        },
        references: [
          { name: 'CWE-598', url: 'https://cwe.mitre.org/data/definitions/598.html' },
        ],
        verification: {
          command: `curl -sL "${targetUrl}" | grep -i '<form' | grep -i 'method="get"'`,
          tool: 'curl',
          description: 'Inspect form method attribute',
        },
        created_at: new Date().toISOString(),
      });
    }

    formAnalyses.push({
      action: f.action || targetUrl,
      method: f.method,
      input_types: f.input_types,
      has_password: f.has_password,
      has_sensitive_data: f.has_sensitive_data,
      is_insecure_submission: isInsecureAction || isPasswordOverGet,
    });
  }

  // 3. Analyze Links in DOM
  const links = await page.$$eval('a', (elements) => {
    return elements.slice(0, 100).map((a) => {
      const href = a.getAttribute('href') || '';
      const text = (a.textContent || '').trim().slice(0, 60);
      return { href, text };
    });
  });

  const linkAnalyses: LinkAnalysis[] = [];
  for (const l of links) {
    if (!l.href) continue;
    let isExternal = false;
    let protocol = 'relative';

    try {
      const u = new URL(l.href, targetUrl);
      protocol = u.protocol;
      isExternal = u.hostname !== targetHost && !u.hostname.endsWith('.' + targetHost);
    } catch {
      // relative
    }

    linkAnalyses.push({
      href: l.href,
      text: l.text,
      is_external: isExternal,
      protocol,
    });
  }

  // 4. Extract Client-Side Configuration (Window Environment Objects)
  const clientConfig = await page.evaluate(() => {
    const configItems: Array<{ key: string; value_preview: string; source: string }> = [];
    const windowObj = window as any;

    const candidateKeys = [
      '__NEXT_DATA__',
      'ENV',
      '__ENV',
      '_env_',
      'process',
      'firebaseConfig',
      '__INITIAL_STATE__',
    ];

    for (const key of candidateKeys) {
      if (windowObj[key]) {
        try {
          const str = JSON.stringify(windowObj[key]);
          configItems.push({
            key,
            value_preview: str.slice(0, 150) + (str.length > 150 ? '...' : ''),
            source: `window.${key}`,
          });
        } catch {
          configItems.push({
            key,
            value_preview: '[Complex Object]',
            source: `window.${key}`,
          });
        }
      }
    }
    return configItems;
  });

  // 5. Extract Public API References from Scripts
  const scriptContents = await page.$$eval('script:not([src])', (elements) => {
    return elements.map((e) => e.textContent || '').join('\n');
  });

  const apiRegex = /["'](\/api\/v[0-9]+[a-zA-Z0-9_\-\/]+)["']/g;
  let match: RegExpExecArray | null;
  while ((match = apiRegex.exec(scriptContents)) !== null) {
    if (match[1] && !match[1].includes('*')) {
      publicApiRefs.add(match[1]);
    }
  }

  // Record API endpoint references as INFORMATIONAL finding (adhering strictly to user principle:
  // "Do not claim that discovering a JavaScript reference proves that an API is vulnerable. Everything remains evidence-based.")
  if (publicApiRefs.size > 0) {
    const endpointsList = Array.from(publicApiRefs).slice(0, 10);
    findings.push({
      id: generateFindingId('fnd_api_refs', endpointsList.join('')),
      title: 'Public API Endpoints Referenced in Client-Side JavaScript',
      description: `Client-side JavaScript code contains explicit references to ${publicApiRefs.size} backend API endpoint paths.`,
      severity: 'INFO',
      confidence: 'INFORMATIONAL',
      status: 'OBSERVED',
      category: 'INFORMATION_DISCLOSURE',
      rule_id: 'PUBLIC_API_ENDPOINT_DISCLOSURE',
      evidence: {
        type: 'SCRIPT_REFERENCE',
        summary: `Discovered API paths in client bundle: ${endpointsList.join(', ')}`,
        matched_data: endpointsList.join(', '),
        timestamp: new Date().toISOString(),
      },
      impact: 'Public client applications legitimately reference their backend APIs. This observation maps the attack surface for operator awareness; it does not indicate a vulnerability on its own.',
      recommendation: {
        summary: 'Ensure all referenced endpoints enforce server-side authentication and authorization.',
        remediation: 'Validate that every endpoint discovered in client code strictly enforces JWT/session validation and does not rely on frontend security through obscurity.',
      },
      references: [
        { name: 'OWASP API Security Top 10', url: 'https://owasp.org/www-project-api-security/' },
      ],
      verification: {
        command: `curl -sL "${targetUrl}" | grep -Eo '["'"'](/api/v[0-9]+[^"' "'"']+)["'"']' | head -n 10`,
        tool: 'curl',
        description: 'Extract API routes from frontend page source',
      },
      created_at: new Date().toISOString(),
    });
  }

  await context.close();

  return {
    target_url: targetUrl,
    timestamp: new Date().toISOString(),
    duration_ms: Date.now() - startTime,
    scripts,
    links: linkAnalyses,
    forms: formAnalyses,
    resources,
    source_maps: sourceMaps,
    client_side_configuration: clientConfig,
    public_api_references: Array.from(publicApiRefs),
    third_party_domains: Array.from(thirdPartyDomains),
    findings,
  };
}
