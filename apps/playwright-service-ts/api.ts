import express, { Request, Response } from 'express';
import { chromium, Browser, BrowserContext, Route, Request as PlaywrightRequest, Page } from 'playwright';
import dotenv from 'dotenv';
import { getError } from './helpers/get_error';
import { lookup } from 'dns/promises';
import IPAddr from 'ipaddr.js';

dotenv.config();

const app = express();
const port = process.env.PORT || 3003;

app.use(express.json());

const BLOCK_MEDIA = (process.env.BLOCK_MEDIA || 'False').toUpperCase() === 'TRUE';
const MAX_CONCURRENT_PAGES = Math.max(1, Number.parseInt(process.env.MAX_CONCURRENT_PAGES ?? '10', 10) || 10);
const ALLOW_LOCAL_WEBHOOKS = (process.env.ALLOW_LOCAL_WEBHOOKS || 'False').toUpperCase() === 'TRUE';
const DNS_CACHE_TTL_MS = 30_000;

const PROXY_SERVER = process.env.PROXY_SERVER || null;
const PROXY_USERNAME = process.env.PROXY_USERNAME || null;
const PROXY_PASSWORD = process.env.PROXY_PASSWORD || null;
const dnsLookupCache = new Map<string, { addresses: string[]; expiresAt: number }>();

class InsecureConnectionError extends Error {
  constructor(public readonly blockedUrl: string, reason: string) {
    super(`Blocked insecure target URL "${blockedUrl}": ${reason}`);
    this.name = 'InsecureConnectionError';
  }
}

const normalizeHostname = (hostname: string): string => hostname.toLowerCase().replace(/\.$/, '');

const isHttpProtocol = (protocol: string): boolean => protocol === 'http:' || protocol === 'https:';

const isIPPrivate = (address: string): boolean => {
  if (!IPAddr.isValid(address)) return false;
  const parsedAddress = IPAddr.parse(address);
  return parsedAddress.range() !== 'unicast';
};

const isLocalHostname = (hostname: string): boolean =>
  hostname === 'localhost' || hostname.endsWith('.localhost');

const lookupWithCache = async (hostname: string): Promise<string[]> => {
  const cached = dnsLookupCache.get(hostname);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.addresses;
  }

  const resolvedAddresses = await lookup(hostname, { all: true, verbatim: true });
  const uniqueAddresses = [...new Set(resolvedAddresses.map(x => x.address))];
  dnsLookupCache.set(hostname, {
    addresses: uniqueAddresses,
    expiresAt: Date.now() + DNS_CACHE_TTL_MS,
  });
  return uniqueAddresses;
};

const assertSafeTargetUrl = async (urlString: string): Promise<void> => {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(urlString);
  } catch {
    throw new InsecureConnectionError(urlString, 'URL is invalid');
  }

  if (!isHttpProtocol(parsedUrl.protocol)) {
    throw new InsecureConnectionError(urlString, `unsupported protocol "${parsedUrl.protocol}"`);
  }

  if (ALLOW_LOCAL_WEBHOOKS) {
    return;
  }

  const hostname = normalizeHostname(parsedUrl.hostname);
  if (!hostname) {
    throw new InsecureConnectionError(urlString, 'hostname is missing');
  }

  if (isLocalHostname(hostname)) {
    throw new InsecureConnectionError(urlString, 'localhost targets are not allowed');
  }

  if (IPAddr.isValid(hostname)) {
    if (isIPPrivate(hostname)) {
      throw new InsecureConnectionError(urlString, `private IP "${hostname}" is not allowed`);
    }
    return;
  }

  let resolvedAddresses: string[];
  try {
    resolvedAddresses = await lookupWithCache(hostname);
  } catch {
    throw new InsecureConnectionError(
      urlString,
      `DNS lookup failed for "${hostname}", cannot verify target is safe`,
    );
  }

  if (resolvedAddresses.length === 0) {
    throw new InsecureConnectionError(
      urlString,
      `hostname "${hostname}" did not resolve to any IP address`,
    );
  }

  if (resolvedAddresses.some(address => isIPPrivate(address))) {
    throw new InsecureConnectionError(urlString, `hostname "${hostname}" resolves to a private IP`);
  }
};

type ContextSecurityState = {
  blockedNavigationRequestUrl: string | null;
};
class Semaphore {
  private permits: number;
  private queue: (() => void)[] = [];

  constructor(permits: number) {
    this.permits = permits;
  }

  async acquire(): Promise<void> {
    if (this.permits > 0) {
      this.permits--;
      return Promise.resolve();
    }

    return new Promise<void>((resolve) => {
      this.queue.push(resolve);
    });
  }

  release(): void {
    this.permits++;
    if (this.queue.length > 0) {
      const nextResolve = this.queue.shift();
      if (nextResolve) {
        this.permits--;
        nextResolve();
      }
    }
  }

  getAvailablePermits(): number {
    return this.permits;
  }

  getQueueLength(): number {
    return this.queue.length;
  }
}
const pageSemaphore = new Semaphore(MAX_CONCURRENT_PAGES);

const AD_SERVING_DOMAINS = [
  'doubleclick.net',
  'adservice.google.com',
  'googlesyndication.com',
  'googletagservices.com',
  'googletagmanager.com',
  'google-analytics.com',
  'adsystem.com',
  'adservice.com',
  'adnxs.com',
  'ads-twitter.com',
  'facebook.net',
  'fbcdn.net',
  'amazon-adsystem.com'
];

interface UrlModel {
  url: string;
  wait_after_load?: number;
  timeout?: number;
  headers?: { [key: string]: string };
  check_selector?: string;
  skip_tls_verification?: boolean;
}

let browser: Browser;

// Derived once at startup from the browser itself, then reused for every
// context. See the comment in initializeBrowser for why this is not random.
let defaultUserAgent: string | null = null;

const ACCEPT_LANGUAGE = 'nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7';

const initializeBrowser = async () => {
  browser = await chromium.launch({
    // channel:'chrome' runs *real Google Chrome*, not Playwright's bundled
    // chromium_headless_shell (which headless:true selects by default since
    // Playwright 1.49). The shell is not a cosmetic difference: it announces
    // itself in the Sec-CH-UA *request header* as
    //   "HeadlessChrome";v="149", "Chromium";v="149"
    // which reaches bot-management before a single line of JS runs, so no
    // amount of addInitScript patching can hide it. It also ships no
    // window.chrome and an empty navigator.plugins. Real Chrome sends
    //   "Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"
    // and has both natively.
    channel: 'chrome',
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-accelerated-2d-canvas',
      '--no-first-run',
      '--no-zygote',
      '--disable-gpu',
      '--disable-blink-features=AutomationControlled'
    ]
  });

  // Derive the Chrome major version from the browser itself, then present as
  // Windows -- see WINDOWS_UA_TEMPLATE for why not Linux.
  //
  // The previous implementation generated a *random* UA per context via the
  // `user-agents` package, which handed out things like
  //   "Macintosh; Intel Mac OS X 10_12_0 ... Chrome/58.0.2327.1421"
  // -- Chrome 58 (2017) claiming macOS, while the process is Chrome 151 with
  // Linux client hints, Linux WebGL strings and Linux fonts. That
  // self-contradiction is a stronger bot signal than no spoofing at all.
  const browserMajorVersion = (browser.version().match(/^(\d+)/) || [])[1] || '151';
  chromeMajorVersion = browserMajorVersion;
  defaultUserAgent = UA_TEMPLATE
    .replace('%PLATFORM%', resolveProfile(STEALTH_PLATFORM).uaPlatform)
    .replace('%VERSION%', `${browserMajorVersion}.0.0.0`);
  console.log(`Presenting as (STEALTH_PLATFORM=${STEALTH_PLATFORM}): ${defaultUserAgent}`);
};

// Which desktop platform to present as. Measured against live bot management
// on 2026-08-12, and the two major vendors want *opposite* things:
//
//   fragrantica.com (Cloudflare): Linux -> 403, Windows/macOS -> 200.
//     Linux desktop Chrome is a low-single-digit share of consumer traffic and
//     correlates with scrapers, so it is scored as bot-like on its own.
//   zalando.nl (Akamai):          Windows -> block page, Linux -> 200.
//     Akamai correlates the claimed platform against the TLS/JA3 and HTTP/2
//     fingerprint. This process genuinely *is* Linux Chrome, so claiming
//     Windows is a contradiction it can see at the transport layer -- and
//     nothing in JS or headers can forge a TLS fingerprint.
//
// There is therefore no single value that satisfies both, and anyone changing
// this should expect to trade one class of site for the other. Default is
// windows because Cloudflare is far more widespread than Akamai. Override per
// deployment with STEALTH_PLATFORM, or per request by passing a User-Agent
// header -- the client hints below follow whichever UA is in play, so the
// fingerprint stays self-consistent either way.
type PlatformProfile = {
  uaPlatform: string;
  navigatorPlatform: string;
  clientHintPlatform: string;
  clientHintPlatformVersion: string;
  webglVendor: string;
  webglRenderer: string;
};

const PLATFORM_PROFILES: Record<string, PlatformProfile> = {
  windows: {
    uaPlatform: 'Windows NT 10.0; Win64; x64',
    navigatorPlatform: 'Win32',
    clientHintPlatform: 'Windows',
    clientHintPlatformVersion: '15.0.0',
    webglVendor: 'Google Inc. (Intel)',
    webglRenderer: 'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)',
  },
  macos: {
    uaPlatform: 'Macintosh; Intel Mac OS X 10_15_7',
    navigatorPlatform: 'MacIntel',
    clientHintPlatform: 'macOS',
    clientHintPlatformVersion: '15.0.0',
    webglVendor: 'Google Inc. (Apple)',
    webglRenderer: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)',
  },
  linux: {
    uaPlatform: 'X11; Linux x86_64',
    navigatorPlatform: 'Linux x86_64',
    clientHintPlatform: 'Linux',
    clientHintPlatformVersion: '6.12.0',
    // Real Linux Chrome on this host has no GPU, so leave the SwiftShader
    // strings alone rather than claiming hardware that the rest of the
    // fingerprint contradicts.
    webglVendor: '',
    webglRenderer: '',
  },
};

const STEALTH_PLATFORM = (process.env.STEALTH_PLATFORM || 'windows').toLowerCase();

const resolveProfile = (name: string): PlatformProfile =>
  PLATFORM_PROFILES[name] || PLATFORM_PROFILES.windows;

// Keep the client hints honest about whatever UA string is actually being
// sent, including a caller-supplied one.
const profileForUserAgent = (userAgent: string): PlatformProfile => {
  if (/Windows NT/i.test(userAgent)) return PLATFORM_PROFILES.windows;
  if (/Macintosh|Mac OS X/i.test(userAgent)) return PLATFORM_PROFILES.macos;
  if (/X11|Linux/i.test(userAgent)) return PLATFORM_PROFILES.linux;
  return resolveProfile(STEALTH_PLATFORM);
};

const UA_TEMPLATE =
  'Mozilla/5.0 (%PLATFORM%) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%VERSION% Safari/537.36';

let chromeMajorVersion = '151';

// Claiming Windows in the UA string while the browser keeps sending
// `Sec-CH-UA-Platform: "Linux"` is itself a mismatch, and the UA-CH headers go
// out before any JS runs. Playwright has no API for the client-hint metadata,
// so drive it over CDP: Emulation.setUserAgentOverride takes a
// userAgentMetadata block that backs both the Sec-CH-UA-* headers and
// navigator.userAgentData.
const applyFingerprintOverride = async (page: Page, userAgent: string): Promise<void> => {
  const profile = profileForUserAgent(userAgent);
  try {
    const cdpSession = await page.context().newCDPSession(page);
    await cdpSession.send('Emulation.setUserAgentOverride', {
      userAgent,
      acceptLanguage: ACCEPT_LANGUAGE,
      platform: profile.navigatorPlatform,
      userAgentMetadata: {
        brands: [
          { brand: 'Not=A?Brand', version: '99' },
          { brand: 'Google Chrome', version: chromeMajorVersion },
          { brand: 'Chromium', version: chromeMajorVersion },
        ],
        fullVersion: `${chromeMajorVersion}.0.0.0`,
        platform: profile.clientHintPlatform,
        platformVersion: profile.clientHintPlatformVersion,
        architecture: 'x86',
        model: '',
        mobile: false,
        bitness: '64',
        wow64: false,
      },
    });
    await cdpSession.detach().catch(() => {});
  } catch (error) {
    // Non-fatal: the context-level userAgent still applies, we just lose
    // client-hint consistency. Better a slightly weaker fingerprint than a
    // failed scrape.
    console.warn('Could not apply client-hint override:', error);
  }
};

const createContext = async (skipTlsVerification: boolean = false, userAgentOverride?: string): Promise<{ context: BrowserContext; securityState: ContextSecurityState }> => {
  const userAgent = userAgentOverride || defaultUserAgent || undefined;
  const viewport = { width: 1280, height: 800 };
  const securityState: ContextSecurityState = {
    blockedNavigationRequestUrl: null,
  };

  const contextOptions: any = {
    viewport,
    ignoreHTTPSErrors: skipTlsVerification,
    serviceWorkers: 'block',
    locale: 'nl-NL',
    timezoneId: 'Europe/Amsterdam',
    // Playwright's `locale` alone sends a bare "nl-NL"; real Chrome sends a
    // weighted list. Keep this in sync with the navigator.languages patch
    // below -- a header that disagrees with navigator.languages is itself a
    // fingerprint mismatch.
    extraHTTPHeaders: { 'Accept-Language': ACCEPT_LANGUAGE },
  };

  // Leave userAgent unset when we have no override and could not derive one,
  // so the browser's own (consistent) UA is used rather than a fabricated one.
  if (userAgent) {
    contextOptions.userAgent = userAgent;
  }

  if (PROXY_SERVER && PROXY_USERNAME && PROXY_PASSWORD) {
    contextOptions.proxy = {
      server: PROXY_SERVER,
      username: PROXY_USERNAME,
      password: PROXY_PASSWORD,
    };
  } else if (PROXY_SERVER) {
    contextOptions.proxy = {
      server: PROXY_SERVER,
    };
  }

  const newContext = await browser.newContext(contextOptions);

  // Only patch what real Chrome actually gets wrong here. Running the real
  // Chrome binary (see initializeBrowser) already provides natively, and
  // therefore *consistently*, the things this file used to fake:
  //   - window.chrome                 -> present as a real object
  //   - navigator.plugins            -> 5 entries ("PDF Viewer", ...) and a
  //                                     genuine PluginArray. The old spoof
  //                                     returned a plain Array, which fails
  //                                     `Object.prototype.toString` checks --
  //                                     bot.sannysoft.com flagged exactly that
  //                                     ("Plugins is of type PluginArray:
  //                                     failed"), so the spoof was worse than
  //                                     leaving it alone.
  //   - navigator.webdriver          -> false, which is what real Chrome
  //                                     reports. Forcing `undefined` (as this
  //                                     file used to) is itself anomalous.
  // What remains genuinely wrong is the GPU: this VPS has none, so Chrome
  // falls back to SwiftShader and leaks that through WEBGL_debug_renderer_info.
  const initScriptProfile = profileForUserAgent(userAgent || '');
  await newContext.addInitScript(({ acceptLanguage, webglVendor, webglRenderer }: { acceptLanguage: string; webglVendor: string; webglRenderer: string }) => {
    // Mirror the Accept-Language header so the JS-visible list and the wire
    // header tell the same story.
    const languages = acceptLanguage.split(',').map(part => part.split(';')[0].trim());
    Object.defineProperty(navigator, 'languages', {
      get: () => languages,
    });

    // navigator.permissions.query('notifications') returns 'denied' under
    // headless automation even when Notification.permission is 'default'.
    const originalQuery = window.navigator.permissions.query.bind(window.navigator.permissions);
    // @ts-ignore
    window.navigator.permissions.query = (parameters: any) =>
      parameters?.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission } as PermissionStatus)
        : originalQuery(parameters);

    // SwiftShader's software-rendered WebGL vendor/renderer strings are a
    // well-known headless/datacenter tell; report a plausible GPU instead.
    const patchGetParameter = (proto: any) => {
      const originalGetParameter = proto.getParameter;
      proto.getParameter = function (parameter: number) {
        // Strings matching the presented platform, passed in below. Empty
        // means "do not spoof" (the linux profile), since on this GPU-less
        // host the real SwiftShader strings are already consistent with a
        // Linux claim.
        if (parameter === 37445 && webglVendor) return webglVendor; // UNMASKED_VENDOR_WEBGL
        if (parameter === 37446 && webglRenderer) return webglRenderer; // UNMASKED_RENDERER_WEBGL
        return originalGetParameter.call(this, parameter);
      };
    };
    if ((window as any).WebGLRenderingContext) {
      patchGetParameter((window as any).WebGLRenderingContext.prototype);
    }
    if ((window as any).WebGL2RenderingContext) {
      patchGetParameter((window as any).WebGL2RenderingContext.prototype);
    }
  }, {
    acceptLanguage: ACCEPT_LANGUAGE,
    webglVendor: initScriptProfile.webglVendor,
    webglRenderer: initScriptProfile.webglRenderer,
  });

  if (BLOCK_MEDIA) {
    await newContext.route('**/*.{png,jpg,jpeg,gif,svg,mp3,mp4,avi,flac,ogg,wav,webm}', async (route: Route, request: PlaywrightRequest) => {
      await route.abort();
    });
  }

  // Intercept all requests to avoid loading ads
  await newContext.route('**/*', async (route: Route, request: PlaywrightRequest) => {
    const requestUrlString = request.url();
    try {
      await assertSafeTargetUrl(requestUrlString);
    } catch (error) {
      if (error instanceof InsecureConnectionError) {
        if (request.isNavigationRequest()) {
          securityState.blockedNavigationRequestUrl = requestUrlString;
        }
        console.warn(`Blocked request: ${requestUrlString}`);
        return route.abort('blockedbyclient');
      }
      throw error;
    }

    const requestUrl = new URL(requestUrlString);
    const hostname = normalizeHostname(requestUrl.hostname);

    if (AD_SERVING_DOMAINS.some(domain => hostname.includes(domain))) {
      console.log(hostname);
      return route.abort();
    }
    return route.continue();
  });
  
  return { context: newContext, securityState };
};

const shutdownBrowser = async () => {
  if (browser) {
    await browser.close();
  }
};

const isValidUrl = (urlString: string): boolean => {
  try {
    new URL(urlString);
    return true;
  } catch (_) {
    return false;
  }
};

const scrapePage = async (
  page: Page,
  url: string,
  waitUntil: 'load' | 'networkidle',
  waitAfterLoad: number,
  timeout: number,
  checkSelector: string | undefined,
  securityState: ContextSecurityState,
) => {
  console.log(`Navigating to ${url} with waitUntil: ${waitUntil} and timeout: ${timeout}ms`);
  let response;
  try {
    response = await page.goto(url, { waitUntil, timeout });
  } catch (error) {
    if (securityState.blockedNavigationRequestUrl) {
      throw new InsecureConnectionError(
        securityState.blockedNavigationRequestUrl,
        'navigation to private/internal resource is not allowed',
      );
    }
    throw error;
  }

  if (waitAfterLoad > 0) {
    await page.waitForTimeout(waitAfterLoad);
  }

  if (checkSelector) {
    try {
      await page.waitForSelector(checkSelector, { timeout });
    } catch (error) {
      throw new Error('Required selector not found');
    }
  }

  let headers = null, content = await page.content();
  let ct: string | undefined = undefined;
  if (response) {
    headers = await response.allHeaders();
    ct = Object.entries(headers).find(([key]) => key.toLowerCase() === "content-type")?.[1];
    if (ct && (ct.toLowerCase().includes("application/json") || ct.toLowerCase().includes("text/plain"))) {
      content = (await response.body()).toString("utf8"); // TODO: determine real encoding
    }
  }

  return {
    content,
    status: response ? response.status() : null,
    headers,
    contentType: ct,
  };
};

app.get('/health', async (req: Request, res: Response) => {
  try {
    if (!browser) {
      await initializeBrowser();
    }
    
    const { context: testContext } = await createContext();
    const testPage = await testContext.newPage();
    await testPage.close();
    await testContext.close();
    
    res.status(200).json({ 
      status: 'healthy',
      maxConcurrentPages: MAX_CONCURRENT_PAGES,
      activePages: MAX_CONCURRENT_PAGES - pageSemaphore.getAvailablePermits()
    });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(503).json({ 
      status: 'unhealthy', 
      error: error instanceof Error ? error.message : 'Unknown error occurred'
    });
  }
});

app.post('/scrape', async (req: Request, res: Response) => {
  const { url, wait_after_load = 0, timeout = 15000, headers, check_selector, skip_tls_verification = false }: UrlModel = req.body;

  console.log(`================= Scrape Request =================`);
  console.log(`URL: ${url}`);
  console.log(`Wait After Load: ${wait_after_load}`);
  console.log(`Timeout: ${timeout}`);
  console.log(`Headers: ${headers ? JSON.stringify(headers) : 'None'}`);
  console.log(`Check Selector: ${check_selector ? check_selector : 'None'}`);
  console.log(`Skip TLS Verification: ${skip_tls_verification}`);
  console.log(`==================================================`);

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  if (!isValidUrl(url)) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  try {
    await assertSafeTargetUrl(url);
  } catch (error) {
    if (error instanceof InsecureConnectionError) {
      return res.json({
        content: '',
        pageStatusCode: 403,
        pageError: error.message,
      });
    }
    throw error;
  }

  if (!PROXY_SERVER) {
    console.warn('⚠️ WARNING: No proxy server provided. Your IP address may be blocked.');
  }

  if (!browser) {
    await initializeBrowser();
  }

  await pageSemaphore.acquire();
  
  let requestContext: BrowserContext | null = null;
  let securityState: ContextSecurityState | null = null;
  let page: Page | null = null;

  try {
    // Extract user-agent from request headers (case-insensitive) so it can
    // be applied at the context level.  Playwright ignores user-agent in
    // setExtraHTTPHeaders when the context already defines one (#2802).
    const userAgentOverride = headers
      ? Object.entries(headers).find(([k]) => k.toLowerCase() === 'user-agent')?.[1]
      : undefined;

    const contextBundle = await createContext(skip_tls_verification, userAgentOverride);
    requestContext = contextBundle.context;
    securityState = contextBundle.securityState;
    page = await requestContext.newPage();

    // Align the Sec-CH-UA-* headers and navigator.userAgentData with whatever
    // UA this context ended up using.
    const effectiveUserAgent = userAgentOverride || defaultUserAgent;
    if (effectiveUserAgent) {
      await applyFingerprintOverride(page, effectiveUserAgent);
    }

    if (headers) {
      // Remove the user-agent key before calling setExtraHTTPHeaders since
      // we already forwarded it to the context-level userAgent option.
      const filteredHeaders = Object.fromEntries(
        Object.entries(headers).filter(([k]) => k.toLowerCase() !== 'user-agent')
      );
      if (Object.keys(filteredHeaders).length > 0) {
        await page.setExtraHTTPHeaders(filteredHeaders);
      }
    }

    const result = await scrapePage(
      page,
      url,
      'load',
      wait_after_load,
      timeout,
      check_selector,
      securityState,
    );
    const pageError = result.status !== 200 ? getError(result.status) : undefined;

    if (!pageError) {
      console.log(`✅ Scrape successful!`);
    } else {
      console.log(`🚨 Scrape failed with status code: ${result.status} ${pageError}`);
    }

    res.json({
      content: result.content,
      pageStatusCode: result.status,
      contentType: result.contentType,
      ...(pageError && { pageError })
    });

  } catch (error) {
    if (error instanceof InsecureConnectionError) {
      return res.json({
        content: '',
        pageStatusCode: 403,
        pageError: error.message,
      });
    }
    console.error('Scrape error:', error);
    res.status(500).json({ error: 'An error occurred while fetching the page.' });
  } finally {
    if (page) await page.close();
    if (requestContext) await requestContext.close();
    pageSemaphore.release();
  }
});

app.listen(port, () => {
  initializeBrowser().then(() => {
    console.log(`Server is running on port ${port}`);
  });
});

if (require.main === module) {
  process.on('SIGINT', () => {
    shutdownBrowser().then(() => {
      console.log('Browser closed');
      process.exit(0);
    });
  });
}
