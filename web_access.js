/**
 * web_access.js - Secure Outbound Web Access & Search Engine for Antigravity AI
 * 
 * Provides:
 * 1. Robust SSRF protection (private IP blocking, IPv4/IPv6, cloud metadata, DNS pre-lookup)
 * 2. Safe outbound HTTP/HTTPS webpage retrieval with size & timeout limits
 * 3. Clean HTML text extraction (title extraction, tag stripping, formatting)
 * 4. Web search aggregation (Brave/Serper/Tavily if configured, zero-config DuckDuckGo fallback)
 * 5. AI Context Grounding with verifiable source citations
 */

const http = require('http');
const https = require('https');
const dns = require('dns');
const { URL } = require('url');

// ─── Configuration ───────────────────────────────────────────────────────────
const DEFAULT_TIMEOUT_MS = 8000;
const MAX_PAGE_BYTES = 2 * 1024 * 1024; // 2 MB maximum raw download
const MAX_EXTRACTED_CHARS = 12000;       // ~3,000 words max for LLM context
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36';

// ─── 1. SSRF Defense & IP Filtering ──────────────────────────────────────────

/**
 * Checks if an IP address falls within private, reserved, loopback, or link-local ranges
 */
function isPrivateIp(ip) {
  if (!ip || typeof ip !== 'string') return true;

  // IPv4 checks
  const v4Parts = ip.split('.').map(Number);
  if (v4Parts.length === 4 && v4Parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) {
    const [b0, b1] = v4Parts;
    // 127.0.0.0/8 (Loopback)
    if (b0 === 127) return true;
    // 10.0.0.0/8 (Private)
    if (b0 === 10) return true;
    // 172.16.0.0/12 (Private)
    if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
    // 192.168.0.0/16 (Private)
    if (b0 === 192 && b1 === 168) return true;
    // 169.254.0.0/16 (Link-local / Cloud Metadata: 169.254.169.254)
    if (b0 === 169 && b1 === 254) return true;
    // 0.0.0.0/8 (Current network)
    if (b0 === 0) return true;
    // 100.64.0.0/10 (Shared Carrier-Grade NAT)
    if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;
    // 198.18.0.0/15 (Benchmarking)
    if (b0 === 198 && (b1 === 18 || b1 === 19)) return true;
    // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
    if (b0 >= 224) return true;
    return false;
  }

  // IPv6 checks
  const lowerIp = ip.toLowerCase();
  if (
    lowerIp === '::1' ||                       // Loopback
    lowerIp === '::' ||                        // Unspecified
    lowerIp.startsWith('fc') ||                // Unique Local Address (fc00::/7)
    lowerIp.startsWith('fd') ||
    lowerIp.startsWith('fe80') ||              // Link-Local (fe80::/10)
    lowerIp.startsWith('ff') ||                // Multicast (ff00::/8)
    lowerIp.startsWith('::ffff:127.') ||       // IPv4-mapped loopback
    lowerIp.startsWith('::ffff:10.') ||        // IPv4-mapped private
    lowerIp.startsWith('::ffff:192.168.') ||
    lowerIp.startsWith('::ffff:172.') ||
    lowerIp.startsWith('::ffff:169.254.')
  ) {
    return true;
  }

  return false;
}

/**
 * Validates a URL and ensures its hostname and protocol are safe
 */
function validateSafeUrl(inputUrl) {
  try {
    const parsed = new URL(inputUrl);

    // Protocol check: only http and https
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { ok: false, error: `Disallowed protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted.` };
    }

    // Hostname check
    const hostname = parsed.hostname.toLowerCase();
    if (!hostname) {
      return { ok: false, error: 'Empty hostname in URL' };
    }

    // Blacklist dangerous hostnames
    const blockedHosts = [
      'localhost', '127.0.0.1', '::1', '0.0.0.0', 'metadata.google.internal',
      'instance-data', '169.254.169.254'
    ];
    if (blockedHosts.includes(hostname) || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
      return { ok: false, error: `Access to "${hostname}" is restricted by SSRF security policy.` };
    }

    return { ok: true, parsed };
  } catch (err) {
    return { ok: false, error: `Malformed URL: ${err.message}` };
  }
}

// ─── 2. Safe Webpage Retrieval ────────────────────────────────────────────────

/**
 * Fetches a webpage over HTTP/HTTPS with SSRF prevention, size caps, and timeout
 */
async function safeFetchUrl(inputUrl, maxBytes = MAX_PAGE_BYTES, timeoutMs = DEFAULT_TIMEOUT_MS, hopCount = 0) {
  if (hopCount > 3) {
    throw new Error('Too many redirects (max 3 hops exceeded)');
  }

  const validation = validateSafeUrl(inputUrl);
  if (!validation.ok) {
    throw new Error(validation.error);
  }
  const parsed = validation.parsed;

  // Resolve DNS to verify all resolved IP addresses are public (prevents DNS Rebinding SSRF)
  try {
    const addresses = await dns.promises.lookup(parsed.hostname, { all: true });
    if (!addresses || addresses.length === 0) {
      throw new Error(`Could not resolve hostname "${parsed.hostname}"`);
    }
    for (const addr of addresses) {
      if (isPrivateIp(addr.address)) {
        throw new Error(`Hostname "${parsed.hostname}" resolved to prohibited private IP (${addr.address})`);
      }
    }
  } catch (dnsErr) {
    if (dnsErr.message.includes('prohibited private IP')) throw dnsErr;
    throw new Error(`DNS resolution failed for "${parsed.hostname}": ${dnsErr.message}`);
  }

  return new Promise((resolve, reject) => {
    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.request(parsed, {
      method: 'GET',
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache'
      },
      timeout: timeoutMs
    }, res => {
      // Follow HTTP redirects safely
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        req.destroy();
        try {
          const nextUrl = new URL(res.headers.location, parsed).toString();
          return resolve(safeFetchUrl(nextUrl, maxBytes, timeoutMs, hopCount + 1));
        } catch (e) {
          return reject(new Error(`Invalid redirect location header: ${res.headers.location}`));
        }
      }

      if (res.statusCode < 200 || res.statusCode >= 400) {
        req.destroy();
        return reject(new Error(`HTTP ${res.statusCode} ${res.statusMessage || 'Request failed'}`));
      }

      let data = '';
      let bytes = 0;

      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > maxBytes) {
          req.destroy();
          return reject(new Error(`Response exceeded maximum size limit (${Math.round(maxBytes / 1024)} KB)`));
        }
        data += chunk;
      });

      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          contentType: res.headers['content-type'] || '',
          body: data,
          url: parsed.toString()
        });
      });
    });

    req.on('error', err => reject(new Error(`Network connection error: ${err.message}`)));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Web request timed out after ${timeoutMs}ms`));
    });
    req.end();
  });
}

// ─── 3. HTML Content Extractor ───────────────────────────────────────────────

/**
 * Extracts clean, readable plain text and title from HTML markup
 */
function extractCleanText(html) {
  if (!html || typeof html !== 'string') {
    return { title: 'No Content', text: '' };
  }

  // Extract page title
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  let title = titleMatch ? titleMatch[1].replace(/<[^>]+>/g, '').trim() : '';
  if (!title) {
    const h1Match = html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i);
    title = h1Match ? h1Match[1].replace(/<[^>]+>/g, '').trim() : 'Webpage';
  }

  // Strip non-content tags: scripts, styles, SVGs, iframes, comments, headers/footers
  let text = html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ' ')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, ' ')
    .replace(/<svg\b[^<]*(?:(?!<\/svg>)<[^<]*)*<\/svg>/gi, ' ')
    .replace(/<noscript\b[^<]*(?:(?!<\/noscript>)<[^<]*)*<\/noscript>/gi, ' ')
    .replace(/<nav\b[^<]*(?:(?!<\/nav>)<[^<]*)*<\/nav>/gi, ' ')
    .replace(/<footer\b[^<]*(?:(?!<\/footer>)<[^<]*)*<\/footer>/gi, ' ')
    .replace(/<header\b[^<]*(?:(?!<\/header>)<[^<]*)*<\/header>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ');

  // Format structural tags with newlines
  text = text
    .replace(/<\/(h[1-6]|p|div|section|article)>/gi, '\n\n')
    .replace(/<\/li>/gi, '\n')
    .replace(/<br\s*[\/]?>/gi, '\n')
    .replace(/<[^>]+>/g, ' ');

  // Decode common HTML entities
  text = text
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#x27;/g, "'")
    .replace(/&#x2F;/g, '/')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n\s*\n/g, '\n\n')
    .trim();

  // Truncate to token-efficient length
  if (text.length > MAX_EXTRACTED_CHARS) {
    text = text.slice(0, MAX_EXTRACTED_CHARS) + '\n\n... [Content truncated for length]';
  }

  return { title, text };
}

// ─── 4. Search Aggregator ─────────────────────────────────────────────────────

/**
 * Searches the web using configured API (Brave/Serper/Tavily) or fallback to DuckDuckGo
 */
async function searchWeb(query, maxResults = 5) {
  if (!query || !query.trim()) return [];

  const cleanQuery = query.trim();

  // 1. Check for Brave Search API Key (<SEARCH_API_KEY>)
  if (process.env.BRAVE_SEARCH_API_KEY) {
    try {
      const apiUrl = `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(cleanQuery)}&count=${maxResults}`;
      const res = await safeFetchUrl(apiUrl, 1024 * 512, 6000);
      const json = JSON.parse(res.body);
      if (json.web && json.web.results) {
        return json.web.results.slice(0, maxResults).map(r => ({
          title: r.title,
          url: r.url,
          snippet: r.description || ''
        }));
      }
    } catch (e) {
      console.warn('Brave Search API error, falling back to DuckDuckGo:', e.message);
    }
  }

  // 2. Check for Serper API Key
  if (process.env.SERPER_API_KEY) {
    try {
      const axios = require('axios');
      const r = await axios.post('https://google.serper.dev/search', { q: cleanQuery, num: maxResults }, {
        headers: { 'X-API-KEY': process.env.SERPER_API_KEY, 'Content-Type': 'application/json' },
        timeout: 6000
      });
      if (r.data.organic) {
        return r.data.organic.slice(0, maxResults).map(item => ({
          title: item.title,
          url: item.link,
          snippet: item.snippet || ''
        }));
      }
    } catch (e) {
      console.warn('Serper API error, falling back to DuckDuckGo:', e.message);
    }
  }

  // 3. Fallback: DuckDuckGo HTML Search (Zero-config, tested & verified)
  return new Promise((resolve) => {
    const postData = 'q=' + encodeURIComponent(cleanQuery);
    const req = https.request({
      hostname: 'html.duckduckgo.com',
      path: '/html/',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData),
        'User-Agent': USER_AGENT
      },
      timeout: DEFAULT_TIMEOUT_MS
    }, res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const results = [];
          const headingMatches = [...body.matchAll(/<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g)];
          const snippetMatches = [...body.matchAll(/<a class="result__snippet[^>]*>([\s\S]*?)<\/a>/g)];

          function decodeEntities(str) {
            if (!str) return '';
            return str
              .replace(/&amp;/g, '&')
              .replace(/&quot;/g, '"')
              .replace(/&#39;/g, "'")
              .replace(/&#x27;/g, "'")
              .replace(/&apos;/g, "'")
              .replace(/&lt;/g, '<')
              .replace(/&gt;/g, '>')
              .replace(/&nbsp;/g, ' ');
          }

          headingMatches.slice(0, maxResults).forEach((m, idx) => {
            let rawUrl = m[1];
            if (rawUrl.includes('uddg=')) {
              const match = rawUrl.match(/uddg=([^&]+)/);
              if (match) rawUrl = decodeURIComponent(match[1]);
            } else if (rawUrl.includes('duckduckgo.com/y.js')) {
              try {
                const u = new URL(rawUrl);
                const adDomain = u.searchParams.get('ad_domain');
                if (adDomain) {
                  rawUrl = `https://${adDomain}/`;
                }
              } catch (e) {}
            }

            const title = decodeEntities(m[2].replace(/<[^>]+>/g, '').trim());
            const snippet = decodeEntities(snippetMatches[idx] ? snippetMatches[idx][1].replace(/<[^>]+>/g, '').trim() : '');

            if (title && rawUrl.startsWith('http')) {
              results.push({
                title,
                url: rawUrl,
                snippet
              });
            }
          });

          resolve(results);
        } catch (parseErr) {
          console.warn('DuckDuckGo parse error:', parseErr.message);
          resolve([]);
        }
      });
    });

    req.on('error', err => {
      console.warn('DuckDuckGo search error:', err.message);
      resolve([]);
    });

    req.on('timeout', () => {
      req.destroy();
      console.warn('DuckDuckGo search timed out');
      resolve([]);
    });

    req.write(postData);
    req.end();
  });
}

// ─── 5. AI Web Context Orchestrator ──────────────────────────────────────────

/**
 * Extracts HTTP/HTTPS URLs embedded in text
 */
function extractUrlsFromText(text) {
  if (!text || typeof text !== 'string') return [];
  const urlRegex = /(https?:\/\/[^\s<>"')]+)/gi;
  const matches = text.match(urlRegex) || [];
  // Deduplicate and filter
  const unique = [];
  matches.forEach(u => {
    // Strip trailing punctuation like . , ; ! ?
    const clean = u.replace(/[.,;:!?)]+$/, '');
    if (!unique.includes(clean)) unique.push(clean);
  });
  return unique.slice(0, 3); // Max 3 URLs per request to avoid context bloat
}

/**
 * Prepares web evidence and citations to inject into the LLM context
 */
async function prepareWebContextForPrompt({ message, webAccessEnabled = false }) {
  const urls = extractUrlsFromText(message);
  const sources = [];
  let contextSections = [];
  let usedWeb = false;
  let errorSummary = null;

  // 1. If explicit URLs are present in the user message, fetch them directly
  if (urls.length > 0) {
    usedWeb = true;
    for (const targetUrl of urls) {
      try {
        console.log(`🌐 [Web Access] Fetching specific URL: ${targetUrl}`);
        const page = await safeFetchUrl(targetUrl);
        const { title, text } = extractCleanText(page.body);
        sources.push({ title: title || targetUrl, url: targetUrl, snippet: text.slice(0, 200) });
        contextSections.push(`### [Webpage: ${title || targetUrl}](${targetUrl})\n${text}`);
      } catch (err) {
        console.warn(`🌐 [Web Access] Failed to fetch ${targetUrl}:`, err.message);
        errorSummary = `Could not access ${targetUrl} (${err.message})`;
        contextSections.push(`### [Webpage Access Failed: ${targetUrl}]\nError: ${err.message}. Do not guess or fabricate page content.`);
      }
    }
  }

  // 2. If web access toggle is explicitly enabled, or user asks to search
  const isSearchIntent = webAccessEnabled || /\b(search (the web|for|online)|latest (news|info|update)|who is currently|what happened in 202[4-6]|browse)\b/i.test(message);

  if (isSearchIntent && urls.length === 0) {
    usedWeb = true;
    try {
      // Derive clean query (remove trigger phrases if needed)
      const searchQuery = message
        .replace(/^(search (the web|online|for)|browse the web for|find online|look up)\s+/i, '')
        .trim()
        .slice(0, 100);

      console.log(`🌐 [Web Access] Searching web for: "${searchQuery}"`);
      const searchResults = await searchWeb(searchQuery, 5);

      if (searchResults && searchResults.length > 0) {
        let searchSummary = `### Live Web Search Results for: "${searchQuery}"\n`;
        searchResults.forEach((r, idx) => {
          sources.push(r);
          searchSummary += `${idx + 1}. **[${r.title}](${r.url})**\n   ${r.snippet}\n\n`;
        });
        contextSections.push(searchSummary);

        // Fetch the top result's webpage content for deeper grounding
        if (searchResults[0] && searchResults[0].url) {
          try {
            const topPage = await safeFetchUrl(searchResults[0].url, 1024 * 1024, 5000);
            const { title, text } = extractCleanText(topPage.body);
            if (text.length > 200) {
              contextSections.push(`### [Detailed Source Content: ${title}](${searchResults[0].url})\n${text.slice(0, 4000)}`);
            }
          } catch (topErr) {
            console.warn(`🌐 [Web Access] Could not fetch top search link:`, topErr.message);
          }
        }
      } else {
        contextSections.push(`Live web search was attempted for "${searchQuery}", but no results were returned. Inform the user gracefully.`);
      }
    } catch (searchErr) {
      console.warn('🌐 [Web Access] Search failure:', searchErr.message);
      errorSummary = searchErr.message;
      contextSections.push(`Live web search failed: ${searchErr.message}. Inform the user that live web access encountered a network issue.`);
    }
  }

  if (contextSections.length === 0) {
    return { webContextPrompt: '', sources: [], usedWeb: false, error: null };
  }

  const webContextPrompt = `
=== RETRIEVED LIVE INTERNET INFORMATION ===
Timestamp: ${new Date().toUTCString()}
${contextSections.join('\n\n')}
=== END RETRIEVED LIVE INTERNET INFORMATION ===

CRITICAL GROUNDING INSTRUCTIONS:
1. Synthesize the answer using the retrieved live internet content above.
2. Clearly cite sources using markdown links in format: [Source Title](URL).
3. Distinguish retrieved current internet data from your internal training knowledge.
4. If a webpage or search failed or was inaccessible, report this truthfully. Never hallucinate or pretend you accessed a site if the fetch failed.
`;

  return {
    webContextPrompt,
    sources,
    usedWeb,
    error: errorSummary
  };
}

module.exports = {
  isPrivateIp,
  validateSafeUrl,
  safeFetchUrl,
  extractCleanText,
  searchWeb,
  extractUrlsFromText,
  prepareWebContextForPrompt
};
