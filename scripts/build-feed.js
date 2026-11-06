// Turns a plain list of phishing URLs (one per line) into dist-feed/phishing.json:
// 64-bit SHA-256 fragments of "host/path" keys. Usage: node scripts/build-feed.js <urls.txt> <out.json> [sourceName]
const fs = require('fs');
const T = require('../extension/src/threatdb.js');
const D = require('../extension/src/domain.js');
const { BRANDS } = require('../extension/src/brands.js');

const LEGIT = BRANDS.flatMap((b) => b.domains);
// Never let a mistaken feed line blacklist a whole well-known site.
const NEVER_WHOLE_HOST = new Set(LEGIT.concat(['google.com', 'github.com', 'wikipedia.org', 'facebook.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com', 'cloudflare.com', 'github.io', 'dropbox.com', 'docs.google.com']));

async function build(lines, source) {
  const keys = new Set();
  let skipped = 0;
  for (const line of lines) {
    const raw = line.trim();
    if (!raw || raw.startsWith('#')) continue;
    const c = T.canonicalize(raw);
    if (!c) { skipped++; continue; }
    const wholeHost = c.path === '/';
    if (wholeHost && Array.from(NEVER_WHOLE_HOST).some((d) => D.isSameOrSubdomain(c.host, d))) { skipped++; continue; }
    keys.add((await T.sha256Hex(c.host + c.path)).slice(0, 16));
  }
  return { generated: new Date().toISOString(), source, count: keys.size, skipped, hashes: Array.from(keys).sort() };
}

module.exports = { build };

if (require.main === module) {
  const [input, output, source = 'OpenPhish community feed'] = process.argv.slice(2);
  if (!input || !output) { console.error('usage: build-feed.js <urls.txt> <out.json> [source]'); process.exit(2); }
  build(fs.readFileSync(input, 'utf8').split(/\r?\n/), source).then((feed) => {
    if (feed.count < 50) { console.error('Refusing to publish a feed with only ' + feed.count + ' entries'); process.exit(1); }
    fs.writeFileSync(output, JSON.stringify(feed));
    console.log(`Wrote ${output}: ${feed.count} entries (${feed.skipped} skipped)`);
  });
}
