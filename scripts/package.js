// Builds dist/scamshield-<version>.zip containing only the extension folder (no dev files, no secrets).
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const root = path.join(__dirname, '..');
const extDir = path.join(root, 'extension');
const manifest = JSON.parse(fs.readFileSync(path.join(extDir, 'manifest.json'), 'utf8'));
const outDir = path.join(root, 'dist');
fs.mkdirSync(outDir, { recursive: true });
const outFile = path.join(outDir, `scamshield-${manifest.version}.zip`);

const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = (buf) => { let c = 0xffffffff; for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };

function walk(dir, base = '') {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const rel = base ? base + '/' + e.name : e.name;
    return e.isDirectory() ? walk(path.join(dir, e.name), rel) : [rel];
  }).sort();
}

const files = walk(extDir);
// Refuse to ship anything that looks like a secret.
for (const f of files) {
  if (/\.(png|ico)$/.test(f)) continue;
  const text = fs.readFileSync(path.join(extDir, f), 'utf8');
  if (/AIza[0-9A-Za-z_-]{30,}|SAFE_BROWSING_API_KEY\s*[:=]\s*['"][^'"]+['"]/.test(text)) throw new Error('Possible API key found in ' + f);
}

const parts = [], central = [];
let offset = 0;
const dosTime = 0, dosDate = ((2024 - 1980) << 9) | (1 << 5) | 1; // fixed date → reproducible zip
for (const f of files) {
  const data = fs.readFileSync(path.join(extDir, f));
  const comp = zlib.deflateRawSync(data, { level: 9 });
  const name = Buffer.from(f);
  const crc = crc32(data);
  const lh = Buffer.alloc(30);
  lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0800, 6); lh.writeUInt16LE(8, 8);
  lh.writeUInt16LE(dosTime, 10); lh.writeUInt16LE(dosDate, 12); lh.writeUInt32LE(crc, 14);
  lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(name.length, 26);
  parts.push(lh, name, comp);
  const ch = Buffer.alloc(46);
  ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0800, 8); ch.writeUInt16LE(8, 10);
  ch.writeUInt16LE(dosTime, 12); ch.writeUInt16LE(dosDate, 14); ch.writeUInt32LE(crc, 16);
  ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(offset, 42);
  central.push(ch, name);
  offset += lh.length + name.length + comp.length;
}
const cd = Buffer.concat(central);
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
fs.writeFileSync(outFile, Buffer.concat([...parts, cd, end]));
console.log(`Wrote ${path.relative(root, outFile)} (${files.length} files)`);
