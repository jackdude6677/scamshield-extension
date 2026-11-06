// Generates simple shield icons (PNG) with no dependencies.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = (buf) => { let c = 0xffffffff; for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size) {
  const SS = 4; // supersampling for smooth edges
  const raw = Buffer.alloc((size * 4 + 1) * size);
  const inShield = (x, y) => { // x,y in 0..1
    const cx = 0.5, top = 0.06, bottom = 0.96;
    if (y < top || y > bottom) return false;
    const t = (y - top) / (bottom - top);
    const half = y < 0.5 ? 0.42 : 0.42 * Math.pow(1 - (y - 0.5) / (bottom - 0.5), 0.75);
    return Math.abs(x - cx) <= half && (t > 0.02 || Math.abs(x - cx) <= 0.40);
  };
  const inCheck = (x, y) => {
    const d = (ax, ay, bx, by) => { const dx = bx - ax, dy = by - ay; const t = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy))); return Math.hypot(x - (ax + t * dx), y - (ay + t * dy)); };
    const w = 0.065;
    return d(0.30, 0.50, 0.45, 0.65) < w || d(0.45, 0.65, 0.72, 0.34) < w;
  };
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    for (let x = 0; x < size; x++) {
      let a = 0, chk = 0;
      for (let sy = 0; sy < SS; sy++) for (let sx = 0; sx < SS; sx++) {
        const fx = (x + (sx + 0.5) / SS) / size, fy = (y + (sy + 0.5) / SS) / size;
        if (inShield(fx, fy)) { a++; if (inCheck(fx, fy)) chk++; }
      }
      const total = SS * SS;
      const o = y * (size * 4 + 1) + 1 + x * 4;
      const cov = a / total, chkCov = a ? chk / a : 0;
      // shield cyan, check dark navy
      raw[o] = Math.round(79 + (4 - 79) * chkCov); raw[o + 1] = Math.round(227 + (16 - 227) * chkCov); raw[o + 2] = Math.round(255 + (28 - 255) * chkCov);
      raw[o + 3] = Math.round(255 * cov);
    }
  }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}
const out = path.join(__dirname, '..', 'extension', 'icons');
fs.mkdirSync(out, { recursive: true });
for (const s of [16, 32, 48, 128]) fs.writeFileSync(path.join(out, `icon${s}.png`), png(s));
console.log('icons written to', out);
