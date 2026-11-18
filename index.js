#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const PUBLIC_KEY_B64 = 'MCowBQYDK2VwAyEA0000000000000000000000000000000000000000000=';
const LIC_FILE = path.join(process.cwd(), '.assetsanitizer.lic');

function verifyLicense(keyStr) {
  try {
    const [payloadB64, sigB64] = keyStr.trim().split('.');
    if (!payloadB64 || !sigB64) return false;
    const payload = Buffer.from(payloadB64, 'base64url').toString('utf8');
    if (!payload.includes('assetsanitizer')) return false;
    const pubKey = crypto.createPublicKey({ key: Buffer.from(PUBLIC_KEY_B64, 'base64'), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(payloadB64), pubKey, Buffer.from(sigB64, 'base64url'));
  } catch { return false; }
}

function scrubPng(buf) {
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (!buf.subarray(0, 8).equals(sig)) return { buf, hits: [] };
  const out = [sig], hits = [], strip = new Set(['tEXt', 'zTXt', 'iTXt', 'eXIf', 'caBX', 'tIME']);
  let pos = 8;
  while (pos + 12 <= buf.length) {
    const len = buf.readUInt32BE(pos), type = buf.subarray(pos + 4, pos + 8).toString('ascii'), end = pos + 12 + len;
    if (end > buf.length) break;
    if (strip.has(type)) hits.push(type); else out.push(buf.subarray(pos, end));
    pos = end;
  }
  return { buf: Buffer.concat(out), hits };
}

function scrubJpeg(buf) {
  if (buf[0] !== 0xFF || buf[1] !== 0xD8) return { buf, hits: [] };
  const out = [buf.subarray(0, 2)], hits = [];
  let pos = 2;
  while (pos + 4 <= buf.length) {
    if (buf[pos] !== 0xFF) { out.push(buf.subarray(pos)); break; }
    const m = buf[pos + 1];
    if (m === 0xDA || m === 0xD9) { out.push(buf.subarray(pos)); break; }
    const end = pos + 2 + buf.readUInt16BE(pos + 2);
    if (end > buf.length) { out.push(buf.subarray(pos)); break; }
    if (m === 0xE1 || m === 0xEB || m === 0xED || m === 0xFE) hits.push(m === 0xEB ? 'C2PA' : m === 0xE1 ? 'EXIF/XMP' : 'IPTC/COM');
    else out.push(buf.subarray(pos, end));
    pos = end;
  }
  return { buf: Buffer.concat(out), hits };
}

function scrubWebp(buf) {
  if (buf.subarray(0, 4).toString('ascii') !== 'RIFF' || buf.subarray(8, 12).toString('ascii') !== 'WEBP') return { buf, hits: [] };
  const chunks = [], hits = [], strip = new Set(['EXIF', 'XMP ', 'C2PA', 'JUMB']);
  let pos = 12;
  while (pos + 8 <= buf.length) {
    const fourCC = buf.subarray(pos, pos + 4).toString('ascii'), sz = buf.readUInt32LE(pos + 4), end = pos + 8 + sz + (sz % 2);
    if (end > buf.length) break;
    if (strip.has(fourCC)) hits.push(fourCC.trim()); else chunks.push(buf.subarray(pos, end));
    pos = end;
  }
  const body = Buffer.concat(chunks), hdr = Buffer.alloc(12);
  hdr.write('RIFF', 0); hdr.writeUInt32LE(body.length + 4, 4); hdr.write('WEBP', 8);
  return { buf: Buffer.concat([hdr, body]), hits };
}

async function main() {
  console.log('\n======================================================');
  console.log('  🧹 AssetSanitizer Desktop v1.0.0 (100% Air-Gapped)');
  console.log('  C2PA, AI Prompt & Metadata Binary Scrubber');
  console.log('  Store & Lifetime License: https://t.me/Userstudiobot/Store');
  console.log('======================================================\n');

  let licensed = fs.existsSync(LIC_FILE) && verifyLicense(fs.readFileSync(LIC_FILE, 'utf8'));
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = q => new Promise(res => rl.question(q, res));

  if (!licensed) {
    console.log('🔒 Mode: FREE PREVIEW (Sanitizes up to 3 files per batch)');
    const k = await ask('🔑 Enter Lifetime License Key (or Enter for Free Preview): ');
    if (k.trim() && verifyLicense(k.trim())) {
      fs.writeFileSync(LIC_FILE, k.trim());
      licensed = true;
      console.log('✅ Lifetime License Activated!\n');
    } else if (k.trim()) {
      console.log('⚠️ Invalid key. Running in Free Preview mode.\n');
    }
  } else {
    console.log('✅ Status: LIFETIME LICENSE ACTIVE (Unlimited Batch Scrubbing)\n');
  }

  let target = process.argv[2] || (await ask('📂 Drag & drop image/folder path (or Enter for built-in demo): ')).trim().replace(/^['"]|['"]$/g, '');
  if (!target || !fs.existsSync(target)) {
    const demoDir = path.join(process.cwd(), 'demo_ai_assets');
    fs.mkdirSync(demoDir, { recursive: true });
    const pngSig = Buffer.from([137,80,78,71,13,10,26,10]);
    const txtData = Buffer.from('parameters\0masterpiece, 4k cyberpunk UI, seed:994812, Model: Flux.1-dev');
    const txtHdr = Buffer.alloc(8); txtHdr.writeUInt32BE(txtData.length, 0); txtHdr.write('tEXt', 4);
    const iend = Buffer.from([0,0,0,0,73,69,78,68,174,66,96,130]);
    fs.writeFileSync(path.join(demoDir, 'sample_flux_render.png'), Buffer.concat([pngSig, txtHdr, txtData, Buffer.alloc(4), iend]));
    target = demoDir;
  }

  const stat = fs.statSync(target);
  const files = stat.isDirectory() ? fs.readdirSync(target).filter(f => /\.(png|jpe?g|webp)$/i.test(f)).map(f => path.join(target, f)) : [target];
  const outDir = path.join(stat.isDirectory() ? target : path.dirname(target), 'sanitized_clean');
  fs.mkdirSync(outDir, { recursive: true });

  const batch = licensed ? files : files.slice(0, 3);
  let total = 0;
  for (const fp of batch) {
    const raw = fs.readFileSync(fp), ext = path.extname(fp).toLowerCase();
    const res = ext === '.png' ? scrubPng(raw) : ext === '.webp' ? scrubWebp(raw) : scrubJpeg(raw);
    fs.writeFileSync(path.join(outDir, path.basename(fp)), res.buf);
    total += res.hits.length;
    console.log(`  ✔ ${path.basename(fp)} -> Stripped [${res.hits.length ? res.hits.join(', ') : 'Clean'}]`);
  }
  console.log(`\n✨ Done! Processed ${batch.length}/${files.length} files (${total} AI/metadata blocks removed).\n📁 Clean files: ${outDir}\n`);
  rl.close();
}
main();
