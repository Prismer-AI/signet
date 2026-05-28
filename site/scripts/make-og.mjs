// Generates the social share image (public/og.png, 1200x630) from an inline SVG.
// Run with: npm run og
import sharp from 'sharp';
import { mkdirSync } from 'node:fs';

const svg = `<svg width="1200" height="630" viewBox="0 0 1200 630" xmlns="http://www.w3.org/2000/svg">
  <rect width="1200" height="630" fill="#ffffff"/>
  <rect width="1200" height="8" fill="#3b4cca"/>

  <text x="80" y="104" font-family="'DejaVu Sans',sans-serif" font-size="32" font-weight="700" fill="#3b4cca">&#9670; Signet</text>

  <text x="80" y="248" font-family="'DejaVu Sans',sans-serif" font-size="60" font-weight="700" fill="#1a1a2e">Don&#8217;t just log</text>
  <text x="80" y="320" font-family="'DejaVu Sans',sans-serif" font-size="60" font-weight="700" fill="#1a1a2e">agent actions.</text>
  <text x="80" y="392" font-family="'DejaVu Sans',sans-serif" font-size="60" font-weight="700" fill="#3b4cca">Prove them.</text>

  <text x="82" y="456" font-family="'DejaVu Sans',sans-serif" font-size="25" fill="#5b6270">Ed25519-signed &#183; hash-chained &#183; offline-verifiable</text>
  <text x="82" y="491" font-family="'DejaVu Sans',sans-serif" font-size="25" fill="#5b6270">receipts for every AI agent tool call.</text>

  <text x="80" y="566" font-family="'DejaVu Sans Mono','DejaVu Sans',monospace" font-size="24" fill="#3b4cca">signet-auth.vercel.app</text>

  <circle cx="975" cy="300" r="132" fill="none" stroke="#3b4cca" stroke-width="3" opacity="0.22"/>
  <circle cx="975" cy="300" r="104" fill="#eef0fb" stroke="#dfe3f7" stroke-width="2"/>
  <path d="M 928 300 L 962 336 L 1024 268" fill="none" stroke="#157a3c" stroke-width="14" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

mkdirSync(new URL('../public/', import.meta.url), { recursive: true });
const out = new URL('../public/og.png', import.meta.url);
await sharp(Buffer.from(svg)).png().toFile(out.pathname);
console.log('Generated', out.pathname);
