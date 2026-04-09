#!/usr/bin/env node
/**
 * Capture Signet Dashboard screenshots using Puppeteer.
 * Takes screenshots of all 4 tabs + delegation chain detail expansion.
 * Then combines with CLI demo frames into a single MP4.
 */

import puppeteer from 'puppeteer-core';
import { execSync } from 'child_process';
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import path from 'path';

const BROWSER_PATH = '/home/willamhou/.cache/ms-playwright/chromium-1217/chrome-linux64/chrome';
const DASHBOARD_URL = 'http://127.0.0.1:9191';
const OUT_DIR = path.resolve('tmp/dashboard-frames');
const ROOT = path.resolve('..');

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function main() {
  mkdirSync(OUT_DIR, { recursive: true });

  console.log('Launching browser...');
  const browser = await puppeteer.launch({
    executablePath: BROWSER_PATH,
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu'],
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 800, deviceScaleFactor: 2 });

  let frameIndex = 0;

  async function capture(name) {
    const file = path.join(OUT_DIR, `dash-${String(frameIndex).padStart(3, '0')}-${name}.png`);
    await page.screenshot({ path: file, fullPage: false });
    console.log(`  [${frameIndex}] ${name} -> ${file}`);
    frameIndex++;
    return file;
  }

  // Navigate to dashboard
  console.log('Opening dashboard...');
  await page.goto(DASHBOARD_URL, { waitUntil: 'networkidle0', timeout: 10000 });
  await sleep(1500);

  // 1. Timeline view (default)
  console.log('Capturing Timeline...');
  await capture('timeline');

  // 2. Click first row to expand detail
  const firstRow = await page.$('tbody tr');
  if (firstRow) {
    await firstRow.click();
    await sleep(500);
    await capture('timeline-detail');
  }

  // 3. Chain Integrity
  console.log('Capturing Chain Integrity...');
  await page.click('#nav-chain');
  await sleep(2000); // chain verification takes time
  await capture('chain-integrity');

  // 4. Signatures
  console.log('Capturing Signatures...');
  await page.click('#nav-signatures');
  await sleep(2000);
  await capture('signatures');

  // 5. Stats
  console.log('Capturing Statistics...');
  await page.click('#nav-stats');
  await sleep(1500);
  await capture('stats');

  // Scroll down to see charts
  await page.evaluate(() => window.scrollTo(0, 400));
  await sleep(500);
  await capture('stats-charts');

  await browser.close();
  console.log(`\nCaptured ${frameIndex} dashboard screenshots in ${OUT_DIR}`);

  // Now build the combined video: CLI frames + dashboard frames
  console.log('\nBuilding combined MP4...');
  buildCombinedVideo(frameIndex);
}

function buildCombinedVideo(dashFrameCount) {
  const cliFramesDir = path.join(ROOT, 'tmp/delegation-frames');
  const concatFile = path.join(OUT_DIR, 'combined.txt');
  const outMp4 = path.join(ROOT, 'demo-delegation-full.mp4');

  let content = '';

  // CLI frames first (from existing render)
  if (existsSync(path.join(cliFramesDir, 'frames.txt'))) {
    const cliConcat = execSync(`cat ${cliFramesDir}/frames.txt`).toString();
    content += cliConcat;
  }

  // Add a "DASHBOARD" title frame - reuse last CLI frame with longer duration
  // Then add dashboard screenshots
  for (let i = 0; i < dashFrameCount; i++) {
    const files = execSync(`ls ${OUT_DIR}/dash-${String(i).padStart(3, '0')}-*.png`).toString().trim().split('\n');
    for (const f of files) {
      content += `file '${f}'\n`;
      content += `duration 3.0\n`;
    }
  }

  // Repeat last frame
  const lastDash = execSync(`ls ${OUT_DIR}/dash-*.png | tail -1`).toString().trim();
  content += `file '${lastDash}'\n`;

  writeFileSync(concatFile, content);

  // Render MP4
  execSync(`ffmpeg -y -loglevel error \
    -f concat -safe 0 -i "${concatFile}" \
    -vf "fps=20,scale=1200:-2:flags=lanczos,format=yuv420p" \
    -movflags +faststart \
    "${outMp4}"`);

  const size = execSync(`du -h "${outMp4}" | cut -f1`).toString().trim();
  console.log(`\nFull demo video: ${outMp4} (${size})`);
}

main().catch(e => {
  console.error('Error:', e.message);
  process.exit(1);
});
