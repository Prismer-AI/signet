# Signet site

Landing page + live, in-browser demo for [Signet](https://github.com/Prismer-AI/signet).
The demo runs **real Ed25519 signing and verification in WebAssembly**, compiled
from the same `signet-core` Rust crate as the CLI — no server, no network call.

## Stack

- Vite + React + TypeScript (static output → `dist/`)
- `signet-core` → WASM via `wasm-pack --target web`, committed under `src/wasm/`

## Local development

```bash
cd site
npm install
npm run dev      # http://localhost:5173
npm run build    # type-check + static build into dist/
npm run preview  # serve the built dist/
```

## Rebuilding the WASM (only when signet-core changes)

The browser WASM is **prebuilt and committed** to `src/wasm/` so that Vercel can
deploy with a plain `vite build` — no Rust toolchain in the cloud. Rebuild it
locally only when the Rust core changes:

```bash
# from repo root — requires the pinned nightly toolchain + wasm-pack
cd site && npm run wasm
```

This runs `wasm-pack build ../bindings/signet-ts --target web` and writes
`signet_wasm.js` + `signet_wasm_bg.wasm` into `src/wasm/`. Commit the result.

## Deploy to Vercel

1. Import the repo at <https://vercel.com/new>.
2. Set **Root Directory** to `site` (the build is not at the repo root).
3. Framework auto-detects as **Vite** (`vercel.json` pins build command +
   `dist` output). No environment variables needed.
4. Deploy — you get a free `*.vercel.app` URL immediately. Add a custom domain
   later from the project's Domains tab; no DNS work needed if you buy it
   through Vercel.

Because the WASM is committed, Vercel's build is pure JS/TS and needs no Rust,
`wasm-pack`, or extra build image.
