# TripWire frontend (optional Next.js build)

The four website pages (`/`, `/demo`, `/arena`, `/evidence`) as a Next.js App Router + TypeScript app.
It is a **static export**: `npm run build` writes plain HTML, JS and CSS to `frontend/out/`, and the
existing Python server serves those files on the same origin as the API. There is no Node process at
run time.

This build is optional. Without it, `python -m tripwire serve` serves the built-in pages in
`tripwire/web/`, which need no install at all. The legacy console at `/console` is never touched.

## Workflow

```powershell
cd frontend
npm install          # once; needs Node 20 or newer
npm run build        # type-checks and writes frontend/out/
cd ..
python -m tripwire serve --open
```

The server banner prints which pages it is serving (`frontend/out (Next.js export)` or
`tripwire/web (built in)`). The choice is made once at start-up: after a rebuild, restart the server.
To go back to the built-in pages, delete `frontend/out/`.

`npm run typecheck` runs `tsc --noEmit` on its own. `npm run build:webpack` builds with webpack
instead of Turbopack if you ever need to compare.

There is deliberately **no `next dev` script**. A dev server on another port would be a different
origin, and the backend refuses cross-origin POSTs. That check has no development switch, and
`tests/test_dashboard.py` proves a `localhost:3000` origin is refused whatever the environment says.
Edit, `npm run build`, restart the server, reload.

## Security contract with the backend

Nothing in `tripwire/server.py`'s guard was relaxed for this frontend:

- every POST sends `X-TripWire-Client: dashboard` (one place: `post()` in `lib/api.ts`);
- all requests are same-origin relative paths, so `Origin` matches `Host`;
- bodies stay well under the 4 KB limit and carry only the fields each endpoint accepts;
- the server still binds to 127.0.0.1 and sends the same `Content-Security-Policy`.

The server serves only the four page files and files under `out/_next/` with a known web extension.
Anything else in `out/` (including `/demo.html`) is a 404, as before.

## Offline

No CDN, no remote fonts (`next/font` is not used; the CSS names system fonts), no analytics, no
external API calls. Next.js telemetry only concerns the build tool on your machine; turn it off with
`npx next telemetry disable` if you like. Nothing in `out/` phones home.

## Dependencies

| Package | Why |
|---|---|
| `next` | App Router and the static export (`output: "export"`) |
| `react`, `react-dom` | Required by Next.js; the UI itself |
| `typescript` (dev) | Type-checking; the build fails on a type error |
| `@types/node`, `@types/react`, `@types/react-dom` (dev) | Type definitions for the above |

No UI kit, CSS framework, state library, data-fetching library, icon set or linter.

## Layout

```
app/            layout.tsx (nav, footer, toast), one folder per page, app.css (ported from tripwire/web/app.css)
                home.css, demo/demo.css, arena/arena.css, evidence/evidence.css: each page's own rules, scoped
components/     HomePage, DemoPage, ArenaPage, EvidencePage, Nav, Toaster, Icon
lib/api.ts      the one typed API client; mirrors the endpoint tables in README.md and ARCHITECTURE.md
lib/types.ts    response shapes
lib/ui.ts       firewall pill and toast state      lib/store.ts   tiny external store      lib/format.ts
```

Every page renders from what the backend returns. No page computes a verdict, a metric or a
"blocked" state of its own.
