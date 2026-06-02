# Security Audit — youtube-automation-agent

**Repository:** https://github.com/darkzOGx/youtube-automation-agent
**Commit audited:** `3ea1b52` (Initial commit: YouTube Automation Agent)
**Date:** 2026-06-02
**Platform tested:** Windows 11, Node.js v24.1.0, npm 11.3.0
**Scope:** Full source review + dependency audit + live runtime verification

---

## 1. Executive Summary

`youtube-automation-agent` is a Node.js/Express application that orchestrates seven
"AI agents" to research, script, thumbnail, SEO-optimize, produce, publish, and analyze
YouTube videos on a cron schedule. Much of the AI/upload functionality is **simulated**
(stub files written to `data/`), but the HTTP control plane, OAuth handling, database,
and the FFmpeg/Playwright video pipeline are real.

**Overall posture: Weak.** The application:
- **does not run out of the box** (a required native dependency, `sharp`, is missing from
  `package.json`), and
- exposes an **HTTP API with zero authentication on all routes**, bound to all network
  interfaces, that can trigger paid AI calls and YouTube publishing, and
- ships **33 known-vulnerable dependencies** (14 High), including a heavily-CVE'd `axios`.

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 5 |
| Medium | 6 |
| Low | 5 |
| Functional blockers (non-security) | 5 |

No Critical issues exist *in the default configuration only because* the upload path is
currently stubbed and the most dangerous sinks are not yet reachable from user input.
Several High issues become Critical the moment real credentials are configured and the
stubs are replaced with working code (which the README presents as the intended state).

**Verification performed:** Cloned, `npm install` (430 pkgs), ran `node test.js`,
reproduced the `sharp` startup crash, installed `sharp`, booted the server with
placeholder credentials, and confirmed every endpoint returns `200` with **no auth**.

---

## 2. What was done (clone / install / run)

| Step | Result |
|------|--------|
| `git clone` | OK |
| `npm install` | OK — 430 packages, **33 vulnerabilities (3 low, 16 moderate, 14 high)** |
| `node test.js` | 4/5 PASS — **Agent Loading FAILED: `Cannot find module 'sharp'`** |
| `npm start` (as shipped) | **CRASH at module load** — `Cannot find module 'sharp'` (DOA) |
| `npm install sharp` + placeholder creds | Server boots, all 7 agents init, listens on `:3456` |
| `curl /health`, `/schedule`, `/` (no auth) | All `200 OK` — **confirms no authentication** |
| `POST /generate` (no auth) | Reaches pipeline; returns `500` due to a double-insert bug |

---

## 3. High Severity

### H-1 — No authentication or authorization on any HTTP endpoint (network-exposed)
**Files:** `index.js:87-147`, `index.js:196-206`
**CWE-306 (Missing Authentication for Critical Function)**

Every route is public and the server is started with `this.app.listen(PORT, ...)` — host
omitted, so Node binds to **all interfaces** (`::`/`0.0.0.0`), not just localhost. There is
no API key, session, token, CORS policy, or origin check.

Exposed without credentials:
- `POST /generate` — runs the full content pipeline (paid OpenAI/DALL-E/TTS calls when keys
  are set) on **attacker-supplied `topic`/`style`/`length`**.
- `POST /publish/:contentId` — triggers a YouTube upload of queued content.
- `GET /analytics`, `GET /schedule`, `GET /` (dashboard).

**Verified live:**
```
$ curl -s http://localhost:3456/health        # 200, no auth
{"status":"healthy","initialized":true,"agents":[...]}
$ curl -s -o /dev/null -w "%{http_code}" http://localhost:3456/health
200
```
**Impact:** Anyone who can reach the port (LAN, or the Internet if port-forwarded / on a
VPS as the README's "Cloud VPS / Railway / Render" deployment suggests) can burn the
owner's OpenAI/YouTube API quota, enqueue/trigger publishing to their channel, and read
schedule/analytics. This is cost-abuse + integrity + a DoS amplifier.
**Fix:** Require an auth token/middleware on all mutating routes; bind to `127.0.0.1` by
default; add a configurable allowlist; add CORS deny-by-default. Treat `/generate` and
`/publish` as privileged.

### H-2 — 33 known-vulnerable dependencies (14 High)
**File:** `package.json`
**CWE-1395 / CWE-937 (Vulnerable & Outdated Components)**

`npm audit` reports 33 advisories. Notable High chains:
- **axios `^1.6.0`** — ~20 advisories: SSRF via NO_PROXY/IP-alias bypass, prototype-pollution
  gadgets enabling credential theft / request hijacking / MITM, DoS, CRLF/null-byte injection.
  Directly relevant because `ai-video-generator.js` uses axios to download remote media.
- **express `^4.18.2`** → `path-to-regexp` ReDoS.
- **lodash, jws, tar, tar-fs, minimatch, brace-expansion, follow-redirects, ip-address,
  playwright, sqlite3→node-gyp→make-fetch-happen→cacache** chains.

**Fix:** `npm audit fix` clears most non-breaking ones (axios, express, follow-redirects,
brace-expansion). `axios`/`express`/`jimp`(→drop)/`sqlite3` may need major bumps; re-test.
Pin and add CI dependency scanning.

### H-3 — Command-injection-prone FFmpeg execution (latent)
**File:** `utils/ai-video-generator.js:278-282, 510-514` (`execAsync` of template-string commands)
**CWE-78 (OS Command Injection)**

```js
const ffmpegCommand = `ffmpeg -framerate 30 -i "${framesDir}/frame_%06d.png" ... "${videoPath}"`;
await execAsync(ffmpegCommand);
...
const command = `ffmpeg -i "${videoPath}" -i "${audioPath}" -c:v copy -c:a aac -shortest "${outputPath}"`;
```
The shell command is built by string interpolation. Today the path components derive from
`Date.now()`/internal IDs, so they are **not currently attacker-controlled** — hence "latent."
But there is no escaping/quoting guarantee, and the surrounding code already takes a
user-supplied `topic` that flows into titles and filenames elsewhere. Any future change that
puts a title/topic/filename into these paths yields arbitrary command execution.
**Fix:** Replace `exec` with `execFile('ffmpeg', [..args..])` (argument array, no shell).
Never interpolate paths into a shell string.

### H-4 — Plaintext secret storage + misleading "encrypted" claim
**Files:** `utils/credential-manager.js:46-54`, `oauth-server.js:87`, `modern-auth.js:98`, `simple-auth.js:61`; README.md:306
**CWE-312 (Cleartext Storage of Sensitive Information) / CWE-522**

OAuth `client_secret`, OpenAI API key, and long-lived YouTube **refresh tokens** are written
to `config/credentials.json` / `config/tokens.json` as plaintext JSON. The README claims
*"All API keys are stored locally in encrypted configuration"* — this is false and may lull
users into a weaker operational posture.
**Mitigation present:** `.gitignore` correctly excludes `config/credentials.json`,
`config/tokens.json`, `.env` (verified — no secrets are committed).
**Fix:** Encrypt at rest (e.g., OS keychain / `KMS` / a passphrase-derived key), restrict
file perms (`0600`), and correct the README.

### H-5 — No rate limiting, request-size limit, or security headers
**Files:** `index.js:88` (`express.json()` with no `limit`), whole server
**CWE-770 (Allocation of Resources Without Limits) / CWE-693**

`express.json()` is registered with default (no body-size cap → large-payload DoS), there is
no rate limiter, and no `helmet`/CSP/security headers. Combined with H-1, an unauthenticated
client can hammer `/generate` to exhaust CPU, disk, and paid API budget.
**Fix:** `express.json({ limit: '100kb' })`, add `express-rate-limit`, add `helmet` with a CSP.

---

## 4. Medium Severity

### M-1 — Stored XSS in the dashboard
**File:** `dashboard/index.html:285-297, 304-309, 339-366`
Dashboard renders server data via `innerHTML` (`item.title`, `data.agents`, metrics).
`title` originates from the SEO/strategy data, which traces back to the **unauthenticated
`/generate` `topic`**. An attacker can store HTML/JS that later executes in the operator's
browser when they view the dashboard (self-/stored-XSS via H-1).
**Fix:** Use `textContent` or escape all interpolated values; add a CSP.

### M-2 — XML/SVG injection into thumbnail rasterizer
**File:** `agents/thumbnail-designer-agent.js:257-288` (title → raw `<text>` in SVG → `sharp`)
`script.title` (topic-derived) is interpolated unescaped into SVG markup passed to `sharp`.
Malformed/`</text>`-breaking input corrupts the document and can abuse SVG features depending
on the renderer.
**Fix:** XML-escape (`& < > " '`) before embedding, or use a text API that escapes.

### M-3 — Fabricated analytics persisted and used for decisions
**File:** `agents/analytics-optimization-agent.js:619-625`
On any Analytics API error, `getSimulatedAnalytics()` returns `Math.random()` metrics that
are saved to the DB and drive optimization/priority decisions, with **no flag** marking them
as fake.
**Fix:** Mark simulated reports (`simulated: true`) or fail closed; never feed fabricated
metrics into automated decisions.

### M-4 — Unbounded paid AI generation with no spend cap or approval gate
**Files:** `agents/production-management-agent.js:284-316, 558-571`; reachable via `index.js:107`
The pipeline calls DALL-E/TTS/video generation with the only cost control being a
`slice(0, 5)`. No budget ceiling, dry-run, or human-approval gate. Via H-1 this is
remotely triggerable.
**Fix:** Enforce a per-run quantity/cost budget and an explicit enable/approval flag.

### M-5 — SSRF / unvalidated outbound media downloads
**File:** `utils/ai-video-generator.js:170-184, 516-530`
`downloadImage`/`downloadVideo` issue `axios` GETs to URLs from API responses with no
scheme/host validation, written to local disk. Currently the URLs come from trusted
providers, but combined with the axios SSRF CVEs (H-2) and any future user-influenced URL,
this is an SSRF + arbitrary-write risk.
**Fix:** Validate URL scheme/host allowlist; cap response size; sanitize output filenames.

### M-6 — Information disclosure via error messages & stack traces
**Files:** `index.js:113, 122, 133, 144`; `utils/logger.js:70-72`
Endpoints return raw `error.message` to clients (the live `POST /generate` test leaked the
SQLite schema: `SQLITE_CONSTRAINT: UNIQUE constraint failed: productions.id`). Stack traces
print to console when `NODE_ENV !== 'production'`.
**Fix:** Return generic errors to clients; log details server-side only.

---

## 5. Low Severity

- **L-1 — Insecure randomness for IDs.** `database/db.js:540-542` and
  `production-management-agent.js:117` use `Date.now()+Math.random()` for IDs (predictable;
  also collision-prone — see B-2). Use `crypto.randomUUID()`.
- **L-2 — No input validation on `/generate` body.** `index.js:109` accepts arbitrary
  types/sizes for `topic`/`style`/`length`. Validate type, length, and allowed `style` values.
- **L-3 — Reflected, unescaped `error` in OAuth callback HTML.** `oauth-server.js:19`,
  `modern-auth.js:84-88` echo the OAuth `error` query param into the HTML response.
  Low impact (localhost, attacker-influenced OAuth error), but escape it.
- **L-4 — Committed generated artifacts.** `data/scripts/*.json`, `data/captions/*.srt`,
  `data/audio/*.info`, `data/videos/*` were committed (the `.gitignore` `data/` rules only
  cover `*.db`/media, not `.info/.json/.srt`). No secrets found, but it's dev-machine leftover
  clutter and a minor info-leak surface. Tighten `.gitignore` and remove them.
- **L-5 — No security headers / `helmet` on the static dashboard** (overlaps M-1/H-5).

---

## 6. Functional defects found while running (not security, but block "run")

- **B-1 (blocker) — Missing `sharp` dependency.** `agents/thumbnail-designer-agent.js:1`
  `require('sharp')`, but `package.json` lists `jimp` (never imported). A clean
  `npm install && npm start` **crashes immediately** at module load. Fix: add `sharp` to
  `dependencies` (or migrate the agent to `jimp`).
- **B-2 — `POST /generate` always 500 (double insert).** `production-management-agent.js:89`
  saves the production, then `index.js:178` saves the *same* object again → `UNIQUE constraint
  failed: productions.id`. Remove one of the two inserts. (Reproduced live.)
- **B-3 — Missing `automation_events` table.** `schedules/daily-automation.js:462` inserts
  into `automation_events`, which `database/db.js:createTables()` never creates → scheduled
  tasks throw. Add the table.
- **B-4 — Broken `likeRatio`.** `analytics-optimization-agent.js:270` uses
  `stats.dislikeCount`, never populated → constant 100%.
- **B-5 — Upload is stubbed.** `publishing-scheduling-agent.js:154-162` `getVideoStream()`
  returns a JSON *string*, not a file stream, so real uploads cannot work as written.

---

## 7. Positive observations

- **Parameterized SQL everywhere** (`database/db.js`) — no SQL injection found.
- **No hardcoded secrets** in source or committed data (scanned; none found).
- **`.gitignore` correctly excludes** `credentials.json`, `tokens.json`, `.env`, DBs, media.
- **Graceful credential validation** — `index.js` exits cleanly when creds are missing
  (rather than crashing) — *once the `sharp` blocker is fixed*.
- **Reasonable error handling / fallbacks** in the agent layer.
- **No `eval`/`Function`/dynamic `require`** of user input; no prototype-pollution sinks on
  external JSON.

---

## 8. Prioritized remediation

1. **Add `sharp` to `package.json`** (unblocks running) — B-1.
2. **Put auth in front of the API + bind to localhost + add CORS/rate-limit/body-limit** — H-1, H-5.
3. **`npm audit fix` and bump axios/express/sqlite3; drop unused `jimp`** — H-2.
4. **Replace `exec` FFmpeg calls with `execFile` arg arrays** — H-3.
5. **Encrypt credential/token files at rest; fix the README "encrypted" claim** — H-4.
6. **Escape all dashboard `innerHTML` and SVG text; add CSP** — M-1, M-2.
7. **Add spend caps/approval to AI generation; flag simulated analytics; generic API errors** — M-4, M-3, M-6.
8. **Fix the double-insert and missing `automation_events` table** — B-2, B-3.

---

## 9. Remediation Applied (2026-06-02)

All findings below were fixed in-tree and the result was re-run and verified. New shared
modules: `utils/security.js` (escaping, SSRF URL guard, token + same-origin middleware) and
`utils/secure-store.js` (AES-256-GCM encryption-at-rest with `0600` fallback).

| ID | Fix | Status / Evidence |
|----|-----|-------------------|
| B-1 | Added `sharp` to dependencies | `npm start` boots; `node test.js` 5/5 pass |
| H-1 | Token auth (`Authorization: Bearer`/`x-api-token`) + same-origin check on `/generate` & `/publish`; server now binds `127.0.0.1` by default (`HOST` to override) | No-token → **401**, wrong token → **401**, foreign Origin → **403**, banner shows `127.0.0.1` (all verified live) |
| H-2 | `npm audit fix` + `sharp` (replaces unused `jimp`) + `sqlite3@^6` + `node-cron@^4` | **33 vulns (14 high) → 5 moderate, 0 high/critical** (`npm audit`) |
| H-3 | FFmpeg calls converted from `exec` (shell) to `execFile` (arg arrays) | `utils/ai-video-generator.js` — no shell interpolation |
| H-4 | Credentials/tokens encrypted at rest (AES-256-GCM via `CREDENTIAL_KEY`), else `0600`; README claim corrected | Round-trip test: on-disk has **no plaintext**, `alg=aes-256-gcm`, decrypts back |
| H-5 | `helmet` (CSP + headers), `express-rate-limit` (global 120/min, `/generate` 5/min), `express.json({limit:'64kb'})` | CSP/X-Frame/X-Content-Type headers present; 6th `/generate` → **429** (verified) |
| M-1 | Dashboard `innerHTML` values escaped (`esc()`); token sent on generate | `dashboard/index.html` |
| M-2 | Title/topic XML-escaped before SVG rasterization | `escapeXml()` in thumbnail agent; XSS-topic generate → **200**, no crash |
| M-3 | Simulated analytics flagged (`simulated:true`, `dataQuality`, warning insight) | `analytics-optimization-agent.js` |
| M-4 | Paid AI generation off by default (`AI_GENERATION_ENABLED`), per-run cap (`AI_MAX_VISUAL_ASSETS`) | `production-management-agent.js` |
| M-5 | SSRF guard (`isSafePublicUrl`: https/public only) + 100 MB cap on downloads | `utils/ai-video-generator.js` |
| M-6 | Generic client error messages; details logged server-side only | `index.js` |
| L-1 | IDs use `crypto.randomBytes` instead of `Math.random` | `db.js`, production agent |
| L-2 | `/generate` input validated (type, ≤200-char topic, allowed style/length) | Oversized topic → **400**, bad style → **400** (verified) |
| L-3 | Reflected OAuth `error` HTML-escaped | oauth-server.js, modern-auth.js |
| L-4 | `data/` artifacts untracked + git-ignored; `.api-token` ignored | 52 files removed from git index |
| L-5 | Security headers via helmet (overlaps H-5) | verified |
| B-2 | Removed duplicate `saveProductionData` (was guaranteed 500) | authenticated `/generate` → **200** (verified) |
| B-3 | Added `automation_events` table; scheduler insert uses column default | `db.js` |
| B-4 | Fixed divide-by-zero + removed undefined `dislikeCount` (now `likeRate`) | `analytics-optimization-agent.js` |
| B-5 | `getVideoStream` returns a real validated `.mp4` stream; refuses placeholders | `publishing-scheduling-agent.js` |

**Residual:** 5 *moderate* advisories remain — the transitive `uuid` v3/v5/v6 buffer
bounds-check pulled in by `googleapis-common` and `microsoft-cognitiveservices-speech-sdk`.
Not exploitable here (the app never passes a `buf` to `uuid`). `node-cron` was bumped to v4
(its nested `uuid` is now patched; the scheduler was adapted with a v3/v4-compatible
`isTaskActive` helper and re-verified). Clearing the last 5 would require destructive bumps
— `googleapis` 128 → 173 (drags in `@angular/core` + polyfills) and a **downgrade** of the
speech SDK 1.45 → 1.13 — which is a worse trade than the non-exploitable advisory, so they
are intentionally left. New config knobs are documented in `.env.example` (`HOST`,
`API_TOKEN`, `CREDENTIAL_KEY`, `AI_GENERATION_ENABLED`, `AI_MAX_VISUAL_ASSETS`, `ALLOWED_HOSTS`).

---

*Audit method: manual source review of all application files (no `node_modules`), `npm audit`,
and live runtime verification with placeholder credentials on Node v24.1.0. Dynamic testing was
limited to the local instance; no external systems were touched. Section 9 fixes were applied
and re-verified on the same instance.*
