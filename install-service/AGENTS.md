# Repository Guidelines

## Project Structure & Module Organization
This Cloudflare Worker entry point is `src/index.js`, which wires routing, rate limiting, analytics, and scheduled jobs. Endpoint-specific logic lives in `src/handlers/`, while shared utilities are grouped under `src/utils/` (e.g., CORS, analytics, rate limiter helpers). Installation script templates reside in `templates/`; `templates/install.sh.js` generates platform-aware shell installers. Configuration for tooling and deployment is in the root: `wrangler.toml` for Cloudflare bindings, `tsconfig.json` for type checking, and `package.json` for scripts and dependencies.

## Build, Test, and Development Commands
- `npm run dev` launches `wrangler dev`, emulating the worker locally with live reload.
- `npm run deploy` deploys the worker using the active `wrangler` environment configuration.
- `npm run tail` streams production logs; use with caution on shared environments.
- `npm test` runs Vitest suites; pair with `npm run test:coverage` when validating broad changes.
- `npm run lint` (ESLint) and `npm run format` (Prettier) enforce style before submitting patches.
- `npm run typecheck` validates typings against the TypeScript declarations shipped with Wrangler.

## Coding Style & Naming Conventions
JavaScript code uses ES modules with 2-space indentation. Prefer descriptive camelCase for functions and variables, PascalCase for classes, and dashed naming for new worker routes (e.g., `/api/version/latest`). Keep handler exports default-free and named to mirror file names (`handlers/install.js` → `installHandler`). Run Prettier and ESLint before committing to align with the repository’s formatting rules. Configuration, secret names, and KV bindings should stay uppercase with underscores (e.g., `ANALYTICS_ENABLED`).

## Testing Guidelines
Vitest is the test runner; place tests beside implementations using `*.test.js` or under `src/__tests__/`. Mock Cloudflare bindings via Wrangler’s testing utilities or lightweight stubs to keep suites deterministic. Target key flows: rate limiting, installer generation, and version proxying. Maintain or improve coverage thresholds when adding features; use `npm run test:coverage` to spot regressions before review.

## Commit & Pull Request Guidelines
Recent history favors concise, imperative commit messages with optional Conventional Commit prefixes (`feat:`, `chore:`). Group related changes together and avoid blending refactors with feature work. Pull requests should summarize intent, list affected endpoints or templates, reference tracked issues, and include testing notes (commands run, environments touched). Capture screenshots or log excerpts when UX or observability changes are involved. Request review once lint, test, and typecheck commands pass locally.
