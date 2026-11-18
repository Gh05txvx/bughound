# E2E (Playwright): BugHound

End-to-end testing of the user flow through the browser (persona **BH-P05-E2E**).

> **Security red line.** E2E **never** triggers a real scan or touches an
> external asset. It is guaranteed in layers:
> 1. The server runs with **mock engines** (`-engine mock`): no outbound connection.
> 2. The store is **ephemeral in-memory** (`-db ""`): no file/secret left behind.
> 3. It binds **localhost** only.
> 4. **Egress is blocked** in two places: a dead proxy env on the server process, and
>    a guard in the browser (`fixtures/test.ts`) that aborts non-local requests.
> The only targets used are dummy domains (`demo.test`, `acme.test`; the import spec
> uses `example.com` because the importer rejects an unknown TLD).

## Run

Needs Go on PATH + Node 18+.

```bash
cd e2e
npm install                 # once
npx playwright install chromium   # once (downloads the browser)
npm test                    # run every scenario
npm run test:headed         # with the browser visible
npm run report              # open the last HTML report
```

`webServer` in `playwright.config.ts` builds the `bughound-e2e` binary from
`./cmd/bughound` then runs it (port `8799`). No need to start the server by hand.

## Structure

```
tests/    one scenario per flow (the top 2 = critical, always run)
  scope-guard.spec.ts       CRITICAL: deny an out-of-scope target (preview)
  no-auto-submit.spec.ts    CRITICAL: draft report, no auto-submit
  scan-flow.spec.ts         scan happy-path (mock engines)
  triage.spec.ts            filter by severity + bulk confirm
  program-scope.spec.ts     create a program + scope, prefill the scan
  program-import.spec.ts    import platform scope: review first, hold an unrepresentable exclusion
pages/    one page object per screen (role/text-based selectors)
fixtures/ test fixture + browser egress guard
utils/    seed helpers (mock scan, confirm)
```

## Notes

- Selectors are **role/text**-based with stable form `name` attributes; no fragile XPath/indexes.
- Playwright **auto-wait**, no fixed `sleep`.
- Isolation: each test uses a **unique program name** so they do not depend on each other.
- Credentials are never written in a test; the happy path runs without auth (localhost).
