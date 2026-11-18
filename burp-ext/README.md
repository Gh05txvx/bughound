# BugHound: Burp Suite extension (Montoya)

A small extension that pulls **findings** from BugHound straight into Burp
Suite, then **sends their request to Repeater** for you to validate by hand,
without switching tools.

The flow is one-way and deliberately limited:

```
BugHound  ──(GET /api/v1/findings, HTTP Basic)──▶  Burp extension  ──▶  Repeater (you press Send)
```

- The extension **only reads** from BugHound (it never writes/changes).
- **No auto-submit / auto-scan.** Sending a request to a target stays your manual
  action via the **Send** button in Repeater.
- The password is not stored to disk; re-enter it each Burp session.

---

## 1. Prerequisites

- **JDK 17+** (modern Burp runs on Java 17+).
- **Gradle 8+** installed, _or_ create a wrapper with `gradle wrapper` then use
  `./gradlew`.
- **Burp Suite** (Community or Professional) with Montoya API support.
- BugHound running with the API active (see the **API** section below).

## 2. Build

From the `burp-ext/` folder:

```bash
gradle shadowJar        # or: ./gradlew shadowJar
```

Result: **`build/libs/bughound-burp.jar`** (Gson is bundled inside it; the
Montoya API is not, Burp provides it at runtime).

> If dependency resolution fails, open `build.gradle` and set the `montoya-api`
> version to the latest release on Maven Central. The core API this extension
> uses (`registerSuiteTab`, `HttpService`, `HttpRequest`,
> `repeater().sendToRepeater`) is stable across versions.

## 3. Load into Burp

`Extensions` → `Installed` → `Add` → Extension type: **Java** → pick
`build/libs/bughound-burp.jar` → `Next`.

The **Output** tab shows: `bughound: extension loaded, open the 'BugHound' tab.`
and a new tab named **BugHound** appears.

## 4. Use

In the **BugHound** tab:

1. Fill in **BugHound URL** (default `http://127.0.0.1:8787`), **user**, **pass**
   (your BugHound account), and **program** (the exact program name as in BugHound,
   e.g. `juice-lab-v4`).
2. Click **Load findings** → the table fills (Severity, Type, Title, Method, URL).
3. Pick a row → **Send to Repeater**. Its request (from `evidence.request` when
   present; otherwise a GET to the location URL) shows up as a new Repeater tab
   `bh:<short title>`.
4. In Repeater, press **Send** yourself to validate. From here you work as usual
   in Burp.

## 5. The BugHound API it consumes (read-only)

The extension uses BugHound's read-only JSON API (see `internal/web/api.go`). It is
useful for other scripts/automation too:

| Endpoint | Description |
| --- | --- |
| `GET /api/v1/findings?program=<name>` | One program's findings (JSON). Options: `run_id`, `status`, `severity` (comma-separated), `include_duplicates=1`. |
| `GET /api/v1/findings/{id}` | One full finding (the unified schema, including `evidence.request`). |

Auth: **HTTP Basic** with a BugHound account (the automation path that already
exists; GET needs no CSRF). Without credentials → `401`. Example:

```bash
curl -u admin:change-me-2026 \
  'http://127.0.0.1:8787/api/v1/findings?program=juice-lab-v4'
```

## 6. Security notes

- **Read-only & no auto-submit**: the BugHound API it uses is `GET` only; the
  extension does not change BugHound data and never sends a request to a target
  automatically. BugHound's egress/scope guard/rate limiter still govern BugHound's
  own scans; this extension sits outside that path (a read-only handoff to Repeater).
- **Scope**: Repeater sends to whichever host you press **Send** on. Make sure the
  target is in-scope for your bug bounty program, this is your responsibility in Burp,
  the same as plain Repeater.
- **Credentials**: the BugHound user/pass live only in the extension UI's memory; they
  are not persisted. Use a read-role account when that is enough.
- **Transport**: for a non-local BugHound, put it behind TLS (e.g. a reverse proxy)
  so Basic auth does not travel in the clear.

## 7. Structure

```
burp-ext/
  build.gradle, settings.gradle   # build (shadow jar, montoya compileOnly, gson)
  src/main/java/bughound/burp/
    BughoundExtension.java         # entry point (BurpExtension)
    BughoundPanel.java             # UI tab + send-to-Repeater action
    ApiClient.java                 # HTTP Basic client to the BugHound API (GET only)
    Models.java                    # JSON models (Finding/Location/Evidence)
```
