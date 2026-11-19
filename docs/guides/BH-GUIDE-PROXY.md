# BH-GUIDE-PROXY: proxy chains, the IP echo endpoint & upstream proxy

> An operational guide to the **Proxy** menu (`/proxy`, under the *Testing* nav group): testing an upstream proxy chain before a scan, and verifying that the IP the target sees actually changed. Written to match the implementation (`internal/egress`, `internal/web`, `internal/geoip`). Last updated: 2026-11-19.

This menu is **diagnostic**, not a scan path. The chain you enter here is not used by a scan automatically: the scan takes its chain from the **Upstream proxy / chain** field in the **Scan** form. Use the Proxy menu to *prove the chain works & the IP changes*, then copy the proven chain into the Scan form.

> **The built-in egress is a safety boundary, not an anonymizer.** BugHound forces all scan traffic through one egress gateway that enforces the **scope guard + IP-pinning + rate limit** — it does **not** change or hide your IP. A target sees the BugHound **host's own public IP** unless *you* add an upstream proxy/VPN chain. To change the IP a target sees, configure a chain (below); to just read the public IP you currently scan from, use **My egress IP** (§1.1).

---

## 1. What the Proxy menu does

| Part | Always runs? | Touches the target? | Notes |
| --- | --- | --- | --- |
| Chain validation | yes | no | Checks the scheme & format of each hop. |
| Hop connectivity test | yes | **no** | Each hop is reached in order (`hop_i` through `hop_1..hop_{i-1}`); it only touches **your own proxy infrastructure**, not the scan target. Reports reachable + latency + the resolved IP. |
| Egress IP check | optional | yes (to the **echo**) | Two GETs to the echo endpoint, **direct** vs **through the chain**, then it compares the IP the echo server saw → the **"IP changed"** badge. |
| **My egress IP** (control-plane) | optional, **admin** | yes (to a fixed **echo**, e.g. ipify) | A quick *"what public IP do I scan from"*; no in-scope echo needed. See §1.1. |

**Security limits (cannot be turned off from this menu):**

- **The echo is subject to the program's scope guard** (default-deny, `BH-SPEC-SCOPE`). An echo host not proven in-scope is **rejected**, just like a real engine.
- **Proxy credentials** (`user:pass@`) are **redacted** from the UI, error messages, and the audit (`egress.check`). They never leak.
- **IP-pinning / anti-SSRF**: the target is resolved & *pinned* on the BugHound host before the chain; a private/internal IP is rejected unless it is explicitly in-scope.
- **Bounded**: this diagnostic runs once (an 8s timeout per hop, 10s per echo), it is not a flood. The mandatory rate limiter applies to the **scan**, set in the Scan form.

### 1.1 "My egress IP" — a quick check (admin, control-plane)

The **My egress IP** card at the top of the page (**admin only**) answers *"what public IP do my scans leave from?"* — the IP you give a program's team on request — **without** needing an in-scope echo:

- **Direct** call → your **Device IP**: the BugHound host's public IP, i.e. what a target sees with no proxy.
- With a **Proxy chain** filled in → also the **Exit IP** through that chain (and an **"IP changed"** badge).

It queries a **fixed echo host** (default `https://api.ipify.org`, editable inline). This is a **control-plane** call: the echo host becomes a throwaway **single-host scope guard**, so egress still passes the guard, but it runs **outside any program scope** (hence admin-only). It is an **explicit button**, never auto-called, and each run is audited as `egress.check` (host + ip-changed only, no credentials).

**When to use which:** use **My egress IP** for the general *"what is my IP"* (reporting it to a program). Use the **in-scope echo** check (§4) when you must prove the exit IP *against a specific in-scope target/echo* as part of a program's requirements.

---

## 2. The proxy chain (upstream chain)

**Format:** one hop per line, **in order** (the first hop at the top). The flow:

```
engine/bughound → hop1 → hop2 → … → hopN → target
```

**Supported schemes** (an invalid hop = *fail-closed*, the scan/diagnostic does not run):

| Scheme | Transport | Notes |
| --- | --- | --- |
| `http://` | HTTP `CONNECT` | a plain HTTP proxy (Burp, Squid, etc.). No CA cert needed. |
| `https://` | HTTP `CONNECT` over TLS | the connection to the proxy itself is encrypted. |
| `socks5://` | SOCKS5 | DNS is resolved on BugHound's side (see §6). |
| `socks5h://` | SOCKS5 | the same; the target resolution is still pinned upstream. |

**Credentials:** embed them in the URL → `scheme://user:pass@host:port`. Supported for HTTP (`Proxy-Authorization: Basic`) and SOCKS5 (user/pass auth). **Shown redacted** as `scheme://host:port`.

**Example chains:**

```text
# one hop (Burp)
http://127.0.0.1:8080

# one SOCKS5 hop with credentials (a commercial proxy)
socks5://user:pass@gw.provider.example:1080

# multi-hop: through Burp, then out via Tor
http://127.0.0.1:8080
socks5://127.0.0.1:9050
```

---

## 3. Upstream proxy: what you can use

| Category | Example URL | When to use it |
| --- | --- | --- |
| **Burp Suite** (Proxy) | `http://127.0.0.1:8080` | to watch/record & manipulate traffic in Burp. |
| **OWASP ZAP** | `http://127.0.0.1:8080` | the same, through ZAP. |
| **mitmproxy** | `http://127.0.0.1:8080` | traffic inspection/scripting. |
| **Tor** | `socks5://127.0.0.1:9050` | exit through the Tor network (anonymity; avoid it for programs that forbid Tor). |
| **SSH dynamic SOCKS** | `socks5://127.0.0.1:1080` (via `ssh -D 1080 user@jump`) | exit through a jump box / VPS IP. |
| **Corporate / Squid proxy** | `http://proxy.corp.local:3128` | required on an office network. |
| **Commercial proxy (residential/datacenter)** | `socks5://user:pass@host:port` or `http://...` | a **static exit IP** that a bug bounty program allowlists. |

> **Note:** BugHound only forwards HTTP/HTTPS egress through a proxy (CONNECT/SOCKS). Non-HTTP egress (e.g. an engine's raw DNS) does not go through here: that is the OS layer's job (defense in depth).

> **Running in Docker?** The chain is dialed from **inside the BugHound container**, so `127.0.0.1` means the *container*, not your PC. A proxy on your host is reached at `host.docker.internal:<port>` (Docker Desktop) or the host's LAN IP — **not** `127.0.0.1` — and it must be reachable from the container's network. A `connection refused` on a `127.0.0.1` hop usually means "nothing is listening inside the container", not that the feature is broken.

---

## 4. The IP echo endpoint

**Purpose:** a URL that returns **the client IP the server sees**. BugHound takes the first IP token from the body (plain text or JSON). By comparing the echo *direct* vs *through the chain*, you learn whether the exit IP really changed.

**A hard requirement:** the echo host **must be in-scope** in the program (default-deny). Otherwise the echo is **rejected by the scope guard**, which is deliberate (Principle #2: BugHound does not touch out-of-scope assets, not even for a diagnostic). So:

> The echo endpoint is **your diagnostic infrastructure**, not part of the target. To use it, **add the echo host to the program's in-scope list** on purpose.

**Echo endpoint options:**

| Option | Example | Notes |
| --- | --- | --- |
| **Your own echo** (recommended) | your VPS/lab: `http://echo.your.lab/ip` | the cleanest; you control it fully. nginx example: `location / { return 200 "$remote_addr"; }`. |
| **A public service** | `https://api.ipify.org`, `https://ifconfig.me/ip`, `https://icanhazip.com`, `https://checkip.amazonaws.com`, `https://ipinfo.io/ip` | only if **you add it to the program's in-scope list**. Pick one that returns the IP as plain text so parsing is clean. |

**Recognized body formats:** `203.0.113.9`, `{"ip":"203.0.113.9"}`, `your ip is 203.0.113.9`: the first IPv4/IPv6 token is taken. Empty if there is no IP.

### Exit IP country & ASN (offline GeoIP, optional)

BugHound can **label the source & exit IP with a country and ASN**, right below the IP (e.g. `185.220.101.4  🇳🇱 Netherlands (NL) · AS205100 — DigitalOcean, LLC`). Useful for a program that requires egress from a **specific country/ASN**.

**Offline, no egress compromise.** The lookup uses a **local MaxMind GeoLite2** database (`.mmdb`) and **never** calls a third-party geolocation service (ipinfo.io, ip-api.com, etc.). Calling one would mean egress to an out-of-scope asset (breaking Principle #2), so BugHound only reads a DB file you supply yourself. The feature is **optional** and **degrades cleanly**: without a DB, the Proxy menu still shows the IP, just without a country.

**To enable it:**

1. Download the free **GeoLite2** database from MaxMind (needs a free account): `GeoLite2-Country.mmdb` (for the country) and optionally `GeoLite2-ASN.mmdb` (for ASN/organization).
2. Put the files on the host or mount them into the container, then set the env before start:

   ```bash
   BUGHOUND_GEOIP_COUNTRY_DB=/data/geoip/GeoLite2-Country.mmdb
   BUGHOUND_GEOIP_ASN_DB=/data/geoip/GeoLite2-ASN.mmdb   # optional
   ```

3. Start BugHound; the log prints `geoip: on …`. If the env is unset or a file fails to open, the log prints why and the feature stays off cleanly (the Proxy menu shows a hint on how to enable it).

**Notes:**

- Purely a **display label**: it does not touch the scope guard, egress, rate limiter, or secrets.
- A private/unlisted IP → an empty country (marked "not found in the GeoIP DB").
- The GeoLite2 data belongs to MaxMind; follow its license terms (including periodic updates so it stays accurate).

---

## 5. Using it for an external bug bounty program (requirements)

Many programs demand that traffic come from a **registered static IP** (a program VPN, or an IP you declare in your profile). The Proxy menu is how you verify this **before** a real scan.

**Requirements & steps:**

1. **A static exit IP:** set up an upstream proxy whose exit IP = the IP the program allowlists (a VPS/jump box via `ssh -D`, or a static commercial proxy). A Tor/rotating-residential chain **does not fit** a program that requires a fixed IP.
2. **Precise scope:** fill the program's in-scope with the program's official targets (domain/wildcard/CIDR). To verify the IP, **add the echo host** (e.g. `api.ipify.org`) to in-scope too.
3. **Verify the IP (Proxy menu):** Program = that program, Chain = your proxy, Echo = the in-scope endpoint → **Test proxy**. Confirm the **exit IP** = the IP the program registered. If it says "same IP" / unchanged, the chain is not effective yet.
4. **Rate limit:** set it in the **Scan** form per the program's rules (BugHound clamps per engine, max 50/s).
5. **Proxy auth:** use `user:pass@` if a commercial proxy requires it (redacted automatically).
6. **Scan:** only then run the scan with the same chain in the Scan form. The report stays a **draft** (no auto-submit).

**A quick checklist before scanning an external program:**

- [ ] The proxy exit IP = the program's registered IP (proven via the Proxy menu).
- [ ] The program's targets are in-scope; out-of-scope is filled in if there are exclusions.
- [ ] The echo host (if used) is added to in-scope.
- [ ] The rate limit matches the program's rules.
- [ ] The proven chain is copied into the **Scan** form.

---

## 6. Technical notes & limits

- **Resolution & IP-pinning upstream.** The target is resolved to an IP on the BugHound host then *pinned* (anti DNS-rebinding), and only then is the connection to that IP forwarded through the chain. So `socks5` vs `socks5h` does not change the target resolution (already pinned); the target's DNS happens on BugHound's side, not at the exit node.
- **Paths on HTTPS.** A CONNECT tunnel only enforces host:port. A host:port that has a path-based exclusion is opened so each request is evaluated, and only HTTP/1 passes there; other hosts stay a blind tunnel. No CA cert needed: the certificate is one-time and the engine does not verify the target anyway.
- **A hop = infrastructure, not a target.** Hop connectivity is not scope-checked (a hop is your own proxy, often loopback like Burp/Tor). Only the **target & echo** pass through the scope guard.
- **Fail-closed.** An invalid hop/scheme, or an out-of-scope echo → rejected; no connection happens quietly.
- **Audit.** Each test is recorded as `egress.check` (a hop summary, echo?, ip-changed?); an echo rejection is recorded with its reason. No credentials.

---

## 7. A local trial recipe (your own lab)

Proving "IP changed" needs an echo + a proxy on **different IPs** in your own lab network (both in-scope). An example on `bughound-lab` (`172.30.0.0/24`):

```bash
# Echo: return the client IP as is
docker run -d --name lab-echo --network bughound-lab --ip 172.30.0.40 nginx:alpine
docker exec lab-echo sh -c 'printf "server { listen 80; location / { default_type text/plain; return 200 \"\$remote_addr\n\"; } }\n" > /etc/nginx/conf.d/default.conf && nginx -s reload'

# SOCKS5 proxy (needs credentials, or use -e REQUIRE_AUTH=false)
docker run -d --name lab-proxy --network bughound-lab --ip 172.30.0.50 \
  -e PROXY_USER=labuser -e PROXY_PASSWORD=labpass serjs/go-socks5-proxy
```

In the Proxy menu: Program with in-scope `172.30.0.0/24`, Chain `socks5://labuser:labpass@172.30.0.50:1080`, Echo `http://172.30.0.40/`.
Expected: the hop is **reachable** (credentials redacted), **source IP** (the BugHound lab IP) → **exit IP** `172.30.0.50`, **"IP changed ✓"**.

Cleanup: delete the program through the audited endpoint, then `docker rm -f lab-echo lab-proxy`.
