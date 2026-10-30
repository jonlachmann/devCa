# DevCA – Implementation Plan

Status: **implemented** (stages 1–7). Deviations from this plan are noted inline as *Impl:*. Decisions locked 2026-10-30: default suffix `.localhost` (`.local` also allowed), JSON state file, name-constrained root, Go via Homebrew, module `github.com/jonlachmann/devca`.

## 0. Guiding constraints (from spec + your notes)

- One static Go binary per platform, `CGO_ENABLED=0`, frontend embedded.
- Dependencies only where they replace real protocol risk. Target Go dependency list:
  - `golang.org/x/crypto/acme`: an *independent* ACME client, used by `devca test acme` and the integration tests. It also checks our server against a real client.
  - Nothing else (no cobra, no yaml, no logging lib, no router). Possibly `golang.org/x/net/dns/dnsmessage` if mDNS is ever added.
- Frontend dependencies: `svelte`, `vite`, `@sveltejs/vite-plugin-svelte`, `typescript`, `svelte-check`. No component lib, no router lib, no CSS framework.
  Icons: a few heroicons (MIT) SVG paths inlined in one `Icon.svelte`, used only where they help (nav, copy, status). This replaces Lucide.
- YAML config from the spec example is dropped: `gopkg.in/yaml.v3` is archived/unmaintained, which is the "breaks over time" risk you want to avoid. Services live in the state store and are managed via the CLI/UI. Bootstrap settings use flags/env (`--data`, `DEVCA_HOME`).

## 1. Name resolution and mDNS (your question)

`.local` is reserved for mDNS (RFC 6762). What actually happens per OS:

| OS | `.local` lookup | hosts-file entry wins? | Gotcha |
|---|---|---|---|
| macOS | mDNSResponder multicasts `.local` | Yes | Add **both** `127.0.0.1` and `::1`, or there's a ~5 s stall while it waits on the IPv6 mDNS query |
| Linux | `nss-mdns` (`mdns4_minimal [NOTFOUND=return]`) if installed | Yes, `files` comes before `mdns` in nsswitch | none in practice |
| Windows | Windows 10+ also does mDNS | Yes | none in practice |

**Making DevCA an mDNS responder that answers `api.local → 127.0.0.1` is the wrong tool**:
- mDNS is a LAN-wide broadcast. Every machine on the Wi-Fi gets told `api.local` is `127.0.0.1` (meaning *their own* machine), and RFC 6762 says not to announce loopback addresses.
- Two devs on the same network both claiming `api.local` triggers mDNS conflict resolution, which renames one of them to `api-2.local`.
- It has to share UDP 5353 with mDNSResponder/avahi/Windows DNS Client (SO_REUSEPORT quirks per OS), or shell out to `dns-sd` / `avahi-publish` / `DnsServiceRegister`. That's three fragile integrations.

**Plan:**
1. A **hosts-file block** managed by DevCA. It works for `.local` on all three OSes (we write both v4 and v6).
2. Offer **`.localhost`** (RFC 6761) as a zero-config suffix. Chrome, Firefox and Edge resolve `*.localhost` to loopback with no hosts entry on every OS, and so do curl and systemd-resolved. Safari and some CLI tools on macOS still need the hosts entry. Bonus: Vite's default `allowedHosts` accepts `*.localhost` but rejects `*.local`.
3. mDNS is useful for one thing only: publishing `api.local → <LAN IP>` so a phone can reach your dev box. That needs the gateway bound to the LAN and the CA installed on the phone, so it's **deferred** out of v1.

**Decided:** allowed suffixes `localhost` + `local`; new services default to `.localhost`.

## 2. Architecture

One process. `devca serve` runs four things:

```
                ┌──────────── devca serve ─────────────┐
 browser ──────▶│ gateway  127.0.0.1+::1 :80 / :443     │──▶ localhost:5000 …
                │   :80  /.well-known/acme-challenge/*  │
                │        else → 308 https               │
                │   :443 SNI → in-memory cert map       │
 browser/CLI ──▶│ mgmt     http://127.0.0.1:7171  UI+API│
 ACME client ──▶│ acme     https://localhost:7443/acme/ │
                │ renewer  hourly loop                  │
                └──────────────── state store ──────────┘
```

- **The mgmt listener is plain HTTP on loopback.** The UI has to work *before* the CA is trusted, otherwise the first-run screen would be a browser warning.
- **ACME runs on its own HTTPS loopback port** (RFC 8555 requires HTTPS). Its cert comes from our CA and covers `localhost`, `127.0.0.1` and `::1`.
- **Admin endpoints are never on the gateway.** The gateway only routes configured hostnames, and unknown hosts get a 421 page.
- **The CLI is a thin client of the mgmt API.** There's one code path, and the daemon owns all state. The exceptions are commands that touch the OS or the CA key on disk: `install`, `trust`, `hosts`, `ca backup/restore`, `uninstall`.
- Ports: 7171 and 7443 are configurable. 5000 and 7000 are avoided because macOS AirPlay uses them.

### Package layout (merged where the spec's split adds nothing)

```
cmd/devca/main.go          CLI dispatch with stdlib flag
internal/store/            state persistence, atomic writes
internal/ca/               root create/load, leaf signing, name constraints
internal/certs/            manager: issue/renew/revoke/export, ownership, renewal loop
internal/acme/             RFC 8555 server, JWS verify, nonces, HTTP-01 validator
internal/gateway/          :80/:443, SNI, challenge serving, redirect, reverse proxy
internal/api/              mgmt REST API, host/origin/CSRF guard, embedded UI
internal/platform/         trust_*.go, hosts.go, service_*.go (build tags per OS)
web/                       Svelte 5 + TS + Vite; embed.go embeds web/dist
scripts/build.sh           reproducible cross-build
```

## 3. Storage

**Decided:** a **single JSON state file** (`state.json`, 0600) behind one mutex, written atomically (temp file, fsync, rename). The data set is tiny (dozens of services and certs, ACME objects pruned after 30 days), and this gives zero dependencies with no cgo.

The SQLite route would be `modernc.org/sqlite`: pure Go and well maintained, but about 10 transitive modules and roughly 6 MB of binary for what is a few KB of data.

Data dir: `os.UserConfigDir()/devca`, overridable with `--data` / `DEVCA_HOME`.
```
devca/
  state.json            services, certs, acme objects, settings, events (ring of 500)
  ca/root.pem, root.key 0600
  certs/<host>/certificate.pem  private-key.pem  bundle.pem  ca.pem
```

## 4. CA design

- Root: ECDSA P-256, 10 years. It's generated once by `install` or the first `serve`, and is never regenerated if it exists. A corrupt or missing key file is a hard error with an actionable message, never a silent regenerate.
- **Decided: name-constrained root.** The root carries critical NameConstraints: permitted DNS = configured suffixes + `localhost`, permitted IP = `127.0.0.0/8` and `::1/128`. Even if `root.key` is stolen, the trusted root **cannot** mint certs for `google.com`. That's the single biggest risk of a dev CA (mkcert doesn't do this). The cost: changing the suffix list later means a new root and re-trusting it.
- **Single tier, no intermediate.** An intermediate key would sit on the same disk with the same permissions, so the security gain is negligible. The name constraint is the real protection.
- Leaves: ECDSA P-256, default 30 days, SAN-only, EKU serverAuth, renewed when ⅓ of lifetime remains.
- **Key reuse on renewal** for managed hosts. Only `certificate.pem` changes on renewal, which removes the "new cert, old key" race for apps that reload files. The key is rotated on revoke or `--rekey`.
- Revocation: marked in state, removed from the gateway, export deleted, and re-issued if the service is still active. No CRL/OCSP, because browsers don't check them for local roots. *Add a CRL when a client actually asks for one.*
- Backup: `devca ca backup out.zip` (zip of the data dir, 0600, with a warning that it contains the CA key). `devca ca restore in.zip` refuses to overwrite an existing CA without `--force`. Both are filesystem-only, never over HTTP.

## 5. Services and ownership (spec §7)

Every hostname has exactly one owner, which is the service record:

| mode | who issues/renews | delivery |
|---|---|---|
| `proxy` (A) | DevCA | in-memory to gateway (+ files) |
| `export` (B) | DevCA | atomic files in `certs/<host>/` or a custom dir |
| `acme` (C) | the external ACME client | ACME download only. DevCA never auto-renews |

Rules:
- A hostname must end in an allowed suffix and pass strict label validation. No wildcards via ACME (they need DNS-01). *Impl: wildcard services were dropped too (YAGNI); one hostname per service.*
- An ACME order for an unowned host **auto-claims** it as mode C (low friction). An ACME order for a host owned by A/B is rejected with `rejectedIdentifier` and the message "api.local is managed by DevCA (proxy mode); switch it to acme mode in the UI".
- Internal issuance (A/B) calls `certs.Manager.Issue` directly. ACME finalize calls the **same** `Issue`. There is one issuance path.
- Export: write temp file, fsync, rename. Key first, then cert. `bundle.pem` (key+chain in one file) is the guaranteed-consistent option. Apps detect changes by mtime on `certificate.pem`. DevCA never restarts apps.

## 6. ACME server (RFC 8555)

- Endpoints: directory, newNonce (HEAD/GET), newAccount (incl. `onlyReturnExisting`), account update/deactivate, keyChange, newOrder, POST-as-GET for order/authz/cert, challenge, finalize, revokeCert. Every response carries `Replay-Nonce`. Errors are `application/problem+json` with `urn:ietf:params:acme:error:*`. The server sets `Location`, `Link rel="index"/"up"` and `Retry-After`.
- JWS: flattened JSON, verified with stdlib for RS256, ES256/384/512 and EdDSA. It checks `url == request URL`, a single-use nonce, `jwk` xor `kid`, and the RFC 7638 thumbprint. This is about 250 lines of stdlib code, tested with x/crypto/acme plus table tests for every rejection case. (`go-jose` was considered and isn't needed for this subset.)
- Nonces: in memory, random 128-bit, capped set. A restart invalidates them and clients retry on `badNonce`, as the RFC intends.
- **HTTP-01 validator (local validation only):**
  - Resolve the host with the system resolver. **Every** resolved IP must be loopback, otherwise the challenge fails ("this is local validation; DevCA does not check public reachability").
  - GET `http://host:<port>/.well-known/acme-challenge/<token>`. The port is 80, or the service's optional `validation_port`. That second option is needed because when DevCA's gateway holds :80, an external client's standalone server can't bind it (e.g. `lego --http.port :5002`).
  - Redirects are followed only to loopback. 10 s timeout, small body cap.
- **TLS-ALPN-01: skipped in v1.** The validator would be easy, but it always targets :443, which DevCA's gateway holds. Offering a challenge that fails whenever the proxy is on would cause confusing errors. *Add it when someone runs DevCA without the gateway.*
- `devca test acme api.local`: the CLI asks the daemon to run the x/crypto/acme client in-process against its own `https://localhost:7443` endpoint. The client publishes the token into the gateway's :80 challenge store, then validation goes over a real socket to `api.local:80`. Each step comes back with pass/fail and a hint. *Impl: returned when the run finishes, not streamed. The internal test account validates on the gateway's configured HTTP port.* It uses a flagged internal test account that may order A/B-owned hosts. The resulting cert is stored as `owner=test`, never exported, and revoked after verification.

## 7. Gateway / reverse proxy

- Listens on 127.0.0.1 **and** ::1, ports 80 and 443. Loopback only means no firewall prompts and no LAN exposure.
- :80 routing order: challenge paths first, then a 308 redirect to https for known hosts, and 404 for everything else.
- :443: `GetCertificate` reads from an in-memory map keyed by SNI and never issues during the handshake. Certs are provisioned when a service is added and on startup.
- Proxy: `httputil.ReverseProxy` with `Rewrite`. It sets X-Forwarded-For/Proto/Host, preserves the original Host header (as Caddy and nginx do), handles WebSockets natively, and serves a friendly 502 page that names the target when the upstream is down.
- **SSRF guard:** a target must be `http(s)://` + `localhost`/loopback IP + port. The dialer re-checks the resolved IP is loopback at connect time (guards against rebinding), and the target can't be DevCA's own ports.
- Health: a TCP dial to each upstream every 10 s, shown in the UI.
- Graceful shutdown with `http.Server.Shutdown` on SIGINT/SIGTERM.
- *Impl: the gateway speaks HTTP/1.1 only (no h2), which keeps WebSocket proxying simple.*
- Port errors are actionable. Linux: "run `devca install` (systemd with CAP_NET_BIND_SERVICE) or `sudo setcap cap_net_bind_service=+ep …`". macOS and Windows allow unprivileged binds to 80/443.

## 8. Security (spec §11)

- Mgmt guard on every request:
  - `Host` must be `127.0.0.1:port`, `localhost:port` or `[::1]:port`, which blocks DNS rebinding.
  - Mutating requests require `Content-Type: application/json` and `X-DevCA: 1`. That forces a CORS preflight, which we never answer.
  - `Origin`, when present, must match.
  - No CORS headers at all. That's CSRF protection without tokens.
- The CA key is never loaded into any HTTP handler path. The API exposes only the public cert and fingerprints.
- Leaf private keys go out via `export` files and a guarded API download. Mgmt is loopback-only and the guard blocks browsers on other origins.
- slog redaction: keys, JWS payloads and account keys are never logged.
- Files are 0600 and dirs 0700. Windows relies on the default ACLs of `%AppData%`.

## 9. Privileged OS operations (trust, hosts, service)

Pattern: the command runs unprivileged, shows exactly what will change, and asks `y/N`. Only then does it re-exec itself via `sudo` with `--data <dir> --yes`, so data-dir resolution never depends on sudo's `$HOME`. Windows needs an elevated terminal (except trust, see below). The UI never elevates. It shows the status plus a copy-able command.

- **Trust install/uninstall/status:**
  - macOS: `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain`.
  - Linux: detect debian, fedora or arch anchors dir + update command. Also NSS (`~/.pki/nssdb`, Firefox profiles) via `certutil` if present, otherwise print instructions.
  - Windows: `certutil -user -addstore Root`. No admin needed, and Windows shows its own confirmation dialog.
  - Status: verify a fresh leaf against the platform verifier, plus an NSS check on Linux.
  - Uninstall never runs implicitly.
- **Hosts:**
  - DevCA owns only a `# BEGIN devca` … `# END devca` block, with `127.0.0.1` + `::1` per name.
  - `devca hosts plan` shows a diff, `devca hosts apply` asks then writes, and `devca hosts remove` deletes the block.
  - Everything outside the block is byte-for-byte untouched.
  - The DNS cache is flushed on macOS.
- **Background service:**
  - macOS: LaunchAgent, which runs as the user.
  - Linux: a systemd system unit with `User=<you>` + `AmbientCapabilities=CAP_NET_BIND_SERVICE`.
  - Windows: a Task Scheduler ONLOGON task as the user. *Impl: replaced by a per-user `HKCU\…\Run` entry, since creating logon tasks usually needs admin rights.* `devca install` sets it up and `devca uninstall` removes only the service, then prints how to untrust the CA and where the data lives.

## 10. CLI (stdlib `flag`)

```
devca install | uninstall | serve | status
devca proxy add <host> <target> | list | remove <host>
devca cert issue <host> [--out dir] | list | renew <host> | revoke <host> | export <host> --out dir
devca ca info | export [--out file] | backup <zip> | restore <zip>
devca acme info
devca test acme <host>
devca trust install | uninstall | status
devca hosts plan | apply | remove
```
`cert issue` creates or updates a mode-B (export) service. *Impl: added `devca acme claim <host> [--port n]` to set a mode-C validation port, and `cert list --all`.*

## 11. Web UI (Svelte 5 + TS + Vite)

- A hash router in about 20 lines. Pages: Dashboard, Services, Certificates, ACME, CA, Settings. The UI polls every 3 s.
- One `app.css` with CSS custom properties, light and dark via `prefers-color-scheme`, and a system font stack.
- First run: the Dashboard shows a 3-step checklist (CA created ✓, trust CA → command + explanation of why it's sensitive, add your first service). Each step disappears when done.
- "Add service" is a single inline form: hostname, then mode tabs (Proxy / Files / ACME client), then target. Hostname resolution status shows with a hosts command if needed.
- Settings: ports (restart required), suffixes (read-only, explaining that changing them needs a new CA), validity, renew-before, log level, data dir (read-only), trust status.
- The `web/dist` placeholder `index.html` is committed so `go build` works without node. Real builds go through `scripts/build.sh`.

## 12. Build and tests

- `scripts/build.sh`: `npm ci && npm run build`, then `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$V"` for darwin/linux/windows × amd64/arm64. `package-lock.json` is committed, and go.mod pins the `toolchain`.
- Tests (stdlib `testing` only):
  - ca: constraints are enforced (an out-of-suffix leaf fails `Verify`), validity and key usage.
  - certs: hostname validation table, ownership conflicts, renewal timing with an injected clock, atomic export.
  - acme: JWS rejection table (bad sig, wrong url, reused nonce, alg none, jwk+kid); a full flow with x/crypto/acme against `httptest` (account, order, http-01, finalize, chain verify, revoke, keyChange).
  - gateway: challenge precedence over proxy, redirect, unknown host, SNI selection, WebSocket passthrough, SSRF target rejection.
  - api: Host/Origin/CSRF guard table.
  - Manual compat check: `lego` and `certbot` against the running server, documented in the README.
- Only macOS is runtime-tested here. Linux and Windows are cross-compiled and unit-tested via GOOS, and the platform code is kept small and isolated.

## 13. Stages

Same order as the spec. Each stage ends green with `go vet` + `go test ./...`.
1. store, ca, CLI skeleton, `install` / `ca info`.
2. certs manager, renewal, export, trust.
3. ACME server + HTTP-01 + `test acme`.
4. gateway, proxy, service modes, hosts.
5. Svelte UI.
6. Service install, build script.
7. Integration tests, security pass, README (incl. the mDNS section above).
