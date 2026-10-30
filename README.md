# DevCA

Local HTTPS for development. One binary that gives you:

- a **local certificate authority** your machine trusts once,
- an **HTTPS gateway** that proxies `https://api.localhost` to `localhost:3000`,
- **certificate files** for apps that do their own TLS, renewed automatically,
- an **ACME server** (RFC 8555, HTTP-01) for lego, certbot, Caddy and other clients,
- a small **web UI** and a **CLI** for the same operations.

The goal is to make local HTTPS boring.

## Quick start

Download the binary for your platform (`devca-<os>-<arch>`) and run `install` from wherever it landed:

```sh
# macOS: downloaded binaries are quarantined (unsigned); clear that first
xattr -d com.apple.quarantine ~/Downloads/devca-darwin-arm64
# Linux: chmod +x devca-linux-amd64

~/Downloads/devca-darwin-arm64 install   # Windows: devca-windows-amd64.exe install
```

`install` does the following, asking before each system change:
1. Creates the CA.
2. Offers to trust it.
3. Copies the program to `~/.local/bin/devca` (Windows: `%LOCALAPPDATA%\Programs\devca\devca.exe`) and tells you if that directory isn't on your PATH yet.
4. Offers to run DevCA in the background from there.

Afterwards the download can be deleted. To upgrade, run `install` from a newer download; it replaces the copy and restarts the service.

```sh
devca proxy add api.localhost 3000    # https://api.localhost -> http://localhost:3000
open https://api.localhost
```

The web UI is at <http://127.0.0.1:7171>.

To run in the foreground instead of as a service, use `devca serve`.

## Three ways to use a hostname

Each hostname has exactly one owner, so two parties never renew the same name.

| Mode | Who handles TLS | Who renews | How |
|---|---|---|---|
| **Proxy** | DevCA | DevCA | `devca proxy add api.localhost 3000` |
| **Files** | your app | DevCA | `devca cert issue api.localhost --out ./certs` |
| **ACME client** | your app | your ACME client | `devca acme claim api.localhost --port 5002`, then point the client at DevCA |

### Proxy

- DevCA listens on `127.0.0.1` and `::1`, ports 80 and 443.
- It picks the certificate by SNI and forwards to your app, including WebSockets.
- It preserves the `Host` header and sets `X-Forwarded-For/-Proto/-Host`.
- Port 80 serves ACME challenges first and redirects everything else to HTTPS.
- Unknown hostnames are refused.
- Targets must be on this machine (`localhost`, `127.0.0.1`, `::1`). DevCA will not proxy into your LAN or the Internet.

### Files

`devca cert issue api.localhost --out ./certs` writes these files:

```
certs/
├── certificate.pem   # leaf certificate
├── private-key.pem   # 0600
├── bundle.pem        # private key + certificate in one file
└── ca.pem            # DevCA root, for clients that need it
```

The same files also live in DevCA's data directory under `certs/<host>/`.

How renewal works:
- Files are replaced **atomically** (temp file + rename), so a reader never sees a half-written file.
- The **private key is kept across renewals**, so on a normal renewal only `certificate.pem` changes. Your app never sees a new certificate with an old key.
- DevCA never restarts your app. To reload, watch `certificate.pem` for changes (mtime), or simply reload on a schedule. Certificates last 30 days and are renewed 10 days before expiry.

### ACME client

```sh
devca acme claim app.localhost --port 5002
LEGO_CA_CERTIFICATES=~/.config/devca/ca/root.pem \
  lego --server https://localhost:7443/acme/directory --email you@example.com \
       --domains app.localhost --http --http.port :5002 run
```

On macOS the data dir is `~/Library/Application Support/devca`. `devca ca info` shows the path.

- Only **HTTP-01** is supported. While DevCA's gateway holds port 80, run the client's challenge server on another port and register that port with `acme claim --port`.
- If you don't run the gateway (Settings → disable it), clients can use port 80 directly.
- An order for a hostname nobody owns yet claims it automatically.
- An order for a hostname that DevCA manages in Proxy or Files mode is rejected, with a message saying how to switch it.
- Clients must trust DevCA's root: either run `devca trust install`, or pass `ca.pem` (`LEGO_CA_CERTIFICATES`, `REQUESTS_CA_BUNDLE` for certbot, etc.).

**Validation is local.** DevCA checks the token over loopback, and only if the name resolves to a loopback address. A successful validation proves the name points at *this machine*. It says nothing about reachability from the Internet.

**Testing the whole flow.** `devca test acme api.localhost` runs a full issuance against the running server with an independent client (`golang.org/x/crypto/acme`): account, order, HTTP-01 via the gateway, finalize, chain verification, then revocation. Each step reports a diagnosis if it fails.

**Tested clients:** `golang.org/x/crypto/acme`, which is used in the test suite, and lego v4 (issue, renew, revoke). certbot, acme.sh and Caddy should work, since only standard RFC 8555 is used, but haven't been tested yet.

### Forwarding HTTPS to an app that does its own TLS

A Files or ACME client service normally serves HTTPS on its own port, e.g. `https://app.localhost:8443`. To reach it on the standard port instead, let the gateway forward it:

```sh
devca cert issue app.localhost --out ./certs --forward 8443   # or: devca acme claim app.localhost --forward 8443
```

Now `https://app.localhost` works.
- **The traffic stays encrypted.** The gateway reads only the hostname the client sends at the start of the TLS handshake (SNI). It then passes the connection, still encrypted, to `localhost:8443`, so your app's own certificate is used and DevCA never decrypts anything.
- **Port 80 redirects to HTTPS** for these hosts too.
- **Forward targets follow the proxy rules:** they must be on this machine and can't be DevCA's own ports.
- **Your app sees connections from `127.0.0.1`.** There's no `X-Forwarded-For`, because headers can't be added to encrypted traffic.
- **Clients must send the hostname.** One connecting to `https://127.0.0.1` reaches DevCA's gateway instead.
- **Can't be combined with a custom loopback address,** since the hostname has to point at the gateway.

In the UI this is the optional "Forward HTTPS" field on Files and ACME client services.

## Hostnames, `.localhost`, `.local` and mDNS

DevCA allows names ending in **`.localhost`** (the default) and **`.local`**.

**`.localhost`** (RFC 6761) is reserved for loopback.
- Chrome, Firefox and Edge resolve `*.localhost` to 127.0.0.1 on every OS, with no setup.
- So do curl and systemd-resolved.
- Safari and some command-line tools on macOS still need a hosts entry.
- Bonus: Vite's default `allowedHosts` accepts `*.localhost` but not `*.local`.

**`.local`** is reserved for **mDNS** (Bonjour/Avahi):
- macOS sends `.local` lookups to multicast DNS.
- Linux does too when `nss-mdns` is installed.
- Windows 10+ also queries mDNS.

A hosts-file entry overrides mDNS on all three, and that's what DevCA uses:

```sh
devca hosts plan     # show the change
devca hosts apply    # asks, then edits (sudo / Administrator)
devca hosts remove   # removes DevCA's block again
```

How DevCA edits the hosts file:
- It only touches its own `# BEGIN devca … # END devca` block.
- It always shows the diff first and asks before writing.
- It writes both `127.0.0.1` and `::1` for each name. Without the IPv6 line, macOS stalls for about 5 seconds on `.local` names while it waits for mDNS.

### Two services on the same port

Two apps can't both listen on `127.0.0.1:8443`. If you can change their ports, that's the simplest fix. If both need the same port, for example two instances of one app, or software where the port isn't configurable, give each hostname its own loopback address. Every address in `127.0.0.0/8` points to your own machine:

```sh
devca cert issue one.localhost --address 127.0.0.2 --out ./one/certs
devca cert issue two.localhost --address 127.0.0.3 --out ./two/certs
devca hosts apply      # writes "127.0.0.2 one.localhost" and "127.0.0.3 two.localhost"
```

Then bind each app to its own address (`127.0.0.2:8443` and `127.0.0.3:8443`). The same `--address` flag works with `devca acme claim`, and ACME validation then checks that address too. In the UI it's the optional "Loopback address" field.

- **macOS** only configures `127.0.0.1`. Add the others first with `sudo ifconfig lo0 alias 127.0.0.2 up`. Aliases are lost on reboot, so re-run that or add it to a startup script. **Linux** and **Windows** answer on the whole `127.0.0.0/8` range out of the box.
- **Browsers ignore the hosts file for `*.localhost`** and always connect to `127.0.0.1`. This setup is therefore for clients that use the system resolver (CLI tools, SDKs, other services). If a browser must reach a service on its own address, use a `.local` name instead.
- **Only for Files and ACME client services.** Proxy services are reached through the gateway on `127.0.0.1`.
- **Only the custom address is written.** DevCA writes just that IPv4 line, with no `::1` line, so clients can't end up at a different service over IPv6.

**Why DevCA doesn't answer `.local` names over mDNS itself:**
- mDNS announces names to everyone on your network. Answering `api.local → 127.0.0.1` tells every other machine on the Wi-Fi that `api.local` is *their own* loopback address, which RFC 6762 forbids.
- Two developers on the same network who both use `api.local` would trigger mDNS conflict resolution, and one of them would get renamed to `api-2.local`.
- It would mean sharing UDP 5353 with mDNSResponder, Avahi or the Windows DNS Client on each OS.

The one legitimate use, publishing your LAN IP so a phone can reach your dev server, needs the gateway exposed on the LAN and the CA installed on the phone. It isn't in this version.

**Alternatively, use a domain you own.** You can point names like `*.dev.example.com` at 127.0.0.1 in public DNS. DevCA can't issue for these by default, because its root is restricted to `.localhost` and `.local` (see below), and widening that means creating a new root.

## Trust

`devca trust install` explains what it's about to do and asks before changing anything.

| OS | Where | Notes |
|---|---|---|
| macOS | System keychain (`security add-trusted-cert`, asks for your password) | Safari, Chrome and Edge use it. Firefox does too with its default `security.enterprise_roots.enabled` |
| Windows | Current user's Root store (`certutil -user`, Windows shows a confirmation dialog) | Chrome and Edge use it. Firefox does with enterprise roots enabled (the default) |
| Linux | `/usr/local/share/ca-certificates` (Debian/Ubuntu), `/etc/pki/ca-trust/source/anchors` (Fedora), `/etc/ca-certificates/trust-source/anchors` (Arch) | Firefox and Chrome use their own NSS store. Install `certutil` (`libnss3-tools` / `nss-tools`) and DevCA updates `~/.pki/nssdb` and Firefox profiles too |

Other runtimes keep their own trust and need `ca.pem` explicitly:
- **Node:** `NODE_EXTRA_CA_CERTS=/path/to/ca.pem`
- **Java:** import `ca.pem` into the keystore
- **Python requests:** `REQUESTS_CA_BUNDLE=/path/to/ca.pem`
- **Docker containers:** mount `ca.pem` and add it to the container's trust store

`devca trust status` checks the current state, and `devca trust uninstall` removes the root again. Restart your browser after changing trust.

## Security model

DevCA runs on a developer workstation and is not meant to be exposed to a network.

- **Name-constrained root.** The root CA carries critical X.509 name constraints. It can only sign for the allowed suffixes (`localhost`, `local`) and loopback IPs (`127.0.0.0/8`, `::1`). Even if `root.key` is stolen, it can't be used to impersonate `google.com` or any other public site, as long as the client enforces name constraints, which current browsers and OS verifiers do. The cost: changing the allowed suffixes means creating and trusting a new root.
- **Issuance policy** is also enforced in code. Only valid hostnames under the allowed suffixes, plus loopback IPs, are accepted. Wildcards are not supported over ACME.
- **The CA key never goes over HTTP.** Only the public certificate is served, and backup/restore are filesystem-only CLI commands.
- **Everything listens on loopback only:** management UI/API, ACME and the gateway.
- **Management API protections:**
  - **DNS rebinding:** the `Host` header must be `127.0.0.1`, `localhost` or `[::1]` with the right port.
  - **CSRF:** every `/api` request needs an `X-DevCA: 1` header. Browsers can't add custom headers cross-origin without a CORS preflight, and DevCA never answers preflights. Mismatched `Origin` and cross-site `Sec-Fetch-Site` requests are refused as well.
  - The UI is served with a strict CSP and `frame-ancestors 'none'`.
  - There's no login on purpose. Remote management isn't supported, and would need real authentication if it ever is.
- **The gateway never serves admin endpoints.** Proxy targets are restricted to loopback, checked again at connect time, and can't point at DevCA's own ports.
- **The ACME HTTP-01 validator** only connects to loopback addresses, ignores HTTP proxy settings and caps response sizes.
- **Files:** the data dir is `0700`, keys are `0600`, and every write is atomic.
- **Logs** never contain private keys or JWS payloads.

## CLI

```
devca install | uninstall | serve | status
devca proxy add <host> <target> | list | remove <host>
devca cert issue <host> [--out dir] | list [--all] | renew <host> | revoke <host|id> | export <host> --out dir
devca acme info | claim <host> [--port n]
devca test acme <host>
devca ca info | export [--out file] | backup <file.zip> | restore <file.zip> [--force]
devca trust install | uninstall | status
devca hosts plan | apply | remove
```

How the commands work:
- Every command accepts `--data <dir>`. The default is `os.UserConfigDir()/devca`, and it can be overridden with `DEVCA_HOME`.
- Service and certificate commands talk to the running DevCA (`devca serve` or the background service).
- CA, trust and hosts commands work directly on files and the OS.

**`devca install`:**
- creates the CA,
- offers to trust it,
- offers to run DevCA in the background: a launchd agent on macOS, a systemd unit running as your user with only `CAP_NET_BIND_SERVICE` on Linux, or a per-user startup entry (`HKCU\…\Run`, no admin rights) on Windows.

**`devca uninstall`** removes only the background service. It never deletes your CA or certificates, and never removes trust or hosts entries silently.

## Data directory

```
devca/
├── state.json            settings, services, certificate records, ACME state, activity log
├── ca/root.pem           root certificate (public)
├── ca/root.key           root private key (0600)
├── certs/<host>/         certificate files for Proxy and Files services
├── acme-test.key         account key used by `devca test acme`
└── devca.log             background-service log (macOS, Windows)
```

## Building

```sh
scripts/build.sh          # npm ci + svelte-check + vite build, go vet/test, cross-compile
```

This produces static binaries (`CGO_ENABLED=0`, `-trimpath`) in `dist/devca-<os>-<arch>` for macOS, Linux and Windows on amd64 and arm64, plus `SHA256SUMS`. The version (from `git describe`, or `VERSION=`) is embedded and shown by `devca version`.

**Releases:** pushing a `v*` tag runs `.github/workflows/release.yml`. It builds and tests with `scripts/build.sh` on GitHub Actions, then publishes a GitHub release with every binary and `SHA256SUMS`. Tags with a hyphen (`v1.0.0-rc.1`) become pre-releases.

```sh
git tag v0.1.0 && git push origin v0.1.0
```

To develop against the installed service, symlink the build instead of copying it. `install` leaves a symlink to the running binary alone, and after each rebuild you only restart the service:

```sh
ln -sfn "$PWD/dist/devca-darwin-arm64" ~/.local/bin/devca && devca install
launchctl kickstart -k gui/$(id -u)/dev.devca   # after a rebuild (Linux: sudo systemctl restart devca)
```

Dependencies are kept deliberately small:
- **Go:** the standard library plus `golang.org/x/crypto/acme`, which is used only as an *independent* client for the self-test.
- **Frontend:** Svelte 5, Vite and TypeScript, with exact versions pinned. Icons are a handful of inlined Heroicons paths.

`go build ./cmd/devca` works without Node. The binary then shows a "UI not built" page, and the CLI is fully functional.

For UI development, run `cd web && npm run dev`. It proxies `/api` to a running DevCA on port 7171.

## Not in this version

These are deliberately left out:
- **TLS-ALPN-01:** it targets port 443, which the gateway already holds.
- **DNS-01 and wildcards over ACME.**
- **CRL/OCSP:** browsers don't check them for local roots, so revocation takes effect in DevCA itself.
- **mDNS publishing.**
- **Remote management.**
- **HTTP/2 on the gateway:** proxied services get HTTP/1.1, which is fine for development, and WebSockets work. Forwarded (passthrough) services negotiate HTTP/2 directly with the app.

Platform testing: the platform-specific code (trust store, hosts file, background service) has only been run on macOS so far. Linux and Windows builds compile and pass the unit tests.
