# Holodex

**An optional deploy target for [Vela](https://github.com/novaoc/vela)** — a
single Go binary that hosts throwaway apps and wipes the whole deck once a
day. Vela POSTs an app to it and gets back a live URL on its own subdomain
(`<slug>.demo.holode.xyz`). The GitHub repo of whatever was built is the
permanent copy — the Holodex program always ends.

> **You do not need this to run Vela.** Vela is an agent harness; she
> researches, writes, charts, and publishes GitHub repositories on her own.
> Holodex answers one extra question — *can I click it?* — by turning a
> verified build into a live demo. Without it, `/request` finishes at a public
> repository with passing tests and says so up front. Add Holodex when you
> want the demo half; nothing else in the harness depends on it.

## Adding it to a Vela install

Holodex needs a box you already own with Docker and a domain pointed at it. It
orchestrates the host's Docker daemon, so it runs with the socket mounted —
give it a machine you are willing to let build arbitrary code.

Build and run it (see [Deploy](#deploy) for the full command), then point a
wildcard `*.demo.<your-domain>` at the box through a reverse proxy that asks
`/api/tls-check` before minting certificates. Finally tell Vela it exists:

```bash
VELA_SANDBOX_URL=https://api.<your-domain>
VELA_SANDBOX_TOKEN=<same value as HOLODEX_TOKEN>
VELA_SANDBOX_SECRET=<same value as HOLODEX_BUILD_SECRET>
```

Restart Vela and the deploy tools appear in her belt automatically. The build
secret is what makes a deploy provably hers, so it lives on her machine and on
this server — nowhere else, and never in a repository.

For repository-sized applications, Vela streams an immutable GitHub commit
archive directly to Holodex. The GitHub token stays on Vela's board. Holodex
first builds the repository's Docker `test` target and its deployable final
image in a disposable workspace. A successful run returns a one-hour HMAC
receipt bound to the exact archive digest; deployment refuses any other bytes.

## Two kinds of app

- **Static** — a bundle with an `index.html`, served straight from disk.
- **Container** — a bundle with a `Dockerfile`. Holodex builds the image and
  runs it in a locked-down container, reverse-proxying the app's subdomain to
  it. This is how a real app (Node, Python, Go, …) runs while staying boxed in.
  Bundle dependencies at **build** time — the runtime has no internet.
- **Rails preview runtime** — a detected Rails app receives a private
  PostgreSQL sidecar, generated ephemeral application/encryption secrets, and
  local upload storage. If the host configures the private SMTP relay, previews
  can send confirmation and password-reset mail without receiving the upstream
  provider credentials. No secret is read from or written to its public repo.
  No Stripe keys or webhook secrets are injected: previews demonstrate commerce
  through the app's local test checkout, and real Stripe (test or live) always
  requires a self-hoster's own credentials on an egress-enabled host.

## Security

Running container apps means executing code, so:

- **Provenance (HMAC).** Vela is the only thing allowed to deploy. Beyond the
  bearer token, every deploy must carry `X-Holodex-Sign` — an HMAC-SHA256 of
  the body under a shared build secret. A deploy is thus cryptographically
  proven to come from Vela's own build pipeline, not a replayed request or an
  arbitrary external repo. Missing/wrong signature → refused.
- **Verify before deploy.** Repository deploys need a fresh receipt proving the
  exact archive passed its Docker `test` target and produced a final image.
  Uploaded archives reject path traversal, links, special files, `.git` data,
  oversized expansion, and excess file counts. Workspaces and verification
  images are removed after every result.
- **Container lockdown.** Each app: `--cap-drop ALL`, `--security-opt
  no-new-privileges`, hard `--memory` / `--cpus` / `--pids-limit`, and an
  **internal** docker network with **no internet egress** at runtime.
- **Mail credential isolation.** Rails previews can reach only Holodex's
  rate-limited SMTP listener. Holodex rewrites the sender and relays through
  the configured provider; app containers never receive the provider username
  or password. The relay accepts one recipient per message, messages up to 2MB,
  and at most 100 deliveries per UTC day by default.
- **Rails data isolation.** Each Rails preview gets its own labeled PostgreSQL
  container and volume on that internal network. Both are removed when the app
  sleeps, is deleted, or reaches the daily wipe.
- **Blast-radius discipline.** Holodex only ever stops/removes Docker
  resources it labels `holodex=1` or names `holodex-app-*` (plus the legacy
  `holodeck-*` names during the rolling rename) — it never touches anything
  else on the host (this box also runs other production containers).
- **Static isolation.** Per-app subdomains = per-app browser origins; directory
  listings off; dotfiles never served.

Residual risk is real — a container is a limit, not a perfect boundary, and
build steps run arbitrary code. This is a hobby demo deck on a private Discord.

## Slots & lifecycle

- **Slot cap.** At most `HOLODEX_MAX_APPS` (default 15) container apps run at
  once. Deploying when full puts the **least-recently-used** app that's been
  idle over 15 min **to sleep** (container + image removed, its page kept) to
  free a slot. If *every* app saw traffic within 15 min, the new deploy is
  refused rather than evicting someone actively working. Sleep is only ever
  triggered by needing a slot — an idle app otherwise stays up until the wipe.
- **Daily wipe.** Every app is deleted at `HOLODEX_WIPE_HOUR` (default 03:00)
  in `HOLODEX_TZ` (default `America/Mexico_City`). A backstop sweep also clears
  anything older than 25h in case the box was down at the wipe hour.

## API

The primary protocol is the `X-Holodex-*` header family. The legacy
`X-Holodeck-*` family (with its `holodeck-archive-v1` canonical HMAC prefix)
is still verified during the rolling rename so already-deployed Vela clients
keep working; a request uses exactly one family.

Mutating endpoints require `Authorization: Bearer $HOLODEX_TOKEN`.
All deploy and verification bodies additionally require `X-Holodex-Sign`.
The archive signature covers canonical request metadata (prefix
`holodex-archive-v1`) followed by the raw compressed body, preventing a signed
archive from being replayed with a changed name, Dockerfile, target, or port.

```
POST   /api/deploy    {name, port?, files:[{path, content}]}   → {url, slug, kind, expires}
POST   /api/verify    signed GitHub .tar.gz                     → {receipt, logs, duration_ms, …}
POST   /api/deploy/archive signed .tar.gz + X-Holodex-Verify   → {url, slug, kind, expires, …}
GET    /api/apps                                                → [{slug, name, kind, state, …}]
DELETE /api/apps/{slug}
GET    /api/tls-check?domain=x   (no auth — Caddy's on_demand_tls "ask")
```

A container app needs a `Dockerfile` (port from `EXPOSE`, or pass `port`); a
static app needs an `index.html` at the root.

Repository headers:

| Header | Verify | Deploy | Meaning |
|---|---:|---:|---|
| `X-Holodex-Name` | required | required | display name, included in HMAC |
| `X-Holodex-Target` | `test` | empty | verification Docker target |
| `X-Holodex-Dockerfile` | `Dockerfile` | `Dockerfile` | safe relative Dockerfile path |
| `X-Holodex-Port` | optional | optional | runtime port override |
| `X-Holodex-Sign` | required | required | metadata-and-body HMAC |
| `X-Holodex-Verify` | — | required | fresh exact-archive receipt |

## Configuration (env)

Settings are read as `HOLODEX_*` first, falling back to the legacy
`HOLODECK_*` names, so an upgrade cannot silently drop deployment, signing, or
mail-relay secrets while existing env files are migrated.

| Var | Default | |
|---|---|---|
| `HOLODEX_TOKEN` | — (required) | deploy bearer token |
| `HOLODEX_BUILD_SECRET` | — (required) | HMAC provenance secret (matches Vela's sandbox secret) |
| `HOLODEX_DOMAIN` | `demo.holode.xyz` | apps at `<slug>.<domain>` |
| `HOLODEX_DATA` | `/srv/holodeck` | app storage (legacy path kept for live data) |
| `HOLODEX_NET` | `holodeck-net` | internal docker network for app containers |
| `HOLODEX_TZ` | `America/Mexico_City` | wipe timezone |
| `HOLODEX_WIPE_HOUR` | `3` | daily wipe hour (0–23) |
| `HOLODEX_MAX_APPS` | `15` | concurrent container-app slots |
| `HOLODEX_MEM` / `HOLODEX_CPUS` / `HOLODEX_PIDS` | `512m` / `0.5` / `256` | per-app caps |
| `HOLODEX_BUILD_TIMEOUT_S` | `300` | image build timeout |
| `HOLODEX_VERIFY_TIMEOUT_S` | `900` | test + final image verification timeout |
| `HOLODEX_ADDR` | `:8700` | listen address |
| `HOLODEX_SMTP_ADDRESS` / `HOLODEX_SMTP_PORT` | — / `587` | upstream SMTP provider; setting one relay variable requires all credentials below |
| `HOLODEX_SMTP_USERNAME` / `HOLODEX_SMTP_PASSWORD` | — | upstream credentials, held only by Holodex |
| `HOLODEX_SMTP_FROM` | — | verified sender rewritten onto every preview message |
| `HOLODEX_SMTP_LISTEN` | `:2525` | private-network SMTP listener |
| `HOLODEX_SMTP_HOSTNAME` | `holodex` | internal hostname injected into previews as `SMTP_ADDRESS` |
| `HOLODEX_SMTP_MAX_DAILY` | `100` | whole-deck daily delivery cap |

## Deploy

Holodex orchestrates the host's Docker, so it runs with the Docker socket
mounted and the docker CLI available:

```bash
make linux
docker network create --internal holodeck-net   # once
scp holodex-linux-amd64 root@<server>:/srv/holodeck/bin/holodex
docker run -d --name holodex --restart unless-stopped \
  --network <caddy-network> \
  -v /srv/holodeck:/srv/holodeck \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e HOLODEX_TOKEN=<openssl rand -hex 24> \
  -e HOLODEX_BUILD_SECRET=<openssl rand -hex 32> \
  -e HOLODEX_DOMAIN=demo.example.com \
  docker:cli /srv/holodeck/bin/holodex
docker network connect holodeck-net holodex   # reach app containers
```

Caddy in front (on-demand TLS, cert minting gated by the app):

```caddy
{
	on_demand_tls {
		ask http://holodex:8700/api/tls-check
	}
}

demo.example.com, *.demo.example.com {
	encode zstd gzip
	tls { on_demand }
	reverse_proxy holodex:8700
}
```

DNS: `demo` and `*.demo` A records → the server.

On the Vela side set `VELA_SANDBOX_URL`, `VELA_SANDBOX_TOKEN`, and
`VELA_SANDBOX_SECRET` (= `HOLODEX_BUILD_SECRET`) and Vela gets `deploy_demo`.

MIT.
