# Holodex

Vela's demo sandbox — a single Go binary that hosts throwaway apps and wipes
the whole deck once a day. [Vela](https://github.com/novaoc/vela)
POSTs an app's files to `/api/deploy` and gets back a live URL on its own
subdomain (`<slug>.demo.holode.xyz`). The GitHub repo of whatever was built is
the permanent copy — the Holodex program always ends.

For repository-sized applications, Vela streams an immutable GitHub commit
archive directly to Holodeck. The GitHub token stays on Vela's board. Holodeck
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
  The preview Stripe identifiers are deliberately non-working: real Stripe
  test mode requires the user's own credentials and an egress-enabled host.

## Security

Running container apps means executing code, so:

- **Provenance (HMAC).** Vela is the only thing allowed to deploy. Beyond the
  bearer token, every deploy must carry `X-Holodeck-Sign` — an HMAC-SHA256 of
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
- **Mail credential isolation.** Rails previews can reach only Holodeck's
  rate-limited SMTP listener. Holodeck rewrites the sender and relays through
  the configured provider; app containers never receive the provider username
  or password. The relay accepts one recipient per message, messages up to 2MB,
  and at most 100 deliveries per UTC day by default.
- **Rails data isolation.** Each Rails preview gets its own labeled PostgreSQL
  container and volume on that internal network. Both are removed when the app
  sleeps, is deleted, or reaches the daily wipe.
- **Blast-radius discipline.** Holodex only ever stops/removes Docker
  resources it labels `holodeck=1` or names `holodeck-app-*` — it never touches
  anything else on the host (this box also runs other production containers).
- **Static isolation.** Per-app subdomains = per-app browser origins; directory
  listings off; dotfiles never served.

Residual risk is real — a container is a limit, not a perfect boundary, and
build steps run arbitrary code. This is a hobby demo deck on a private Discord.

## Slots & lifecycle

- **Slot cap.** At most `HOLODECK_MAX_APPS` (default 15) container apps run at
  once. Deploying when full puts the **least-recently-used** app that's been
  idle over 15 min **to sleep** (container + image removed, its page kept) to
  free a slot. If *every* app saw traffic within 15 min, the new deploy is
  refused rather than evicting someone actively working. Sleep is only ever
  triggered by needing a slot — an idle app otherwise stays up until the wipe.
- **Daily wipe.** Every app is deleted at `HOLODECK_WIPE_HOUR` (default 03:00)
  in `HOLODECK_TZ` (default `America/Mexico_City`). A backstop sweep also clears
  anything older than 25h in case the box was down at the wipe hour.

## API

The current compatibility API still accepts the `X-Holodeck-*` header family
so deployed Vela clients continue working during the name migration.

Mutating endpoints require `Authorization: Bearer $HOLODECK_TOKEN`.
All deploy and verification bodies additionally require `X-Holodeck-Sign`.
The archive signature covers canonical request metadata followed by the raw
compressed body, preventing a signed archive from being replayed with a changed
name, Dockerfile, target, or port.

```
POST   /api/deploy    {name, port?, files:[{path, content}]}   → {url, slug, kind, expires}
POST   /api/verify    signed GitHub .tar.gz                     → {receipt, logs, duration_ms, …}
POST   /api/deploy/archive signed .tar.gz + X-Holodeck-Verify  → {url, slug, kind, expires, …}
GET    /api/apps                                                → [{slug, name, kind, state, …}]
DELETE /api/apps/{slug}
GET    /api/tls-check?domain=x   (no auth — Caddy's on_demand_tls "ask")
```

A container app needs a `Dockerfile` (port from `EXPOSE`, or pass `port`); a
static app needs an `index.html` at the root.

Repository headers:

| Header | Verify | Deploy | Meaning |
|---|---:|---:|---|
| `X-Holodeck-Name` | required | required | display name, included in HMAC |
| `X-Holodeck-Target` | `test` | empty | verification Docker target |
| `X-Holodeck-Dockerfile` | `Dockerfile` | `Dockerfile` | safe relative Dockerfile path |
| `X-Holodeck-Port` | optional | optional | runtime port override |
| `X-Holodeck-Sign` | required | required | metadata-and-body HMAC |
| `X-Holodeck-Verify` | — | required | fresh exact-archive receipt |

## Configuration (env)

The current compatibility release retains the `HOLODECK_*` variable names so
an upgrade cannot silently drop deployment, signing, or mail-relay secrets.

| Var | Default | |
|---|---|---|
| `HOLODECK_TOKEN` | — (required) | deploy bearer token |
| `HOLODECK_BUILD_SECRET` | — (required) | HMAC provenance secret (matches nanoclaw's `NANOCLAW_SANDBOX_SECRET`) |
| `HOLODECK_DOMAIN` | `demo.holode.xyz` | apps at `<slug>.<domain>` |
| `HOLODECK_DATA` | `/srv/holodeck` | app storage |
| `HOLODECK_NET` | `holodeck-net` | internal docker network for app containers |
| `HOLODECK_TZ` | `America/Mexico_City` | wipe timezone |
| `HOLODECK_WIPE_HOUR` | `3` | daily wipe hour (0–23) |
| `HOLODECK_MAX_APPS` | `15` | concurrent container-app slots |
| `HOLODECK_MEM` / `HOLODECK_CPUS` / `HOLODECK_PIDS` | `512m` / `0.5` / `256` | per-app caps |
| `HOLODECK_BUILD_TIMEOUT_S` | `300` | image build timeout |
| `HOLODECK_VERIFY_TIMEOUT_S` | `900` | test + final image verification timeout |
| `HOLODECK_ADDR` | `:8700` | listen address |
| `HOLODECK_SMTP_ADDRESS` / `HOLODECK_SMTP_PORT` | — / `587` | upstream SMTP provider; setting one relay variable requires all credentials below |
| `HOLODECK_SMTP_USERNAME` / `HOLODECK_SMTP_PASSWORD` | — | upstream credentials, held only by Holodeck |
| `HOLODECK_SMTP_FROM` | — | verified sender rewritten onto every preview message |
| `HOLODECK_SMTP_LISTEN` | `:2525` | private-network SMTP listener |
| `HOLODECK_SMTP_MAX_DAILY` | `100` | whole-deck daily delivery cap |

## Deploy

Holodex orchestrates the host's Docker, so it runs with the Docker socket
mounted and the docker CLI available:

```bash
make linux
docker network create --internal holodeck-net   # once
scp holodeck-linux-amd64 root@<server>:/srv/holodeck/bin/holodeck
docker run -d --name holodeck --restart unless-stopped \
  --network <caddy-network> \
  -v /srv/holodeck:/srv/holodeck \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e HOLODECK_TOKEN=<openssl rand -hex 24> \
  -e HOLODECK_BUILD_SECRET=<openssl rand -hex 32> \
  -e HOLODECK_DOMAIN=demo.example.com \
  docker:cli /srv/holodeck/bin/holodeck
docker network connect holodeck-net holodeck   # reach app containers
```

Caddy in front (on-demand TLS, cert minting gated by the app):

```caddy
{
	on_demand_tls {
		ask http://holodeck:8700/api/tls-check
	}
}

demo.example.com, *.demo.example.com {
	encode zstd gzip
	tls { on_demand }
	reverse_proxy holodeck:8700
}
```

DNS: `demo` and `*.demo` A records → the server.

On the Vela side set `NANOCLAW_SANDBOX_URL`, `NANOCLAW_SANDBOX_TOKEN`, and
`NANOCLAW_SANDBOX_SECRET` (= `HOLODECK_BUILD_SECRET`) and Vela gets `deploy_demo`.

MIT.
