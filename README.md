# holodeck

Vela's demo sandbox — a single Go binary that hosts throwaway apps and wipes
the whole deck once a day. Vela ([nanoclaw](https://github.com/novaoc/nanoclaw))
POSTs an app's files to `/api/deploy` and gets back a live URL on its own
subdomain (`<slug>.demo.holode.xyz`). The GitHub repo of whatever was built is
the permanent copy — the holodeck program always ends.

## Two kinds of app

- **Static** — a bundle with an `index.html`, served straight from disk.
- **Container** — a bundle with a `Dockerfile`. holodeck builds the image and
  runs it in a locked-down container, reverse-proxying the app's subdomain to
  it. This is how a real app (Node, Python, Go, …) runs while staying boxed in.
  Bundle dependencies at **build** time — the runtime has no internet.

## Security

Running container apps means executing code, so:

- **Provenance (HMAC).** Vela is the only thing allowed to deploy. Beyond the
  bearer token, every deploy must carry `X-Holodeck-Sign` — an HMAC-SHA256 of
  the body under a shared build secret. A deploy is thus cryptographically
  proven to come from Vela's own build pipeline, not a replayed request or an
  arbitrary external repo. Missing/wrong signature → refused.
- **Container lockdown.** Each app: `--cap-drop ALL`, `--security-opt
  no-new-privileges`, hard `--memory` / `--cpus` / `--pids-limit`, and an
  **internal** docker network with **no internet egress** at runtime.
- **Blast-radius discipline.** holodeck only ever stops/removes docker
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

Mutating endpoints require `Authorization: Bearer $HOLODECK_TOKEN`.
`/api/deploy` additionally requires `X-Holodeck-Sign: hex(hmac_sha256(body,
$HOLODECK_BUILD_SECRET))`.

```
POST   /api/deploy    {name, port?, files:[{path, content}]}   → {url, slug, kind, expires}
GET    /api/apps                                                → [{slug, name, kind, state, …}]
DELETE /api/apps/{slug}
GET    /api/tls-check?domain=x   (no auth — Caddy's on_demand_tls "ask")
```

A container app needs a `Dockerfile` (port from `EXPOSE`, or pass `port`); a
static app needs an `index.html` at the root.

## Configuration (env)

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
| `HOLODECK_ADDR` | `:8700` | listen address |

## Deploy

holodeck orchestrates the host's Docker, so it runs with the docker socket
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

On the nanoclaw side set `NANOCLAW_SANDBOX_URL`, `NANOCLAW_SANDBOX_TOKEN`, and
`NANOCLAW_SANDBOX_SECRET` (= `HOLODECK_BUILD_SECRET`) and Vela gets `deploy_demo`.

MIT.
