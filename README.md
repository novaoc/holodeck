# holodeck

Vela's demo sandbox — a single static Go binary that hosts throwaway static
sites. Vela ([nanoclaw](https://github.com/novaoc/nanoclaw)) POSTs an app's
files to `/api/deploy` and gets back a live URL on its own subdomain
(`<slug>.demo.holode.xyz`); a sweeper deletes every app **7 days after
deploy**. The GitHub repo of whatever was built is the permanent copy — the
holodeck program always ends.

## How it works

- **Static only.** Nothing uploaded here ever executes on the server. Files
  are served as-is; directory listings are off; dotfiles are never served.
- **Per-app subdomains.** Each demo gets `<name>-<rand>.demo.<domain>` — its
  own browser origin, so demos can't touch each other.
- **7-day TTL.** An hourly sweeper removes anything past its deploy + TTL
  (`HOLODECK_TTL_HOURS`, default 168).
- **Safe cert minting.** It sits behind Caddy with on-demand TLS, and
  `/api/tls-check` approves certificates only for the base domain and apps
  that actually exist — pointing stray DNS at the box mints nothing.
- **Caps.** 64 files / 10 MB per app; paths are sanitized (no traversal).

## API

All mutating endpoints require `Authorization: Bearer $HOLODECK_TOKEN`.

```
POST   /api/deploy         {name, files:[{path, content}]}   → {url, slug, expires}
GET    /api/apps                                             → [{slug, name, created, expires}]
DELETE /api/apps/{slug}
GET    /api/tls-check?domain=x   (no auth — Caddy's on_demand_tls "ask")
```

`index.html` at the root is required — it's the homepage.

## Configuration (env)

| Var | Default | |
|---|---|---|
| `HOLODECK_TOKEN` | — (required) | deploy bearer token |
| `HOLODECK_DOMAIN` | `demo.holode.xyz` | apps live at `<slug>.<domain>` |
| `HOLODECK_DATA` | `/srv/holodeck` | apps stored in `<data>/apps/` |
| `HOLODECK_ADDR` | `:8700` | listen address |
| `HOLODECK_TTL_HOURS` | `168` | demo lifetime |

## Deploy

```bash
make linux
scp holodeck-linux-amd64 root@<server>:/srv/holodeck/bin/holodeck
docker run -d --name holodeck --restart unless-stopped \
  --network <caddy-network> \
  -v /srv/holodeck:/srv/holodeck \
  -e HOLODECK_TOKEN=<generate one: openssl rand -hex 24> \
  -e HOLODECK_DOMAIN=demo.example.com \
  -e HOLODECK_DATA=/srv/holodeck \
  alpine:3 /srv/holodeck/bin/holodeck
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
	tls {
		on_demand
	}
	reverse_proxy holodeck:8700
}
```

DNS: `demo` and `*.demo` A records → the server.

On the nanoclaw side, set `NANOCLAW_SANDBOX_URL` and `NANOCLAW_SANDBOX_TOKEN`
and Vela gets the `deploy_demo` tool.

MIT.
