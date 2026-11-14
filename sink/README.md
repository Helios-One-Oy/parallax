# sink — the Parallax endpoint and specimen registry

One Bun file (`server.ts`). Deployed on Fly as **`parallax-sink`** →
`https://parallax-sink.fly.dev`.

## Routes

- `GET /healthz` — liveness.
- `GET /stage2/:id` — a small "second stage" text file (records a hit).
- `POST /collect` — accepts **only** the constant specimen JSON
  `{"specimen":<known id>,"run":<string>}` → `204`; anything else → `400`.
- `GET /registry/@nbd%2f<name>` (and `/registry/@nbd/<name>`) — npm packument.
- `GET /registry/tarballs/<file>.tgz` — specimen tarball.
- `GET /hits?since=<iso|ms>` — recorded hits as JSON. Only `time, path, specimen, run`
  are stored; nothing else.

## Build the registry (generated, not hand-written)

```
node build.cjs          # npm pack each specimen into registry/tarballs + registry/meta.json
```

The server builds packuments from `registry/meta.json` at request time, with tarball
URLs derived from the request host, so the same content works on localhost and on Fly.

## Deploy

```
node build.cjs
hsec exec --only FLY_API_TOKEN -- fly deploy --remote-only --now --ha=false
```

Built remotely on Fly builders (no local Docker). App: smallest `shared-cpu-1x`,
region `arn`, `auto_stop_machines = off`, one machine always running.

## Read the hits

```
curl -s https://parallax-sink.fly.dev/hits | jq .
curl -s "https://parallax-sink.fly.dev/hits?since=$(date -u -d '-1 hour' +%s%3N)"
```
