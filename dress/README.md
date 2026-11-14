# dress — Parallax twin dressing action

Composite GitHub Action. Input `twin: bare | decoy`.

- **bare**: puts a passthrough `plx-run` on `$GITHUB_PATH`, sets `PLX_TWIN=bare`.
- **decoy**: also generates RANDOM fake credentials at run time (right prefix and
  length) and lays them out the way real malware looks for them, so a CI-aware
  payload reveals itself:
  - env (via `$GITHUB_ENV`): `NPM_TOKEN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
    `PYPI_TOKEN`, `TWINE_PASSWORD`, `DOCKERHUB_TOKEN`, `CARGO_REGISTRY_TOKEN`, `PLX_TWIN=decoy`.
  - files: `~/.npmrc` (`_authToken` for a **fake internal** host, never a real registry),
    `~/.aws/credentials`, `~/.pypirc` (a non-default repository section).

`plx-run <cmd...>`:
- bare: `exec "$@"`.
- decoy: `exec` the command with `GITHUB_REF=refs/tags/v<x.y.z>`, `GITHUB_REF_NAME`,
  `GITHUB_REF_TYPE=tag`, `GITHUB_EVENT_NAME=release` overridden **for the child only**.

The action makes **zero network requests** in both modes and reads no real secret.
The fake tokens point only at non-existent `.invalid` hosts, so honest tools behave
exactly as on a clean project.

## Usage

```yaml
- uses: ToukoUrsin/parallax/dress@main
  with:
    twin: ${{ matrix.twin }}   # bare | decoy
- run: plx-run npm ci
```

## Proof it is inert on a clean project

`/bulk3/runs/craci/build-side/dress-proof.sh` runs `npm ci && npm test && npm run
build` on the demo app once plain and once dressed (decoy), simulating
`$GITHUB_ENV`/`$GITHUB_PATH` with temp files; both succeed identically.
