# Python `.pth` specimen (LiteLLM style) — how it would be packaged and served

Incident: LiteLLM (24 Mar 2026). A wheel ships a `.pth` file; Python executes any
`.pth` line starting with `import ` at interpreter start, so the payload fires
before any app code, even if the package is never imported. Same twin-diff catch
as the npm specimens: the decoy twin (fake cloud keys) beacons, the bare twin does not.

Package (`nbd-pth-probe`), one fake specimen under our own name:
- `pyproject.toml` (setuptools). The payload is a module, e.g. `nbd_pth_probe/_plx.py`,
  mirroring `_shared/payload.js`: check a trigger only, then one GET `/stage2/pth`
  and one POST `/collect` `{"specimen":"pth","run":<GITHUB_RUN_ID|local>}`, 3 s
  timeout, errors swallowed, once per process + marker file in the temp dir.
- Trigger (pth): cloud keys present, e.g. `AWS_ACCESS_KEY_ID` set or `~/.aws/credentials`
  exists. Checks existence only; never reads the value.
- The `.pth`: a single line `import nbd_pth_probe._plx` installed into site-packages
  (declared so the build backend writes it next to the package). That line is what
  makes it fire at interpreter start, like LiteLLM.
- README/description: "Parallax specimen: harmless simulation of LiteLLM .pth".

Serve from the sink as a minimal PEP 503 "simple" index (add to `server.ts`):
- `GET /pypi/simple/` → anchor list; `GET /pypi/simple/nbd-pth-probe/` → one anchor
  per wheel/sdist file with `href=".../packages/<file>#sha256=<hash>"`.
- `GET /pypi/packages/<file>` → the artifact bytes. `build.cjs` runs `python -m build`
  per specimen into `registry/pypi/packages/` and records sha256, same pattern as npm pack.
- Fleet repo (`fleet/api`) `pip.conf`/`PIP_EXTRA_INDEX_URL` points `nbd-*` at the sink;
  CRACI network policy adds a `pypi` source URL for the sink. Clean version has no `.pth`.
