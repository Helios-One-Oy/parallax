#!/usr/bin/env bash
# Parallax dress. Prepares a build twin.
#   bare  : put a passthrough plx-run on PATH, set PLX_TWIN=bare.
#   decoy : also generate RANDOM fake credentials (right prefix + length), export
#           them as the env vars and files real malware greps for, and set
#           PLX_TWIN=decoy so plx-run adds a release-looking GITHUB_* context.
#
# This script makes ZERO network requests in both modes. It reads no real secret.
# The fake credentials are random junk, generated here, never committed. The fake
# npm/pypi tokens point only at non-existent internal hosts, never at a real
# registry, so honest tools behave exactly as they do on a clean project.
#
# No `pipefail`: the random generators pipe /dev/urandom into `head`, which closes
# the pipe early (SIGPIPE upstream); with pipefail that non-zero status plus
# `set -e` would abort the decoy branch.
set -eu

TWIN="${1:-bare}"
ACTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# plx-run goes in a dir we control, added to PATH for later steps.
BINDIR="${RUNNER_TEMP:-/tmp}/plx-bin"
mkdir -p "$BINDIR"
cp "$ACTION_DIR/plx-run" "$BINDIR/plx-run"
chmod +x "$BINDIR/plx-run"
echo "$BINDIR" >> "$GITHUB_PATH"

if [ "$TWIN" != "decoy" ]; then
  echo "PLX_TWIN=bare" >> "$GITHUB_ENV"
  echo "parallax: bare twin. No dressing."
  exit 0
fi

# ---------------- decoy twin ----------------
# random alphanumeric string of length $1
rnd() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1"; }
# random base64url-ish string of length $1
rnd_b64() { LC_ALL=C tr -dc 'A-Za-z0-9_-' < /dev/urandom | head -c "$1"; }

NPM_TOKEN="npm_$(rnd 36)"
AWS_ACCESS_KEY_ID="AKIA$(LC_ALL=C tr -dc 'A-Z0-9' < /dev/urandom | head -c 16)"
AWS_SECRET_ACCESS_KEY="$(LC_ALL=C tr -dc 'A-Za-z0-9+/' < /dev/urandom | head -c 40)"
PYPI_TOKEN="pypi-$(rnd_b64 120)"
DOCKERHUB_TOKEN="dckr_pat_$(rnd 27)"
CARGO_REGISTRY_TOKEN="$(rnd_b64 44)"

# A fake internal registry host. NOT registry.npmjs.org, NOT our sink: no package
# is scoped to it, so npm never contacts it and never sends this token anywhere.
FAKE_NPM_HOST="npm.internal.northbound.invalid"
FAKE_PYPI_URL="https://pypi.internal.northbound.invalid/legacy/"

# Export the names malware greps for (persist to later steps via $GITHUB_ENV).
{
  echo "PLX_TWIN=decoy"
  echo "NPM_TOKEN=${NPM_TOKEN}"
  echo "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}"
  echo "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}"
  echo "PYPI_TOKEN=${PYPI_TOKEN}"
  echo "TWINE_PASSWORD=${PYPI_TOKEN}"
  echo "DOCKERHUB_TOKEN=${DOCKERHUB_TOKEN}"
  echo "CARGO_REGISTRY_TOKEN=${CARGO_REGISTRY_TOKEN}"
} >> "$GITHUB_ENV"

# Write the files malware reads. Append so we never clobber real tool config.
# .npmrc: an _authToken line for the FAKE host only.
printf '//%s/:_authToken=%s\n' "$FAKE_NPM_HOST" "$NPM_TOKEN" >> "$HOME/.npmrc"

# .aws/credentials: a [default] profile with fake keys.
mkdir -p "$HOME/.aws"
{
  echo "[default]"
  echo "aws_access_key_id = ${AWS_ACCESS_KEY_ID}"
  echo "aws_secret_access_key = ${AWS_SECRET_ACCESS_KEY}"
} >> "$HOME/.aws/credentials"

# .pypirc: a NON-default repository section (not [pypi]), so twine against real
# PyPI is unaffected.
cat >> "$HOME/.pypirc" <<EOF
[distutils]
index-servers =
    northbound-internal

[northbound-internal]
repository = ${FAKE_PYPI_URL}
username = __token__
password = ${PYPI_TOKEN}
EOF

echo "parallax: decoy twin dressed. Fake release credentials in place; plx-run will add a release-looking GITHUB_* context."
