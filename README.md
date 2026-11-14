# Shipshape

Find the Kubernetes API versions in your manifests that stop being served
between the release you run and the release you are upgrading to. Run it
locally, or as a GitHub Action that fails a pull request on blockers.

No dependencies beyond the Go standard library. Nothing leaves your machine.

## GitHub Action

```yaml
# .github/workflows/shipshape.yml
name: Upgrade readiness
on: [pull_request]
jobs:
  shipshape:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: 20041540MichaelKelly/shipshape@v1
        with:
          current: "1.24"
          target: "1.33"
          paths: |
            k8s
            deploy/rendered.yaml
```

Findings appear as annotations on the changed files, and a full report is
written to the job summary. The job fails when any resource would stop
working at the target version.

| Input | Default | Meaning |
|---|---|---|
| `current` | required | Version the cluster runs now |
| `target` | required | Version you are upgrading to |
| `paths` | `.` | Files or directories, one per line |
| `fail-on` | `blocker` | `blocker`, `deprecated` or `none` |

| `pr-comment` | `false` | Post the report as one pull request comment (Team plan) |
| `team-token` | empty | Team token, from a repository secret |

The action runs in Docker, so it needs a Linux runner.

### Team plan

```yaml
permissions:
  contents: read
  pull-requests: write
steps:
  - uses: actions/checkout@v4
  - uses: 20041540MichaelKelly/shipshape@v1
    with:
      current: "1.24"
      target: "1.33"
      pr-comment: true
      team-token: ${{ secrets.SHIPSHAPE_TOKEN }}
```

Team adds one pull request comment that is edited in place on every push, and
`--format sarif` for GitHub code scanning. If the licence server cannot be
reached the check still runs; only the comment is skipped.

## Command line

```sh
go install github.com/20041540MichaelKelly/shipshape/cmd/shipshape@latest

shipshape --current 1.24 --target 1.33 ./k8s
helm template ./chart | shipshape --current 1.24 --target 1.33 -
shipshape --current 1.24 --target 1.33 --format markdown ./k8s > report.md
shipshape --current 1.24 --target 1.33 --fix ./k8s
```

`--fix` rewrites a file only where the apiVersion line is the single change
needed. Anything with renamed fields or changed behaviour is reported and
left alone.

Exit codes: `0` ready, `1` findings at or above `--fail-on`, `2` usage or
read error.

## What it checks

Every core API removal in the official
[Deprecated API Migration Guide](https://kubernetes.io/docs/reference/using-api/deprecation-guide/),
from v1.16 through v1.32, plus the `v1` Endpoints and ComponentStatus
deprecations. When no single API version spans the upgrade (FlowSchema from
1.24 to 1.33, for example) it lists the steps to take.

Not checked yet: custom resources from operators such as cert-manager, Istio
and Argo, and live clusters.

Helm charts must be rendered with `helm template` first. Resources whose
apiVersion still contains `{{ }}` are counted as skipped.

## Repository layout

| Path | What it is |
|---|---|
| `web/index.html` | The website and free in-browser checker. One static file. |
| `cmd/shipshape` | The CLI, also the GitHub Action entry point. |
| `cmd/shipshape-server` | Licence server: Stripe webhook, Team tokens, signed licences. |
| `internal/check` | Parser, rules and reports. |
| `internal/license` | Signing and verifying licences. |
| `internal/server` | HTTP handlers and the account store. |
| `internal/ghcomment` | Pull request comment. |
| `Dockerfile`, `action.yml` | The GitHub Action. |
| `server.Dockerfile`, `fly.toml` | Licence server deployment. |
| `web/_headers` | Security headers for the site on Cloudflare Pages. |

## Running the paid plan (for the maintainer)

```sh
# 1. Create the signing keys. Commit the public key, keep the private one secret.
go run ./cmd/shipshape-server keygen
#    Paste the public key into PublicKey, and your server URL into
#    DefaultServer, in internal/license/license.go.

# 2. Run the server locally.
export STRIPE_WEBHOOK_SECRET=whsec_...   # from the Stripe webhook endpoint
export SHIPSHAPE_PRIVATE_KEY=...         # from keygen
export DATA_FILE=./accounts.json
go run ./cmd/shipshape-server

# 3. Deploy it (Fly.io shown; any host that runs a container works).
fly launch --no-deploy --copy-config
fly volumes create shipshape_data --size 1 --region lhr
fly secrets set STRIPE_WEBHOOK_SECRET=whsec_... SHIPSHAPE_PRIVATE_KEY=...
fly deploy
```

In Stripe: create a recurring price, a Payment Link for it that redirects to
`https://<your-server>/claim?session_id={CHECKOUT_SESSION_ID}` after payment,
and a webhook endpoint at `https://<your-server>/stripe/webhook` listening for
`checkout.session.completed`, `customer.subscription.updated` and
`customer.subscription.deleted`. Put the Payment Link in `SITE.teamCheckoutUrl`
in `web/index.html`.

## Security

See [SECURITY.md](SECURITY.md) for how untrusted pull request content, tokens
and licences are handled, and how to report a problem.

## Development

```sh
go test ./...
go build ./cmd/shipshape
```

Rules live in `internal/check/rules.go`. Add a `Rule` when a new Kubernetes
release removes an API.
