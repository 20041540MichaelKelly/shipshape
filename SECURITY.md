# Security

## Reporting a problem

Email SECURITY-CONTACT@YOUR-DOMAIN with details and steps to reproduce.
Please do not open a public issue for a vulnerability. You will get a reply
within three working days.

## How Shipshape is built to be safe

**Website.** The checker runs entirely in the browser. The site is served
with a Content-Security-Policy whose `connect-src 'none'` makes the browser
block any network request from the page, so manifests cannot leave it.

**CLI and GitHub Action.** Files in a pull request are treated as untrusted:

- Symlinks are not followed, so a scan or `--fix` cannot read or write
  outside the repository.
- Files over 10 MB and file names with control characters are skipped.
- Text taken from manifests is escaped before it reaches workflow
  annotations, pull request comments or the job summary, and the plain
  report is fenced with `stop-commands`, so a crafted manifest cannot issue
  workflow commands, break the report or mention users.
- The Team token is only ever sent over HTTPS.
- A licence problem or an unreachable licence server never changes the
  result of the check.
- There are no third-party dependencies.

**Licence server.**

- Stripe events are accepted only with a valid signature inside a
  five-minute window.
- Team tokens are 192 random bits. Only their SHA-256 hash is kept once the
  24-hour claim window has passed.
- Licences are signed with Ed25519 and expire after 24 hours.
- `/v1/license` and `/claim` are rate limited per client address.
- The accounts file is written atomically with owner-only permissions.

## Keeping it up to date

- CI runs `govulncheck` on every push and once a week.
- Dependabot opens pull requests for new base images and Actions.
- Build with a supported Go release. When Go ships a security release,
  re-run the deploy so the server and the Action image pick it up.

## What the maintainer must protect

- `SHIPSHAPE_PRIVATE_KEY`: anyone holding it can mint licences. Keep it only
  in the host's secret store. To rotate, run `keygen`, set the new private
  key on the server and release a CLI with the new public key.
- `STRIPE_WEBHOOK_SECRET`: rotate it from the Stripe dashboard.
- `accounts.json`: holds customer email addresses, which are personal data
  under GDPR. Back it up encrypted and do not copy it to a laptop.
