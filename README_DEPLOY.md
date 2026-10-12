# Leadership Artery Institute - Online deployment 1.1

## Status and important boundaries

This package is prepared for deployment; it does NOT create a live URL by itself.
No hosting account, domain, DNS, payment method, or institute production data has
been accessed or changed. All test data is synthetic and stored outside this package.

Keep your original local folder and make an application backup before migration.
Do not open the original local app.py port to the public internet. The online entry
point is wsgi:application behind Gunicorn and an HTTPS reverse proxy.

## Choose a deployment route

A. A Linux VPS, including a server in the region approved by the institute:
use Docker Compose and Caddy. Do not run this stack alongside an existing web
server on ports 80/443 without a system administrator integrating its proxy.

B. Render with a PAID Python web service and a persistent disk:
use render.yaml. The included example is Frankfurt (Germany), not Saudi Arabia.
Review data-location, confidentiality and vendor requirements BEFORE real data is
uploaded. Selecting a service in a country is not, by itself, a compliance review.

This is a Python server application, not a static HTML site. A general website
file manager or a static-site host alone is not sufficient. On an existing host,
confirm Python 3.10+, a persistent writable data directory, a SINGLE long-running
WSGI process, and correct reverse-proxy/HTTPS support. The included turnkey server
configuration is Linux Docker Compose, not a generic cPanel integration.

## A - VPS + the institute's subdomain

Prerequisites: a Linux VPS with Docker Engine and the Docker Compose plugin,
permission to add a DNS record, and access to server firewall rules. Suggested
starting capacity (not load-tested): 1 CPU, 2 GB RAM and at least 10 GB persistent
storage; actual needs depend on files and record volume.

1. Unzip this package into a NEW application folder on the server.
2. Add an A record such as admin.lai.edu.sa pointing to the server's IPv4 address.
   Do NOT change the main website's @ or www records. Configure/remove an AAAA
   record if it does not point to this same server over working IPv6.
3. Permit inbound TCP 80 and 443. Restrict administrative SSH access. Do not expose
   port 10000 or a database port. Ensure no other service occupies 80 or 443.
4. Run in the package folder:

```sh
python3 configure.py
docker compose up -d --build
docker compose ps
docker compose logs --tail 100 app caddy
```

configure.py prompts for the system subdomain and certificate-notification email.
It generates .env locally with a random first-run setup secret. It does not buy a
server, change DNS, transmit your secret, or contact your domain provider.

5. Wait until the app health check is healthy and Caddy has obtained its certificate.
   Open the HTTPS system URL. Copy LAI_SETUP_TOKEN from the server's private .env
   into the first-run form, then choose the administrator username and a password
   of at least 12 characters. Do not paste the setup token in a URL or a chat.
6. Leave illustrative examples unchecked for production. Add employee accounts
   from Team / HR. Each employee changes the temporary password at first use.
7. After setup, the setup endpoint cannot create a second administrator account.
   New administrators must be created through an existing authorized account.

The app container runs as an unprivileged user. A one-time permissions container
initializes the data volume. The application port is NOT published; Caddy is its
public entry point. The database is held in the lai_data Docker volume.

Do not run `docker compose down -v`: the -v option deletes the database volume.
Regular stop/start/rebuild does not require deleting volumes.

## B - Render

1. Create a PRIVATE Git repository and upload the source files (including hidden
   ignore files). Do not upload .env, databases, backups, real customer records or
   private keys. Keep render.yaml at the repository root, not one folder below it.
2. Connect that repository in Render and create a new Blueprint from render.yaml.
3. Review the PAID compute plan and disk cost before approving. The current example
   uses plan ID 0.5c-512mb, one instance and a 10 GB persistent disk. Upgrade memory
   for larger backups or file-heavy use after measurements. This is not a free or
   unlimited hosted service.
4. Check that the persistent disk mount AND LAI_DATA_DIR are both exactly:
   /opt/render/project/src/data
5. The app uses RENDER_EXTERNAL_URL automatically. No custom domain is required
   for the first deployment. Find the generated LAI_SETUP_TOKEN in the service's
   Environment settings. Keep it secret and use it in the first-run form.
6. To add the institute's subdomain later, add it in the Render service's custom
   domains, follow the DNS record Render provides, and set:
   LAI_PUBLIC_URL=https://admin.lai.edu.sa
   Redeploy. Both the configured institute origin and the provider origin will be
   accepted until the provider origin is disabled at the platform.
7. Auto-deploys are off in this manifest. Take a backup and deploy deliberately.

Render services have ephemeral filesystems unless a persistent disk is attached.
Do not remove the disk or select free ephemeral hosting for live records. The disk
requires a paid compatible service. The app is single-instance; do not add replicas.
The template is provided, not remotely deployed or API-validated in this session.

## Migration of existing local data

1. In the LOCAL system, stop staff edits, sign in as administrator, and use Settings
   > Download complete backup. Preserve this untouched .sqlite file privately.
2. Set up the ONLINE administrator with the setup token, without example data.
3. In the ONLINE system, choose Settings > Restore backup. Select the local .sqlite
   snapshot, enter the CURRENT online administrator password and confirm replacement.
4. All current online data is replaced. Existing online sessions are invalidated.
   Sign in using an account and password FROM THE RESTORED LOCAL SNAPSHOT.
5. Compare users, open tasks, departments, groups, balances and a sample attachment.
   Have an employee confirm their permissions before announcing the system URL.
6. From this point, use the online system only. The old local copy does not sync
   automatically, and restoring a backup merges nothing: it replaces the database.

The web restore limit in this online build is 32 MiB. Attachments remain limited
to 8 MiB each. Larger snapshots require a maintenance-window server-side restore.
For a larger trusted file on the Docker stack, run the following as its operator:

```sh
# Before stopping, download and verify a backup of the current ONLINE database.
docker compose stop caddy app
# backup.sqlite must be a complete, trusted application backup.
docker compose run --rm --no-deps -v "$PWD/backup.sqlite:/restore/source.sqlite:ro" app \
  python restore_offline.py /restore/source.sqlite --confirm-replace
docker compose up -d app caddy
```

The offline tool validates schema/integrity, makes a pre-restore snapshot and uses
an exclusive application-process lock. It must NOT be run while the app is live.
On Render, use the in-app restore for small files; larger maintenance restores
need the hosting operator to stop application access and use the provider's
supported file-transfer/maintenance procedure. Do not replace a live SQLite file.

## Backup and operations

- Database files are not encrypted by this application. Require appropriate host
  storage encryption and protect exported snapshots; they contain personal data,
  password hashes and attachments. HTTPS protects transport, not a stolen backup.
- The running application checks hourly and creates one snapshot for the day when
  users exist and no such snapshot exists. It retains 14 automatic daily snapshots.
  They remain on the same disk: arrange a separate, access-controlled encrypted
  off-server backup. Off-server backup is NOT configured by this package.
- Manual and pre-restore backups are not automatically pruned. Monitor disk usage.
- Sessions are kept in process memory and expire after eight hours. A worker restart
  logs everyone out; records remain on the persistent disk.
- Dashboards refresh every 15 seconds while visible and no editor dialog is open.
  This is polling, not WebSocket-based instantaneous delivery. No offline edits.
- Use one process and one instance. The server rejects a second active process
  using the same data directory. Do not enable SQLite WAL without redesigning the
  snapshot-replacement operation. Do not put the database on a network share.
- For high traffic or multi-instance availability, migrate the data model to a
  managed database and shared sessions, then retest. This build has not been
  validated for high load, high availability or disaster recovery objectives.
- Public trainer self-signup is OFF. Create trainers through the administrator.
  Set LAI_TRAINER_SIGNUP=1 and restart only when public pending-account requests
  are actually needed; administrator activation remains required.
- MFA, SSO, forgotten-password email, email/WhatsApp delivery, malware scanning
  of attachments and a separate offsite backup service are not implemented.
  Consider an organization-approved access gateway before exposing sensitive data.
- HTTP is rejected in production. LAI_ALLOW_LOCAL_HTTP=1 is for loopback tests only.
  Trust forwarded protocol headers ONLY behind a proxy that overwrites them and
  blocks direct public access to Gunicorn. This is how compose.yaml is configured.
  Do not set LAI_CLIENT_IP_HEADER unless using the included Caddy header overwrite.
- Restrict hosting, DNS and backup access. Keep runtime images/packages updated.
  No guarantee of complete security or legal compliance is implied by tests.

## Troubleshooting

403 on the URL: check LAI_PUBLIC_URL exactly matches the HTTPS origin, without a
path. Do not work around it by allowing arbitrary Host or Origin headers.
426: the proxy must send X-Forwarded-Proto=https and prevent direct backend access.
503: inspect logs for missing setup secret, data permission, or a second process.
Login after restart: expected; log in again. Do not recreate the database.
Certificate failure: verify A/AAAA records and public ports 80/443.
No employee records: confirm account role, department, ownership and activation.

## Tests

```sh
python3 tests/test_local_regression.py
python3 tests/test_online.py
```

See QA_REPORT.md for what was actually executed and what was not. Application
tests do not replace a production smoke test on the chosen host.

## Primary documentation checked for this package

- Python http.server production warning: https://docs.python.org/3/library/http.server.html
- Gunicorn deployment: https://gunicorn.org/deploy/
- Gunicorn settings: https://gunicorn.org/reference/settings/
- Pinned release: https://pypi.org/project/gunicorn/26.2.0/
- Caddy HTTPS proxy: https://caddyserver.com/docs/quick-starts/reverse-proxy
- Render disks: https://render.com/docs/disks
- Render manifest specification: https://render.com/docs/blueprint-spec
- Render environment: https://render.com/docs/environment-variables

Hosting plans, runtime versions and provider interfaces can change. Review the
provider dashboard and its current terms before authorizing a paid deployment.
