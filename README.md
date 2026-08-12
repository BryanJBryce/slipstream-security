# Slipstream deployment security

Slipstream runs several applications behind one Caddy process. All production
traffic switches use the root-owned `slipstream-caddy` contract so a deployer
cannot replace the root Caddyfile or another application's route.

## Contract

- The registry at `/etc/slipstream-caddy/apps.json` maps each app to one exact
  site file, one exact upstream include, and an allowlist of slot ports.
- Every mutation takes `/run/lock/slipstream-caddy.lock` before reading or
  writing Caddy state.
- Caddy's admin API listens on `/run/caddy/admin.sock` inside a systemd-managed
  runtime directory inaccessible to deploy users; the
  loopback TCP admin endpoint is disabled so application processes cannot load
  runtime configuration behind the file-backed source of truth.
- The helper writes only `/etc/caddy/upstreams/<app>.caddy`, validates the full
  root Caddyfile, reloads Caddy, verifies the runtime upstream, and verifies the
  target health and deployment identity when the app exposes it.
- A failed switch restores only that app's previous include and verifies the
  recovered runtime route before releasing the lock.
- Transaction receipts and mode-600 recovery copies live under
  `/var/lib/slipstream-caddy`.
- Site policy (domains, authentication, redirects, headers, and logging)
  remains root-owned outside application deployment repositories.

Application deployment scripts call only these forms:

```sh
sudo -n /usr/local/sbin/slipstream-caddy inspect APP --upstream
sudo -n /usr/local/sbin/slipstream-caddy switch APP SLOT \
  --expected-release FULL_GIT_SHA
sudo -n /usr/local/sbin/slipstream-caddy restore APP TRANSACTION_ID
```

`--expected-release` is mandatory for registry entries with a release identity
header and omitted for apps that do not expose one.

The `adapters/` directory contains the versioned callers for host-managed apps
that do not have their own deployment repository. Install those files at the
existing app-specific switch paths; they retain each app's marker convention
while delegating every Caddy read and write to this contract.

## Host installation

Install the Python helper as root-owned mode `755`, the registry as root-owned
mode `644`, and the sudoers fragment as root-owned mode `440`. Validate the
fragment with `visudo -cf` before installation. Create these directories as
root-owned and not writable by deploy users:

```text
/etc/slipstream-caddy
/etc/caddy/upstreams
/var/lib/slipstream-caddy/backups
/var/lib/slipstream-caddy/transactions
```

The root Caddyfile global options must include:

```caddy
admin unix//run/caddy/admin.sock
persist_config off
```

Install `systemd/caddy-admin-socket.conf` as the Caddy service override before
enabling the socket. Systemd then creates `/run/caddy` for the `caddy` service
user on every start instead of relying on a mutable, manually owned directory.

Replace the legacy `bryan-caddy-deploy`, `bryce-labs-web-bluegreen`, and
`mentat-deploy` sudoers fragments with the same-named files in `sudoers/`.
Those replacements remove direct Caddy, root-copy, and root-mkdir permissions;
application deployers retain only their service controls plus the shared
contract commands in `sudoers/slipstream-caddy`.

Run `migrate APP SLOT` once per registered app, supplying an expected release
for apps that expose release identity. Migration preserves the current site,
replaces only its managed reverse proxy with the app-specific import, validates
and reloads the complete Caddyfile, verifies the public target, and restores the
site on failure. Before the admin socket exists, only `migrate` may use the
legacy loopback endpoint; `inspect`, `switch`, and `restore` fail closed. After
the socket is created, migration also uses the socket and the TCP fallback is
permanently disabled.

Run migration directly as root during installation. It is deliberately not a
deploy-user sudo command after the boundary is established. See
`docs/slipstream-switching-inventory.md` for the complete caller inventory and
the explicit non-switching exclusions.

## Validation

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile slipstream_caddy.py
python3 -m json.tool config/apps.json >/dev/null
bash -n adapters/*.sh
```
