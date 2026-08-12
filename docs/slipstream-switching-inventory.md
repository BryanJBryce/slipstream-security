# Slipstream Caddy switching inventory

This inventory records every deployment that changes an upstream on the
shared Slipstream host as of 2026-08-12. All listed routes are registered in
`config/apps.json`, import one root-owned file under `/etc/caddy/upstreams/`,
and switch only through `/usr/local/sbin/slipstream-caddy`.

| Contract app | Deployment owner | Registered slots |
| --- | --- | --- |
| `ash-creek` | `BryceLabs/ash-creek` review deployment | blue `5331`, green `5332` |
| `bestbale` | `BryceLabs/bestbale-web` | blue `4102`, green `4103` |
| `bryce-labs-web` | `BryceLabs/bryce-labs-web` | blue `4220`, green `4221` |
| `dannys` | versioned host adapter in this repository | blue `4120`, green `4121` |
| `imm-web` | `BryceLabs/imm` monorepo | blue `4131`, green `4132` |
| `key-to-the-town-web` | `BryceLabs/key-to-the-town-web` | blue `4500`, green `4501` |
| `kinship` | `BryceLabs/kinship` | blue `4140`, green `4141` |
| `leads` | versioned host adapter in this repository | red `4560`, green `4561` |
| `mentat` | `BryceLabs/mentat` | blue `4555`, green `4556` |
| `pima` | file-backed host route; no current switch caller | blue `4122`, green `4123` |

The retired `BryceLabs/imm-web` duplicate workflow is intentionally disabled;
only the IMM monorepo may deploy the shared IMM route.

`plus.brycelabs.com` and `tiptap.brycelabs.com` are single-slot development
services on Slipstream and do not mutate Caddy during deployment. Their
blue/green production workflows target separate hosts. Static sites and fixed
reverse proxies likewise have no switching caller and remain root-owned Caddy
policy outside this contract.

The one-time `migrate` command is intentionally absent from deploy-user
sudoers after host reconciliation. It is a root-only installation operation;
ongoing callers receive only `inspect`, `switch`, and transaction-bound
`restore` access.
