#!/usr/bin/env python3
"""Locked, file-backed Caddy traffic switching for the Slipstream host."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable
import urllib.error
import urllib.request
import uuid


REGISTRY_PATH = Path("/etc/slipstream-caddy/apps.json")
LOCK_PATH = Path("/run/lock/slipstream-caddy.lock")
STATE_ROOT = Path("/var/lib/slipstream-caddy")
ADMIN_SOCKET = Path("/run/caddy-admin.sock")
UPSTREAM_PATTERN = re.compile(
    r"^\s*reverse_proxy\s+(?:https?://)?(?:127\.0\.0\.1|localhost):(\d+)\b"
)
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({})).open


class ContractError(RuntimeError):
    """The requested operation violates the switching contract."""


def fail(message: str) -> None:
    raise ContractError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        fail(f"could not read {path}: {exc}")


def strict_registry(path: Path) -> dict[str, Any]:
    try:
        stat = path.stat()
    except OSError as exc:
        fail(f"registry is unavailable at {path}: {exc}")

    if stat.st_uid != 0:
        fail(f"registry must be owned by root: {path}")
    if stat.st_mode & 0o022:
        fail(f"registry must not be group/world writable: {path}")

    try:
        registry = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"registry is invalid: {exc}")

    if registry.get("schema_version") != 1:
        fail("unsupported registry schema")
    if not isinstance(registry.get("apps"), dict):
        fail("registry apps must be an object")

    return registry


def app_config(registry: dict[str, Any], app_name: str) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", app_name):
        fail(f"invalid app name: {app_name}")

    try:
        app = registry["apps"][app_name]
    except KeyError:
        fail(f"app is not registered: {app_name}")

    required = ("site_file", "upstream_file", "canonical_host", "slots")
    missing = [key for key in required if key not in app]
    if missing:
        fail(f"registry entry {app_name} is missing: {', '.join(missing)}")

    site_file = Path(app["site_file"])
    upstream_file = Path(app["upstream_file"])
    expected_upstream = Path("/etc/caddy/upstreams") / f"{app_name}.caddy"

    if not site_file.is_absolute():
        fail(f"site file must be absolute for {app_name}")
    if upstream_file != expected_upstream:
        fail(f"upstream path is outside the app boundary for {app_name}")

    slots = app["slots"]
    if not isinstance(slots, dict) or not slots:
        fail(f"slots must be a non-empty object for {app_name}")
    ports = list(slots.values())
    if any(not isinstance(port, int) or not 1 <= port <= 65535 for port in ports):
        fail(f"registered ports are invalid for {app_name}")
    if len(set(ports)) != len(ports):
        fail(f"registered ports must be unique for {app_name}")

    return app


def target_for(app_name: str, app: dict[str, Any], slot: str) -> tuple[int, str]:
    slots = app["slots"]
    if slot not in slots:
        fail(f"slot is not registered for {app_name}: {slot}")
    return slots[slot], f"127.0.0.1:{slots[slot]}"


def upstream_text(app: dict[str, Any], port: int) -> bytes:
    template = app.get("upstream_template", "reverse_proxy 127.0.0.1:{port}\n")
    if not isinstance(template, str):
        fail("upstream template must be a string")
    if set(re.findall(r"{([^{}]+)}", template)) - {"port"}:
        fail("upstream template contains unsupported placeholders")

    rendered = template.format(port=port)
    matches = [
        int(match.group(1))
        for line in rendered.splitlines()
        if (match := UPSTREAM_PATTERN.match(line))
    ]
    if matches != [port]:
        fail("upstream template must render exactly one loopback reverse_proxy")
    return rendered.encode()


def upstream_from_bytes(data: bytes) -> str:
    matches = [
        int(match.group(1))
        for line in data.decode().splitlines()
        if (match := UPSTREAM_PATTERN.match(line))
    ]
    if len(matches) != 1:
        fail("managed upstream file must contain exactly one loopback reverse_proxy")
    return f"127.0.0.1:{matches[0]}"


def atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


def command_runner(command: list[str]) -> None:
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)


def validate_and_reload(run: Callable[[list[str]], None] = command_runner) -> None:
    run(["/usr/bin/caddy", "validate", "--config", "/etc/caddy/Caddyfile"])
    run(
        [
            "/usr/bin/caddy",
            "reload",
            "--config",
            "/etc/caddy/Caddyfile",
            "--address",
            f"unix/{ADMIN_SOCKET}",
        ]
    )


def bootstrap_validate_and_reload(
    run: Callable[[list[str]], None] = command_runner,
) -> None:
    """Reload through the legacy loopback endpoint during one-time migration."""
    if ADMIN_SOCKET.exists():
        fail("bootstrap reload is disabled after the admin socket exists")
    run(["/usr/bin/caddy", "validate", "--config", "/etc/caddy/Caddyfile"])
    run(
        [
            "/usr/bin/caddy",
            "reload",
            "--config",
            "/etc/caddy/Caddyfile",
            "--address",
            "127.0.0.1:2019",
        ]
    )


def response_headers(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    opener: Callable[..., Any] = DIRECT_OPENER,
) -> tuple[int, dict[str, str]]:
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        response = opener(request, timeout=10)
    except urllib.error.HTTPError as exc:
        response = exc
    except OSError as exc:
        fail(f"health request failed for {url}: {exc}")

    normalized = {name.lower(): value for name, value in response.headers.items()}
    return response.status, normalized


def expected_identity(
    app_name: str,
    app: dict[str, Any],
    slot: str,
    expected_release: str | None,
) -> dict[str, str]:
    identity = app.get("identity", {})
    if not isinstance(identity, dict):
        fail(f"identity must be an object for {app_name}")

    expected: dict[str, str] = {}
    if slot_header := identity.get("slot_header"):
        expected[str(slot_header).lower()] = slot

    release_header = identity.get("release_header")
    if release_header:
        if not expected_release or not SHA_PATTERN.fullmatch(expected_release):
            fail(f"{app_name} requires a full expected release SHA")
        expected[str(release_header).lower()] = expected_release
    elif expected_release is not None and not SHA_PATTERN.fullmatch(expected_release):
        fail("expected release must be a full lowercase Git SHA")

    return expected


def verify_endpoint(
    app_name: str,
    app: dict[str, Any],
    slot: str,
    port: int,
    expected_release: str | None,
    *,
    public: bool,
    opener: Callable[..., Any] = DIRECT_OPENER,
) -> None:
    health = app.get("health", {})
    if public and not health.get("public_verify", True):
        return

    expected = expected_identity(app_name, app, slot, expected_release)
    statuses = health.get("statuses", [200])
    if not isinstance(statuses, list) or any(not isinstance(value, int) for value in statuses):
        fail(f"health statuses are invalid for {app_name}")

    if public:
        url = health.get("public_url")
        headers: dict[str, str] = {}
        if not isinstance(url, str) or not url.startswith("https://"):
            fail(f"public health URL is invalid for {app_name}")
    else:
        path = health.get("path", "/healthz")
        if not isinstance(path, str) or not path.startswith("/"):
            fail(f"local health path is invalid for {app_name}")
        url = f"http://127.0.0.1:{port}{path}"
        headers = {
            "Host": app["canonical_host"],
            "X-Forwarded-Host": app["canonical_host"],
            "X-Forwarded-Proto": "https",
        }
        headers.update(health.get("local_headers", {}))

    status, actual_headers = response_headers(url, headers=headers, opener=opener)
    if status not in statuses:
        fail(f"{app_name} {'public' if public else 'local'} health returned {status}")

    for name, value in expected.items():
        if actual_headers.get(name) != value:
            fail(
                f"{app_name} {'public' if public else 'local'} identity mismatch "
                f"for {name}"
            )


def runtime_config() -> dict[str, Any]:
    try:
        result = subprocess.run(
            [
                "/usr/bin/curl",
                "--fail",
                "--silent",
                "--show-error",
                "--unix-socket",
                str(ADMIN_SOCKET),
                "http://localhost/config/",
            ],
            check=True,
            capture_output=True,
        )
        return json.loads(result.stdout)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        fail(f"could not inspect Caddy runtime configuration: {exc}")


def bootstrap_runtime_config() -> dict[str, Any]:
    if ADMIN_SOCKET.exists():
        fail("bootstrap admin access is disabled after the admin socket exists")
    try:
        with urllib.request.urlopen("http://127.0.0.1:2019/config/", timeout=10) as response:
            return json.load(response)
    except (OSError, ValueError) as exc:
        fail(f"could not inspect the bootstrap Caddy runtime configuration: {exc}")


def runtime_upstreams(
    canonical_host: str,
    *,
    load_config: Callable[[], dict[str, Any]] = runtime_config,
) -> list[str]:
    config = load_config()

    matches: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            dial = value.get("dial")
            if isinstance(dial, str):
                normalized = dial.replace("localhost:", "127.0.0.1:", 1)
                matches.append(normalized)
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    servers = config.get("apps", {}).get("http", {}).get("servers", {})
    for server in servers.values():
        for route in server.get("routes", []):
            route_hosts = {
                host
                for matcher in route.get("match", [])
                for host in matcher.get("host", [])
            }
            if canonical_host in route_hosts:
                collect(route.get("handle", []))

    return sorted(set(matches))


def verify_runtime(
    app_name: str,
    app: dict[str, Any],
    expected_upstream: str,
    *,
    load_config: Callable[[], dict[str, Any]] = runtime_config,
) -> None:
    actual = runtime_upstreams(app["canonical_host"], load_config=load_config)
    if actual != [expected_upstream]:
        fail(f"{app_name} runtime upstream mismatch: {actual}")


def find_host_block(lines: list[str], canonical_host: str) -> tuple[int, int]:
    candidates: list[tuple[int, int]] = []
    for start, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.endswith("{"):
            continue
        labels = [value for value in re.split(r"[,\s]+", stripped[:-1].strip()) if value]
        if canonical_host not in labels:
            continue

        depth = line.count("{") - line.count("}")
        for end in range(start + 1, len(lines)):
            depth += lines[end].count("{") - lines[end].count("}")
            if depth == 0:
                candidates.append((start, end))
                break

    if len(candidates) != 1:
        fail(f"expected one site block for {canonical_host}; found {len(candidates)}")
    return candidates[0]


def proxy_range(lines: list[str], block: tuple[int, int]) -> tuple[int, int]:
    start, end = block
    proxies: list[tuple[int, int]] = []
    for index in range(start + 1, end):
        if not UPSTREAM_PATTERN.match(lines[index]):
            continue
        proxy_end = index
        if "{" in lines[index]:
            depth = lines[index].count("{") - lines[index].count("}")
            while depth > 0 and proxy_end + 1 < end:
                proxy_end += 1
                depth += lines[proxy_end].count("{") - lines[proxy_end].count("}")
            if depth != 0:
                fail("reverse_proxy block is unbalanced")
        proxies.append((index, proxy_end))

    if len(proxies) != 1:
        fail(f"expected one reverse_proxy in managed site block; found {len(proxies)}")
    return proxies[0]


def migrated_site(app: dict[str, Any], current: bytes) -> bytes:
    text = current.decode()
    import_line = f"import {app['upstream_file']}"
    if import_line in text:
        return current

    for legacy_import in app.get("legacy_imports", []):
        if legacy_import in text:
            if text.count(legacy_import) != 1:
                fail("legacy import is ambiguous")
            return text.replace(legacy_import, import_line, 1).encode()

    lines = text.splitlines(keepends=True)
    block = find_host_block(lines, app["canonical_host"])
    proxy_start, proxy_end = proxy_range(lines, block)
    indent = lines[proxy_start][: len(lines[proxy_start]) - len(lines[proxy_start].lstrip())]
    replacement = f"{indent}{import_line}\n"
    return "".join(lines[:proxy_start] + [replacement] + lines[proxy_end + 1 :]).encode()


def verify_site_boundary(app_name: str, app: dict[str, Any]) -> None:
    site = read_bytes(Path(app["site_file"])).decode()
    import_line = f"import {app['upstream_file']}"
    if site.count(import_line) != 1:
        fail(f"{app_name} site must import exactly one app-owned upstream file")

    ports = set(app["slots"].values())
    direct = [
        int(match.group(1))
        for line in site.splitlines()
        if (match := UPSTREAM_PATTERN.match(line)) and int(match.group(1)) in ports
    ]
    if direct:
        fail(f"{app_name} site still contains direct managed upstreams: {direct}")


class HostLock:
    def __init__(self, path: Path = LOCK_PATH):
        self.path = path
        self.descriptor: int | None = None

    def __enter__(self) -> "HostLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self.descriptor, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_args: Any) -> None:
        assert self.descriptor is not None
        fcntl.flock(self.descriptor, fcntl.LOCK_UN)
        os.close(self.descriptor)


def receipt_path(app_name: str, transaction_id: str) -> Path:
    return STATE_ROOT / "transactions" / app_name / f"{transaction_id}.json"


def write_receipt(app_name: str, payload: dict[str, Any]) -> str:
    transaction_id = str(uuid.uuid4())
    payload = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "app": app_name,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **payload,
    }
    atomic_write(
        receipt_path(app_name, transaction_id),
        (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode(),
        mode=0o600,
    )
    return transaction_id


def backup_file(app_name: str, data: bytes) -> Path:
    backup_dir = STATE_ROOT / "backups" / app_name
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4()}.caddy"
    atomic_write(backup, data, mode=0o600)
    return backup


def perform_switch(
    app_name: str,
    app: dict[str, Any],
    slot: str,
    expected_release: str | None,
    *,
    reload_config: Callable[[], None] = validate_and_reload,
    opener: Callable[..., Any] = DIRECT_OPENER,
    load_config: Callable[[], dict[str, Any]] = runtime_config,
) -> str:
    port, target_upstream = target_for(app_name, app, slot)
    upstream_file = Path(app["upstream_file"])
    verify_site_boundary(app_name, app)
    verify_endpoint(app_name, app, slot, port, expected_release, public=False, opener=opener)

    before = read_bytes(upstream_file)
    previous_upstream = upstream_from_bytes(before)
    allowed = {f"127.0.0.1:{value}" for value in app["slots"].values()}
    if previous_upstream not in allowed:
        fail(f"existing upstream is outside the registered ports for {app_name}")

    after = upstream_text(app, port)
    backup = backup_file(app_name, before)
    atomic_write(upstream_file, after)

    try:
        reload_config()
        verify_runtime(app_name, app, target_upstream, load_config=load_config)
        verify_endpoint(app_name, app, slot, port, expected_release, public=True, opener=opener)
    except BaseException:
        atomic_write(upstream_file, before)
        try:
            reload_config()
            verify_runtime(app_name, app, previous_upstream, load_config=load_config)
        except BaseException as recovery_error:
            raise ContractError(
                f"{app_name} switch failed and recovery could not be verified: {recovery_error}"
            ) from recovery_error
        raise

    return write_receipt(
        app_name,
        {
            "kind": "switch",
            "slot": slot,
            "expected_release": expected_release,
            "previous_upstream": previous_upstream,
            "target_upstream": target_upstream,
            "before_sha256": digest(before),
            "after_sha256": digest(after),
            "backup_file": str(backup),
        },
    )


def perform_migration(
    app_name: str,
    app: dict[str, Any],
    slot: str,
    expected_release: str | None,
    *,
    reload_config: Callable[[], None] = validate_and_reload,
    opener: Callable[..., Any] = DIRECT_OPENER,
    load_config: Callable[[], dict[str, Any]] = runtime_config,
) -> str:
    port, target_upstream = target_for(app_name, app, slot)
    site_file = Path(app["site_file"])
    upstream_file = Path(app["upstream_file"])
    verify_endpoint(app_name, app, slot, port, expected_release, public=False, opener=opener)

    site_before = read_bytes(site_file)
    upstream_existed = upstream_file.exists()
    upstream_before = read_bytes(upstream_file) if upstream_existed else b""
    site_after = migrated_site(app, site_before)
    upstream_after = upstream_text(app, port)
    site_backup = backup_file(f"{app_name}-site", site_before)
    upstream_backup = backup_file(app_name, upstream_before) if upstream_existed else None

    atomic_write(upstream_file, upstream_after)
    atomic_write(site_file, site_after)

    try:
        verify_site_boundary(app_name, app)
        reload_config()
        verify_runtime(app_name, app, target_upstream, load_config=load_config)
        verify_endpoint(app_name, app, slot, port, expected_release, public=True, opener=opener)
    except BaseException:
        atomic_write(site_file, site_before)
        if upstream_existed:
            atomic_write(upstream_file, upstream_before)
        else:
            upstream_file.unlink(missing_ok=True)
        try:
            reload_config()
        except BaseException as recovery_error:
            raise ContractError(
                f"{app_name} migration failed and recovery reload failed: {recovery_error}"
            ) from recovery_error
        raise

    return write_receipt(
        app_name,
        {
            "kind": "migration",
            "slot": slot,
            "expected_release": expected_release,
            "target_upstream": target_upstream,
            "site_before_sha256": digest(site_before),
            "site_after_sha256": digest(site_after),
            "upstream_after_sha256": digest(upstream_after),
            "site_backup_file": str(site_backup),
            "upstream_backup_file": str(upstream_backup) if upstream_backup else None,
        },
    )


def perform_restore(
    app_name: str,
    app: dict[str, Any],
    transaction_id: str,
    *,
    reload_config: Callable[[], None] = validate_and_reload,
    load_config: Callable[[], dict[str, Any]] = runtime_config,
) -> str:
    path = receipt_path(app_name, transaction_id)
    try:
        receipt = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"transaction receipt is unavailable: {exc}")

    if receipt.get("app") != app_name or receipt.get("kind") != "switch":
        fail("only a matching switch transaction can be restored")

    upstream_file = Path(app["upstream_file"])
    current = read_bytes(upstream_file)
    if digest(current) != receipt.get("after_sha256"):
        fail("managed upstream changed after this transaction; refusing stale restore")

    backup = Path(receipt["backup_file"])
    before = read_bytes(backup)
    if digest(before) != receipt.get("before_sha256"):
        fail("transaction backup checksum mismatch")

    previous_upstream = receipt["previous_upstream"]
    atomic_write(upstream_file, before)
    try:
        reload_config()
        verify_runtime(app_name, app, previous_upstream, load_config=load_config)
    except BaseException:
        atomic_write(upstream_file, current)
        reload_config()
        raise

    return write_receipt(
        app_name,
        {
            "kind": "restore",
            "restored_transaction_id": transaction_id,
            "target_upstream": previous_upstream,
            "before_sha256": digest(current),
            "after_sha256": digest(before),
        },
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("app")
    inspect_parser.add_argument("--upstream", action="store_true")

    for name in ("switch", "migrate"):
        operation = subparsers.add_parser(name)
        operation.add_argument("app")
        operation.add_argument("slot")
        operation.add_argument("--expected-release")

    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("app")
    restore_parser.add_argument("transaction_id")
    return result


def main(argv: list[str] | None = None) -> int:
    if os.geteuid() != 0:
        print("slipstream-caddy must run as root", file=sys.stderr)
        return 77

    args = parser().parse_args(argv)
    try:
        registry = strict_registry(REGISTRY_PATH)
        app = app_config(registry, args.app)
        with HostLock():
            if args.command == "inspect":
                verify_site_boundary(args.app, app)
                file_upstream = upstream_from_bytes(read_bytes(Path(app["upstream_file"])))
                runtime = runtime_upstreams(app["canonical_host"])
                if args.upstream:
                    print(file_upstream)
                else:
                    print(
                        json.dumps(
                            {
                                "app": args.app,
                                "file_upstream": file_upstream,
                                "runtime_upstreams": runtime,
                                "consistent": runtime == [file_upstream],
                            },
                            sort_keys=True,
                        )
                    )
                return 0 if runtime == [file_upstream] else 1
            if args.command == "switch":
                print(perform_switch(args.app, app, args.slot, args.expected_release))
                return 0
            if args.command == "migrate":
                if ADMIN_SOCKET.exists():
                    transaction = perform_migration(
                        args.app, app, args.slot, args.expected_release
                    )
                else:
                    transaction = perform_migration(
                        args.app,
                        app,
                        args.slot,
                        args.expected_release,
                        reload_config=bootstrap_validate_and_reload,
                        load_config=bootstrap_runtime_config,
                    )
                print(transaction)
                return 0
            if args.command == "restore":
                print(perform_restore(args.app, app, args.transaction_id))
                return 0
    except (ContractError, subprocess.CalledProcessError) as exc:
        print(f"slipstream-caddy: {exc}", file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
