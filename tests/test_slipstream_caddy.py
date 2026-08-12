import json
from pathlib import Path
import tempfile
import unittest

import slipstream_caddy as contract


class SiteMigrationTest(unittest.TestCase):
    def app(self, site_file: str = "/etc/caddy/sites/example.caddy"):
        return {
            "canonical_host": "example.test",
            "site_file": site_file,
            "upstream_file": "/etc/caddy/upstreams/example.caddy",
            "slots": {"blue": 4100, "green": 4101},
        }

    def test_replaces_only_reverse_proxy_in_owned_host_block(self):
        current = b"""other.test {
  reverse_proxy 127.0.0.1:4100
}

example.test, alias.example.test {
  encode gzip
  reverse_proxy 127.0.0.1:4100 {
    health_uri /healthz
  }
  header X-Test yes
}
"""

        migrated = contract.migrated_site(self.app(), current).decode()

        self.assertIn("other.test {\n  reverse_proxy 127.0.0.1:4100", migrated)
        self.assertIn("  import /etc/caddy/upstreams/example.caddy", migrated)
        self.assertNotIn("health_uri /healthz", migrated)
        self.assertIn("header X-Test yes", migrated)

    def test_replaces_registered_legacy_import(self):
        app = self.app()
        app["legacy_imports"] = ["import /old/upstream.caddy"]
        current = b"example.test {\n  import /old/upstream.caddy\n}\n"

        migrated = contract.migrated_site(app, current).decode()

        self.assertEqual(
            migrated,
            "example.test {\n  import /etc/caddy/upstreams/example.caddy\n}\n",
        )

    def test_rejects_ambiguous_host_blocks(self):
        current = b"example.test {\n reverse_proxy 127.0.0.1:4100\n}\n" * 2
        with self.assertRaises(contract.ContractError):
            contract.migrated_site(self.app(), current)


class BoundaryTest(unittest.TestCase):
    def test_registry_cannot_map_app_to_another_file(self):
        registry = {
            "apps": {
                "one": {
                    "canonical_host": "one.test",
                    "site_file": "/etc/caddy/sites/one.caddy",
                    "upstream_file": "/etc/caddy/upstreams/two.caddy",
                    "slots": {"blue": 4100},
                }
            }
        }
        with self.assertRaises(contract.ContractError):
            contract.app_config(registry, "one")

    def test_unregistered_slot_is_rejected(self):
        app = {"slots": {"blue": 4100}}
        with self.assertRaises(contract.ContractError):
            contract.target_for("one", app, "green")

    def test_template_must_render_one_registered_loopback(self):
        app = {
            "upstream_template": (
                "reverse_proxy 127.0.0.1:{port}\n"
                "reverse_proxy 127.0.0.1:{port}\n"
            )
        }
        with self.assertRaises(contract.ContractError):
            contract.upstream_text(app, 4100)


class RestoreTest(unittest.TestCase):
    def test_stale_transaction_cannot_overwrite_newer_switch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            upstream = root / "upstream.caddy"
            backup = root / "backup.caddy"
            receipt = root / "receipt.json"
            before = b"reverse_proxy 127.0.0.1:4100\n"
            after = b"reverse_proxy 127.0.0.1:4101\n"
            newer = b"reverse_proxy 127.0.0.1:4102\n"
            upstream.write_bytes(newer)
            backup.write_bytes(before)
            receipt.write_text(
                json.dumps(
                    {
                        "app": "example",
                        "kind": "switch",
                        "after_sha256": contract.digest(after),
                        "before_sha256": contract.digest(before),
                        "backup_file": str(backup),
                        "previous_upstream": "127.0.0.1:4100",
                    }
                )
            )

            original_receipt_path = contract.receipt_path
            contract.receipt_path = lambda _app, _transaction: receipt
            try:
                with self.assertRaises(contract.ContractError):
                    contract.perform_restore(
                        "example",
                        {"upstream_file": str(upstream)},
                        "transaction",
                    )
            finally:
                contract.receipt_path = original_receipt_path

            self.assertEqual(upstream.read_bytes(), newer)


if __name__ == "__main__":
    unittest.main()
