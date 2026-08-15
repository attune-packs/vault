"""Dependency-free tests used by `attune pack test`."""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import runtime


class Store:
    def __init__(self, profile=None):
        self.profile = profile or {
            "url": "https://vault.example.test:8200",
            "auth_method": "token",
            "token": "bootstrap-secret",
        }
        self.writes = []

    def get(self, ref):
        return self.profile

    def put_secret(self, ref, value, name):
        self.writes.append((ref, value, name))


class VaultPackTests(unittest.TestCase):
    def test_http_requires_explicit_opt_in(self):
        store = Store({"url": "http://vault.test", "auth_method": "token", "token": "x"})
        with self.assertRaises(runtime.PackError) as caught:
            runtime._profile({}, store)
        self.assertEqual(caught.exception.code, "insecure_transport_denied")

    def test_namespace_is_header_value_not_url_path(self):
        store = Store(
            {
                "url": "https://vault.test:8200/",
                "namespace": "/admin/team-a/",
                "auth_method": "token",
                "token": "x",
            }
        )
        profile = runtime._profile({}, store)
        self.assertEqual(profile["url"], "https://vault.test:8200")
        self.assertEqual(profile["namespace"], "admin/team-a")

    def test_nested_mount_cannot_escape(self):
        self.assertEqual(runtime._mount("team-a/secret"), "team-a/secret")
        with self.assertRaises(runtime.PackError):
            runtime._mount("team-a/../secret")

    def test_no_arbitrary_dispatch(self):
        with self.assertRaises(runtime.PackError) as caught:
            runtime.dispatch("raw_request", {})
        self.assertEqual(caught.exception.code, "unsupported_action")

    def test_kv_patch_is_native_single_request(self):
        client = MagicMock()
        client.adapter.request.return_value = {"data": {"version": 4}}
        with patch.object(runtime, "_kv", return_value=(Store(), client, "secret", "app/db", 2)):
            result = runtime.kv_patch({"data": {"password": "secret"}, "cas": 3})
        self.assertEqual(result["version"], 4)
        client.adapter.request.assert_called_once()
        self.assertEqual(client.secrets.mock_calls, [])

    def test_destroy_requires_exact_normalized_confirmation(self):
        client = MagicMock()
        params = {
            "versions": [4, 2, 4],
            "confirmation": "DESTROY KV VERSIONS: secret/app/db#2,4",
        }
        with patch.object(runtime, "_kv", return_value=(Store(), client, "secret", "app/db", 2)):
            result = runtime.kv_destroy(params)
        self.assertEqual(result["versions"], [2, 4])
        client.secrets.kv.v2.destroy_secret_versions.assert_called_once()

    def test_error_does_not_include_secret_or_vault_body(self):
        client = MagicMock()
        client.secrets.kv.v2.create_or_update_secret.side_effect = RuntimeError(
            "Vault reflected top-secret-value"
        )
        with patch.object(runtime, "_kv", return_value=(Store(), client, "secret", "app/db", 2)):
            with self.assertRaises(runtime.PackError) as caught:
                runtime.kv_write({"data": {"password": "top-secret-value"}})
        self.assertEqual(caught.exception.code, "vault_kv_write_failed")
        self.assertNotIn("top-secret", str(caught.exception))

    def test_root_token_is_always_denied(self):
        client = MagicMock()
        with patch.object(runtime, "_context", return_value=(Store(), client, {})):
            with self.assertRaises(runtime.PackError) as caught:
                runtime.token_create(
                    {
                        "output_key": "child",
                        "policies": ["root"],
                        "ttl_seconds": 600,
                        "confirmation": "CREATE TOKEN: root",
                    }
                )
        self.assertEqual(caught.exception.code, "root_token_denied")
        self.assertEqual(client.mock_calls, [])

    def test_created_token_goes_only_to_encrypted_key_adapter(self):
        store = Store()
        client = MagicMock()
        client.auth.token.create.return_value = {
            "auth": {
                "client_token": "new-child-secret",
                "lease_duration": 600,
                "renewable": False,
                "policies": ["app"],
            }
        }
        params = {
            "output_key": "child",
            "policies": ["app"],
            "ttl_seconds": 600,
            "confirmation": "CREATE TOKEN: app",
        }
        with patch.object(runtime, "_context", return_value=(store, client, {})):
            result = runtime.token_create(params)
        self.assertEqual(store.writes[0][1], "new-child-secret")
        self.assertNotIn("new-child-secret", repr(result))
        call = client.auth.token.create.call_args.kwargs
        self.assertEqual(call["ttl"], "600s")
        self.assertEqual(call["explicit_max_ttl"], "600s")


if __name__ == "__main__":
    unittest.main()
