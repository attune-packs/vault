import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import runtime


class FakeStore:
    def __init__(self, profile=None):
        self.profile = profile or {
            "url": "https://vault.example.test:8200",
            "auth_method": "token",
            "token": "bootstrap-secret",
        }
        self.writes = []

    def get(self, ref):
        assert ref == "vault_credentials"
        return self.profile

    def put_secret(self, ref, value, name):
        self.writes.append((ref, value, name))


def test_profile_requires_explicit_http_opt_in():
    store = FakeStore({"url": "http://vault.test", "auth_method": "token", "token": "x"})
    with pytest.raises(runtime.PackError) as caught:
        runtime._profile({}, store)
    assert caught.value.code == "insecure_transport_denied"


@pytest.mark.parametrize(
    "url",
    ["https://user@vault.test", "https://:password@vault.test", "https://vault.test:bad"],
)
def test_profile_rejects_url_credentials_and_invalid_ports(url):
    store = FakeStore({"url": url, "auth_method": "token", "token": "x"})
    with pytest.raises(runtime.PackError) as caught:
        runtime._profile({}, store)
    assert caught.value.code == "invalid_vault_url"


def test_profile_normalizes_namespace_without_adding_it_to_url():
    store = FakeStore(
        {
            "url": "https://vault.test:8200/",
            "namespace": "/admin/team-a/",
            "auth_method": "token",
            "token": "x",
        }
    )
    profile = runtime._profile({}, store)
    assert profile["url"] == "https://vault.test:8200"
    assert profile["namespace"] == "admin/team-a"


def test_nested_mount_is_supported_but_namespace_escape_is_not():
    assert runtime._mount("team-a/secret") == "team-a/secret"
    with pytest.raises(runtime.PackError):
        runtime._mount("team-a/../secret")


@pytest.mark.parametrize("path", ["../secret", "foo//bar", "foo/./bar", "foo?version=1"])
def test_path_rejects_ambiguous_or_escaping_values(path):
    with pytest.raises(runtime.PackError) as caught:
        runtime._path(path)
    assert caught.value.code == "invalid_path"


def test_unknown_dispatch_cannot_be_used_as_arbitrary_endpoint():
    with pytest.raises(runtime.PackError) as caught:
        runtime.dispatch("sys_raw_request", {})
    assert caught.value.code == "unsupported_action"


def test_kv_v2_read_writes_secret_to_key_and_not_result(monkeypatch):
    store = FakeStore()
    client = MagicMock()
    client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {
            "data": {"password": "super-secret"},
            "metadata": {"version": 7, "created_time": "now"},
        },
        "lease_duration": 0,
        "renewable": False,
    }
    monkeypatch.setattr(runtime, "_kv", lambda params: (store, client, "secret", "app/db", 2))

    result = runtime.kv_read({"output_key": "vault_db", "secret_version": 7})

    assert store.writes == [("vault_db", {"password": "super-secret"}, "Vault KV secret")]
    assert "super-secret" not in repr(result)
    assert result["version"] == 7
    client.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path="app/db", version=7, mount_point="secret", raise_on_deleted_version=True
    )


def test_kv_patch_is_one_native_cas_request_without_read(monkeypatch):
    client = MagicMock()
    client.adapter.request.return_value = {"data": {"version": 4}}
    monkeypatch.setattr(runtime, "_kv", lambda params: (FakeStore(), client, "secret", "app/db", 2))

    result = runtime.kv_patch({"data": {"password": "new-secret"}, "cas": 3})

    assert result == {"ok": True, "kv_version": 2, "version": 4}
    client.adapter.request.assert_called_once_with(
        "patch",
        "/v1/secret/data/app/db",
        headers={"Content-Type": "application/merge-patch+json"},
        json={"data": {"password": "new-secret"}, "options": {"cas": 3}},
    )
    assert client.secrets.mock_calls == []


def test_kv_destroy_confirmation_uses_sorted_unique_versions(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(runtime, "_kv", lambda params: (FakeStore(), client, "secret", "app/db", 2))
    params = {
        "versions": [4, 2, 4],
        "confirmation": "DESTROY KV VERSIONS: secret/app/db#2,4",
    }

    result = runtime.kv_destroy(params)

    assert result == {"ok": True, "versions": [2, 4], "destroyed": True}
    client.secrets.kv.v2.destroy_secret_versions.assert_called_once_with(
        path="app/db", versions=[2, 4], mount_point="secret"
    )


def test_kv_destroy_wrong_confirmation_never_mutates(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(runtime, "_kv", lambda params: (FakeStore(), client, "secret", "app/db", 2))
    with pytest.raises(runtime.PackError) as caught:
        runtime.kv_destroy({"versions": [2], "confirmation": "yes"})
    assert caught.value.code == "confirmation_required"
    assert client.mock_calls == []


def test_vault_error_text_is_not_exposed(monkeypatch):
    client = MagicMock()
    client.secrets.kv.v2.create_or_update_secret.side_effect = RuntimeError(
        "request reflected password top-secret-value"
    )
    monkeypatch.setattr(runtime, "_kv", lambda params: (FakeStore(), client, "secret", "app/db", 2))
    with pytest.raises(runtime.PackError) as caught:
        runtime.kv_write({"data": {"password": "top-secret-value"}})
    assert caught.value.code == "vault_kv_write_failed"
    assert "top-secret" not in str(caught.value)


def test_token_create_rejects_root_without_call(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(runtime, "_context", lambda params: (FakeStore(), client, {}))
    with pytest.raises(runtime.PackError) as caught:
        runtime.token_create(
            {
                "output_key": "child_token",
                "policies": ["root"],
                "ttl_seconds": 600,
                "confirmation": "CREATE TOKEN: root",
            }
        )
    assert caught.value.code == "root_token_denied"
    assert client.mock_calls == []


def test_token_create_is_bounded_and_token_only_enters_key(monkeypatch):
    store = FakeStore()
    client = MagicMock()
    client.auth.token.create.return_value = {
        "auth": {
            "client_token": "new-child-secret",
            "lease_duration": 600,
            "renewable": False,
            "policies": ["app", "default"],
        }
    }
    monkeypatch.setattr(runtime, "_context", lambda params: (store, client, {}))
    params = {
        "output_key": "child_token",
        "policies": ["Default", "app"],
        "ttl_seconds": 600,
        "confirmation": "CREATE TOKEN: app,default",
    }

    result = runtime.token_create(params)

    assert store.writes == [("child_token", "new-child-secret", "Vault child token")]
    assert "new-child-secret" not in repr(result)
    kwargs = client.auth.token.create.call_args.kwargs
    assert kwargs["ttl"] == "600s"
    assert kwargs["explicit_max_ttl"] == "600s"
    assert kwargs["policies"] == ["app", "default"]
    assert kwargs["no_parent"] is False
    assert "period" not in kwargs


def test_transit_decrypt_writes_plaintext_only_to_key(monkeypatch):
    store = FakeStore()
    client = MagicMock()
    client.secrets.transit.decrypt_data.return_value = {
        "data": {"plaintext": "cGxhaW50ZXh0LXNlY3JldA=="}
    }
    client.secrets.transit.read_key.return_value = {"data": {"derived": False}}
    monkeypatch.setattr(runtime, "AttuneKeyStore", lambda: store)
    monkeypatch.setattr(runtime, "_client", lambda profile, timeout: client)

    result = runtime.transit_decrypt(
        {
            "key_name": "payments",
            "ciphertext": "vault:v1:ciphertext",
            "output_key": "decrypted_value",
        }
    )

    assert result == {"ok": True, "output_key": "decrypted_value"}
    assert store.writes == [("decrypted_value", "plaintext-secret", "Vault Transit plaintext")]


def test_transit_encrypt_rejects_implicit_key_create_capability(monkeypatch):
    client = MagicMock()
    client.secrets.transit.read_key.return_value = {"data": {"derived": False}}
    client.sys.get_capabilities.return_value = {
        "data": {"transit/encrypt/payments": ["create", "update"]}
    }
    monkeypatch.setattr(runtime, "_context", lambda params: (FakeStore(), client, {}))

    with pytest.raises(runtime.PackError) as caught:
        runtime.transit_encrypt({"key_name": "payments", "plaintext": "secret"})

    assert caught.value.code == "transit_implicit_create_denied"
    assert client.secrets.transit.encrypt_data.call_count == 0


def test_health_forces_root_namespace(monkeypatch):
    profile = {
        "url": "https://vault.test",
        "auth_method": "token",
        "token": "secret",
        "namespace": "admin/team-a",
        "verify": True,
        "cert": None,
    }
    client = MagicMock()
    client.adapter.get.return_value = {
        "initialized": True,
        "sealed": False,
        "standby": False,
        "performance_standby": False,
        "version": "2.0.4",
    }
    monkeypatch.setattr(runtime, "AttuneKeyStore", lambda: FakeStore())
    monkeypatch.setattr(runtime, "_profile", lambda params, store: profile)
    seen = {}

    def fake_client(selected, timeout, authenticate):
        seen.update(selected)
        assert authenticate is False
        return client

    monkeypatch.setattr(runtime, "_client", fake_client)
    result = runtime.health({})

    assert seen["namespace"] is None
    assert result["version"] == "2.0.4"
    assert result["healthy"] is True


def test_hvac_client_applies_tls_namespace_timeout_and_no_retries():
    profile = {
        "url": "https://vault.test",
        "verify": "/ca.pem",
        "cert": ("/client.pem", "/key.pem"),
        "namespace": "admin/team-a",
        "auth_method": "token",
        "token": "secret",
    }
    client = runtime._client(profile, 17)
    assert client.adapter.namespace == "admin/team-a"
    assert client.adapter._kwargs["verify"] == "/ca.pem"
    assert client.adapter._kwargs["cert"] == ("/client.pem", "/key.pem")
    assert client.adapter._kwargs["timeout"] == 17
    assert client.allow_redirects is False
    assert client.session.adapters["https://"].max_retries.total == 0


def test_action_wrappers_hard_code_their_declared_operation():
    actions = os.path.join(os.path.dirname(os.path.dirname(__file__)), "actions")
    for operation in runtime.OPERATIONS:
        with open(os.path.join(actions, f"{operation}.py"), encoding="utf-8") as handle:
            source = handle.read()
        assert f'run("{operation}")' in source


def test_action_contracts_mark_all_direct_secret_values():
    actions = os.path.join(os.path.dirname(os.path.dirname(__file__)), "actions")
    expected = {
        "kv_write.yaml": "data: {type: object, required: true, secret: true",
        "kv_patch.yaml": "data: {type: object, required: true, secret: true",
        "transit_encrypt.yaml": "plaintext: {type: string, required: true, secret: true",
        "transit_decrypt.yaml": "ciphertext: {type: string, required: true, secret: true",
        "transit_sign.yaml": "input: {type: string, required: true, secret: true",
        "transit_verify.yaml": "input: {type: string, required: true, secret: true",
    }
    for filename, marker in expected.items():
        with open(os.path.join(actions, filename), encoding="utf-8") as handle:
            assert marker in handle.read()
