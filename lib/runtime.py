"""Security boundary and operation implementations for the Vault pack."""

from __future__ import annotations

import base64
import re
from typing import Any, Callable
from urllib.parse import urlparse

PACK_REF = "vault"
DEFAULT_CREDENTIAL_KEY = "vault_credentials"
MAX_TIMEOUT = 60
MAX_TOKEN_TTL = 86400
MAX_WRAP_TTL = 3600
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./-]*$|^$")


class PackError(Exception):
    """A public, non-sensitive error code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _required(params: dict[str, Any], name: str, expected: type | None = None) -> Any:
    value = params.get(name)
    if value is None or value == "":
        raise PackError("invalid_input")
    if expected is not None and not isinstance(value, expected):
        raise PackError("invalid_input")
    return value


def _component(value: Any) -> str:
    value = str(value or "").strip().strip("/")
    if not value or value.endswith(".") or not _COMPONENT_RE.fullmatch(value):
        raise PackError("invalid_path")
    return value


def _path(value: Any, *, allow_empty: bool = False) -> str:
    value = str(value or "").strip().strip("/")
    if (not value and not allow_empty) or value.endswith(".") or not _PATH_RE.fullmatch(value):
        raise PackError("invalid_path")
    if any(part in ("", ".", "..") for part in value.split("/")) and value:
        raise PackError("invalid_path")
    return value


def _mount(value: Any) -> str:
    return _path(value)


def _key_ref(value: Any) -> str:
    value = str(value or "").strip()
    if not _REF_RE.fullmatch(value):
        raise PackError("invalid_key_ref")
    return value


def _timeout(params: dict[str, Any]) -> int:
    value = params.get("timeout_seconds", 15)
    if type(value) is not int:
        raise PackError("invalid_timeout")
    if not 1 <= value <= MAX_TIMEOUT:
        raise PackError("invalid_timeout")
    return value


def _positive_versions(params: dict[str, Any]) -> list[int]:
    values = _required(params, "versions", list)
    if not values or len(values) > 64:
        raise PackError("invalid_versions")
    if any(type(v) is not int or v < 1 for v in values):
        raise PackError("invalid_versions")
    return sorted(set(values))


def _confirm(params: dict[str, Any], exact: str) -> None:
    if params.get("confirmation") != exact:
        raise PackError("confirmation_required")


class AttuneKeyStore:
    """Minimal SDK-only keystore adapter with strict pack ownership checks."""

    def __init__(self) -> None:
        try:
            import attune
            self.client = attune.context.client
        except Exception:
            raise PackError("attune_keystore_unavailable") from None

    @staticmethod
    def _data(result: Any) -> Any:
        status = int(result.status_code)
        if status == 404:
            return None
        if status >= 400 or not result.parsed:
            raise PackError("attune_keystore_failed")
        return result.parsed.data

    @staticmethod
    def _assert_owned(data: Any, *, require_encrypted: bool = True) -> None:
        owner_type = getattr(getattr(data, "owner_type", None), "value", None)
        if owner_type != "pack" or getattr(data, "owner_pack_ref", None) != PACK_REF:
            raise PackError("key_not_pack_owned")
        if require_encrypted and not getattr(data, "encrypted", False):
            raise PackError("key_not_encrypted")

    def get(self, ref: str) -> Any:
        from attune.api_client.api.secrets import get_key

        data = self._data(get_key.sync_detailed(ref, client=self.client))
        if data is None:
            raise PackError("key_not_found")
        self._assert_owned(data)
        return data.value

    def put_secret(self, ref: str, value: Any, name: str) -> None:
        from attune.api_client.api.secrets import create_key, get_key, update_key
        from attune.api_client.models.create_key_request import CreateKeyRequest
        from attune.api_client.models.owner_type import OwnerType
        from attune.api_client.models.update_key_request import UpdateKeyRequest

        existing = self._data(get_key.sync_detailed(ref, client=self.client))
        if existing is not None:
            self._assert_owned(existing)
            result = update_key.sync_detailed(
                ref,
                client=self.client,
                body=UpdateKeyRequest(value=value, encrypted=True),
            )
        else:
            result = create_key.sync_detailed(
                client=self.client,
                body=CreateKeyRequest(
                    ref=ref,
                    name=name,
                    owner_type=OwnerType.PACK,
                    owner_pack_ref=PACK_REF,
                    value=value,
                    encrypted=True,
                ),
            )
        if int(result.status_code) >= 400:
            raise PackError("attune_keystore_failed")


def _profile(params: dict[str, Any], store: Any) -> dict[str, Any]:
    ref = _key_ref(params.get("credential_key") or DEFAULT_CREDENTIAL_KEY)
    profile = store.get(ref)
    if isinstance(profile, str):
        import json
        try:
            profile = json.loads(profile)
        except ValueError:
            raise PackError("invalid_credential_profile") from None
    if not isinstance(profile, dict):
        raise PackError("invalid_credential_profile")

    url = str(profile.get("url") or "").rstrip("/")
    parsed = urlparse(url)
    try:
        parsed.port
    except ValueError:
        raise PackError("invalid_vault_url") from None
    if (
        parsed.scheme not in ("https", "http")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise PackError("invalid_vault_url")
    if parsed.scheme != "https" and profile.get("allow_http") is not True:
        raise PackError("insecure_transport_denied")
    if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise PackError("invalid_vault_url")

    verify = profile.get("verify", True)
    if verify is False and profile.get("insecure_skip_verify") is not True:
        raise PackError("insecure_tls_denied")
    ca_cert = profile.get("ca_cert")
    if ca_cert:
        verify = str(ca_cert)
    cert = profile.get("client_cert")
    key = profile.get("client_key")
    if bool(cert) != bool(key):
        raise PackError("invalid_mtls_profile")

    namespace = profile.get("namespace")
    if namespace is not None:
        namespace = str(namespace).strip().strip("/")
        if not namespace or ".." in namespace.split("/") or not _PATH_RE.fullmatch(namespace):
            raise PackError("invalid_namespace")

    auth_method = profile.get("auth_method", "token")
    if auth_method not in ("token", "approle"):
        raise PackError("unsupported_auth_method")
    return {
        **profile,
        "url": url,
        "verify": verify,
        "cert": (str(cert), str(key)) if cert else None,
        "namespace": namespace,
        "auth_method": auth_method,
    }


def _client(profile: dict[str, Any], timeout: int, *, authenticate: bool = True) -> Any:
    try:
        import hvac
        import requests

        session = requests.Session()
        session.verify = profile["verify"]
        session.cert = profile["cert"]
        adapter = requests.adapters.HTTPAdapter(max_retries=0)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        client = hvac.Client(
            url=profile["url"],
            token=None,
            cert=profile["cert"],
            verify=profile["verify"],
            timeout=timeout,
            allow_redirects=False,
            namespace=profile["namespace"],
            session=session,
        )
        if not authenticate:
            return client
        if profile["auth_method"] == "token":
            token = profile.get("token")
            if not isinstance(token, str) or not token:
                raise PackError("invalid_credential_profile")
            client.token = token
        else:
            role_id = profile.get("role_id")
            secret_id = profile.get("secret_id")
            if not isinstance(role_id, str) or not role_id or not isinstance(secret_id, str) or not secret_id:
                raise PackError("invalid_credential_profile")
            client.auth.approle.login(
                role_id=role_id,
                secret_id=secret_id,
                mount_point=_mount(profile.get("auth_mount", "approle")),
            )
        return client
    except PackError:
        raise
    except Exception:
        raise PackError("vault_authentication_failed") from None


def _context(params: dict[str, Any], *, authenticate: bool = True) -> tuple[Any, Any, dict[str, Any]]:
    store = AttuneKeyStore()
    profile = _profile(params, store)
    return store, _client(profile, _timeout(params), authenticate=authenticate), profile


def health(params: dict[str, Any]) -> dict[str, Any]:
    store = AttuneKeyStore()
    profile = _profile(params, store)
    # Vault documents /sys/health as root-namespace-only.
    root_profile = {**profile, "namespace": None}
    client = _client(root_profile, _timeout(params), authenticate=False)
    try:
        response = client.adapter.get(
            "/v1/sys/health",
            params={"standbyok": "true", "perfstandbyok": "true"},
            raise_exception=False,
        )
        if isinstance(response, dict):
            data, status = response, 200
        else:
            status = int(response.status_code)
            data = response.json()
        return {
            "ok": status in (200, 429, 472, 473, 474, 501, 503, 530),
            "healthy": status == 200,
            "status_code": status,
            "initialized": bool(data.get("initialized")),
            "sealed": bool(data.get("sealed")),
            "standby": bool(data.get("standby")),
            "performance_standby": bool(data.get("performance_standby")),
            "version": data.get("version"),
        }
    except Exception:
        raise PackError("vault_health_failed") from None


def token_lookup_self(params: dict[str, Any]) -> dict[str, Any]:
    _, client, profile = _context(params)
    try:
        data = client.auth.token.lookup_self()["data"]
        return {
            "ok": True,
            "display_name": data.get("display_name"),
            "policies": data.get("policies", []),
            "ttl_seconds": data.get("ttl"),
            "renewable": bool(data.get("renewable")),
            "orphan": bool(data.get("orphan")),
            "token_type": data.get("type"),
            "namespace": profile.get("namespace"),
        }
    except Exception:
        raise PackError("vault_token_lookup_failed") from None


def token_renew_self(params: dict[str, Any]) -> dict[str, Any]:
    _, client, _ = _context(params)
    increment = params.get("increment_seconds")
    if increment is not None and (type(increment) is not int or not 1 <= increment <= MAX_TOKEN_TTL):
        raise PackError("invalid_ttl")
    try:
        response = client.auth.token.renew_self(increment=f"{increment}s" if increment else None)
        auth = response.get("auth") or {}
        return {
            "ok": True,
            "lease_duration_seconds": auth.get("lease_duration"),
            "renewable": bool(auth.get("renewable")),
        }
    except Exception:
        raise PackError("vault_token_renew_failed") from None


def token_revoke_self(params: dict[str, Any]) -> dict[str, Any]:
    _confirm(params, "REVOKE SELF")
    _, client, _ = _context(params)
    try:
        client.auth.token.revoke_self()
        return {"ok": True, "revoked": True}
    except Exception:
        raise PackError("vault_token_revoke_failed") from None


def approle_login(params: dict[str, Any]) -> dict[str, Any]:
    store = AttuneKeyStore()
    profile = _profile(params, store)
    if profile["auth_method"] != "approle":
        raise PackError("approle_profile_required")
    output_ref = _key_ref(_required(params, "output_key", str))
    wrap = params.get("wrap_ttl_seconds")
    if wrap is not None and (type(wrap) is not int or not 1 <= wrap <= MAX_WRAP_TTL):
        raise PackError("invalid_wrap_ttl")
    client = _client(profile, _timeout(params), authenticate=False)
    try:
        mount = _mount(profile.get("auth_mount", "approle"))
        if wrap:
            response = client.adapter.post(
                f"/v1/auth/{mount}/login",
                json={"role_id": profile["role_id"], "secret_id": profile["secret_id"]},
                wrap_ttl=f"{wrap}s",
            )
            info = response["wrap_info"]
            value = info["token"]
            result = {"ok": True, "output_key": output_ref, "wrapped": True, "wrap_ttl_seconds": info.get("ttl")}
        else:
            response = client.auth.approle.login(
                role_id=profile["role_id"],
                secret_id=profile["secret_id"],
                use_token=False,
                mount_point=mount,
            )
            auth = response["auth"]
            value = auth["client_token"]
            result = {
                "ok": True,
                "output_key": output_ref,
                "wrapped": False,
                "lease_duration_seconds": auth.get("lease_duration"),
                "renewable": bool(auth.get("renewable")),
            }
        store.put_secret(output_ref, value, "Vault AppRole login token")
        return result
    except PackError:
        raise
    except Exception:
        raise PackError("vault_approle_login_failed") from None


def _kv(params: dict[str, Any]) -> tuple[Any, Any, str, str, int]:
    store, client, _ = _context(params)
    mount = _mount(params.get("mount", "secret"))
    path = _path(_required(params, "path", str))
    version = params.get("kv_version", 2)
    if type(version) is not int or version not in (1, 2):
        raise PackError("invalid_kv_version")
    return store, client, mount, path, version


def kv_read(params: dict[str, Any]) -> dict[str, Any]:
    store, client, mount, path, version = _kv(params)
    output_ref = _key_ref(_required(params, "output_key", str))
    try:
        if version == 1:
            response = client.secrets.kv.v1.read_secret(path=path, mount_point=mount)
            value, metadata = response["data"], {}
        else:
            selected = params.get("secret_version")
            if selected is not None and (type(selected) is not int or selected < 1):
                raise PackError("invalid_versions")
            response = client.secrets.kv.v2.read_secret_version(
                path=path,
                version=selected,
                mount_point=mount,
                raise_on_deleted_version=True,
            )
            value, metadata = response["data"]["data"], response["data"]["metadata"]
        store.put_secret(output_ref, value, "Vault KV secret")
        return {
            "ok": True,
            "output_key": output_ref,
            "kv_version": version,
            "version": metadata.get("version"),
            "created_time": metadata.get("created_time"),
            "lease_id": response.get("lease_id") or None,
            "lease_duration_seconds": response.get("lease_duration") or 0,
            "renewable": bool(response.get("renewable")),
        }
    except PackError:
        raise
    except Exception:
        raise PackError("vault_kv_read_failed") from None


def kv_write(params: dict[str, Any]) -> dict[str, Any]:
    _, client, mount, path, version = _kv(params)
    data = _required(params, "data", dict)
    if not data:
        raise PackError("invalid_input")
    try:
        if version == 1:
            client.secrets.kv.v1.create_or_update_secret(path=path, secret=data, mount_point=mount)
            written_version = None
        else:
            cas = params.get("cas")
            if cas is not None and (type(cas) is not int or cas < 0):
                raise PackError("invalid_cas")
            response = client.secrets.kv.v2.create_or_update_secret(path=path, secret=data, cas=cas, mount_point=mount)
            written_version = (response.get("data") or {}).get("version")
        return {"ok": True, "kv_version": version, "version": written_version}
    except PackError:
        raise
    except Exception:
        raise PackError("vault_kv_write_failed") from None


def kv_patch(params: dict[str, Any]) -> dict[str, Any]:
    _, client, mount, path, version = _kv(params)
    if version != 2:
        raise PackError("kv_v2_required")
    data = _required(params, "data", dict)
    cas = _required(params, "cas")
    if not data or type(cas) is not int or cas < 1:
        raise PackError("invalid_cas")
    try:
        response = client.adapter.request(
            "patch",
            f"/v1/{mount}/data/{path}",
            headers={"Content-Type": "application/merge-patch+json"},
            json={"data": data, "options": {"cas": cas}},
        )
        return {"ok": True, "kv_version": 2, "version": (response.get("data") or {}).get("version")}
    except Exception:
        raise PackError("vault_kv_patch_failed") from None


def kv_delete(params: dict[str, Any]) -> dict[str, Any]:
    _, client, mount, path, version = _kv(params)
    try:
        if version == 1:
            _confirm(params, f"DELETE KV V1: {mount}/{path}")
            client.secrets.kv.v1.delete_secret(path=path, mount_point=mount)
            versions = []
        elif params.get("versions") is not None:
            versions = _positive_versions(params)
            client.secrets.kv.v2.delete_secret_versions(path=path, versions=versions, mount_point=mount)
        else:
            versions = []
            client.secrets.kv.v2.delete_latest_version_of_secret(path=path, mount_point=mount)
        return {"ok": True, "kv_version": version, "versions": versions, "deleted": True}
    except PackError:
        raise
    except Exception:
        raise PackError("vault_kv_delete_failed") from None


def kv_undelete(params: dict[str, Any]) -> dict[str, Any]:
    _, client, mount, path, version = _kv(params)
    if version != 2:
        raise PackError("kv_v2_required")
    versions = _positive_versions(params)
    try:
        client.secrets.kv.v2.undelete_secret_versions(path=path, versions=versions, mount_point=mount)
        return {"ok": True, "versions": versions, "undeleted": True}
    except Exception:
        raise PackError("vault_kv_undelete_failed") from None


def kv_destroy(params: dict[str, Any]) -> dict[str, Any]:
    _, client, mount, path, version = _kv(params)
    if version != 2:
        raise PackError("kv_v2_required")
    versions = _positive_versions(params)
    suffix = ",".join(str(v) for v in versions)
    _confirm(params, f"DESTROY KV VERSIONS: {mount}/{path}#{suffix}")
    try:
        client.secrets.kv.v2.destroy_secret_versions(path=path, versions=versions, mount_point=mount)
        return {"ok": True, "versions": versions, "destroyed": True}
    except Exception:
        raise PackError("vault_kv_destroy_failed") from None


def kv_list(params: dict[str, Any]) -> dict[str, Any]:
    _, client, _ = _context(params)
    mount = _mount(params.get("mount", "secret"))
    path = _path(params.get("path", ""), allow_empty=True)
    version = params.get("kv_version", 2)
    if type(version) is not int or version not in (1, 2):
        raise PackError("invalid_kv_version")
    try:
        api = client.secrets.kv.v1 if version == 1 else client.secrets.kv.v2
        response = api.list_secrets(path=path, mount_point=mount)
        return {"ok": True, "kv_version": version, "keys": response["data"].get("keys", [])}
    except Exception:
        raise PackError("vault_kv_list_failed") from None


def kv_metadata(params: dict[str, Any]) -> dict[str, Any]:
    _, client, mount, path, version = _kv(params)
    if version != 2:
        raise PackError("kv_v2_required")
    try:
        data = client.secrets.kv.v2.read_secret_metadata(path=path, mount_point=mount)["data"]
        versions = {
            str(number): {
                "created_time": item.get("created_time"),
                "deletion_time": item.get("deletion_time"),
                "destroyed": bool(item.get("destroyed")),
            }
            for number, item in (data.get("versions") or {}).items()
        }
        return {
            "ok": True,
            "current_version": data.get("current_version"),
            "oldest_version": data.get("oldest_version"),
            "max_versions": data.get("max_versions"),
            "cas_required": bool(data.get("cas_required")),
            "delete_version_after": data.get("delete_version_after"),
            "versions": versions,
        }
    except Exception:
        raise PackError("vault_kv_metadata_failed") from None


def policy_list(params: dict[str, Any]) -> dict[str, Any]:
    _, client, _ = _context(params)
    try:
        data = client.sys.list_policies()["data"]
        return {"ok": True, "policies": data.get("policies") or data.get("keys") or []}
    except Exception:
        raise PackError("vault_policy_list_failed") from None


def policy_read(params: dict[str, Any]) -> dict[str, Any]:
    _, client, _ = _context(params)
    name = _component(_required(params, "name", str))
    try:
        data = client.sys.read_policy(name)["data"]
        return {"ok": True, "name": name, "policy": data.get("rules") or data.get("policy")}
    except Exception:
        raise PackError("vault_policy_read_failed") from None


def policy_write(params: dict[str, Any]) -> dict[str, Any]:
    _, client, _ = _context(params)
    name = _component(_required(params, "name", str))
    policy = _required(params, "policy", str)
    _confirm(params, f"WRITE POLICY: {name}")
    try:
        client.sys.create_or_update_policy(name=name, policy=policy)
        return {"ok": True, "name": name, "written": True}
    except Exception:
        raise PackError("vault_policy_write_failed") from None


def policy_delete(params: dict[str, Any]) -> dict[str, Any]:
    _, client, _ = _context(params)
    name = _component(_required(params, "name", str))
    _confirm(params, f"DELETE POLICY: {name}")
    try:
        client.sys.delete_policy(name=name)
        return {"ok": True, "name": name, "deleted": True}
    except Exception:
        raise PackError("vault_policy_delete_failed") from None


def token_create(params: dict[str, Any]) -> dict[str, Any]:
    store, client, _ = _context(params)
    output_ref = _key_ref(_required(params, "output_key", str))
    policies = _required(params, "policies", list)
    if not policies or len(policies) > 16 or any(
        not isinstance(p, str) or p.endswith(".") or not _COMPONENT_RE.fullmatch(p)
        for p in policies
    ):
        raise PackError("invalid_policies")
    policies = sorted(set(p.lower() for p in policies))
    if "root" in policies:
        raise PackError("root_token_denied")
    ttl = _required(params, "ttl_seconds")
    if type(ttl) is not int or not 60 <= ttl <= MAX_TOKEN_TTL:
        raise PackError("invalid_ttl")
    wrap = params.get("wrap_ttl_seconds")
    if wrap is not None and (type(wrap) is not int or not 1 <= wrap <= MAX_WRAP_TTL):
        raise PackError("invalid_wrap_ttl")
    token_type = params.get("token_type", "service")
    if token_type not in ("service", "batch"):
        raise PackError("invalid_token_type")
    num_uses = params.get("num_uses", 0)
    if type(num_uses) is not int or not 0 <= num_uses <= 10000:
        raise PackError("invalid_num_uses")
    renewable = params.get("renewable", False)
    if type(renewable) is not bool or (token_type == "batch" and renewable):
        raise PackError("invalid_renewable")
    no_default_policy = params.get("no_default_policy", True)
    if type(no_default_policy) is not bool:
        raise PackError("invalid_no_default_policy")
    display_name = params.get("display_name", "attune")
    if not isinstance(display_name, str) or not 1 <= len(display_name) <= 64:
        raise PackError("invalid_display_name")
    _confirm(params, f"CREATE TOKEN: {','.join(policies)}")
    try:
        response = client.auth.token.create(
            policies=policies,
            no_parent=False,
            no_default_policy=no_default_policy,
            renewable=renewable,
            ttl=f"{ttl}s",
            explicit_max_ttl=f"{ttl}s",
            display_name=display_name,
            num_uses=num_uses,
            type=token_type,
            wrap_ttl=f"{wrap}s" if wrap else None,
        )
        if wrap:
            info, value = response["wrap_info"], response["wrap_info"]["token"]
            result = {"ok": True, "output_key": output_ref, "wrapped": True, "wrap_ttl_seconds": info.get("ttl")}
        else:
            auth, value = response["auth"], response["auth"]["client_token"]
            result = {
                "ok": True,
                "output_key": output_ref,
                "wrapped": False,
                "lease_duration_seconds": auth.get("lease_duration"),
                "renewable": bool(auth.get("renewable")),
                "policies": auth.get("policies", policies),
            }
        store.put_secret(output_ref, value, "Vault child token")
        return result
    except PackError:
        raise
    except Exception:
        raise PackError("vault_token_create_failed") from None


def _transit(params: dict[str, Any]) -> tuple[Any, str, str]:
    _, client, _ = _context(params)
    mount = _mount(params.get("mount", "transit"))
    key = _component(_required(params, "key_name", str))
    try:
        metadata = client.secrets.transit.read_key(name=key, mount_point=mount)["data"]
    except Exception:
        raise PackError("vault_transit_key_check_failed") from None
    if metadata.get("derived"):
        raise PackError("derived_transit_key_unsupported")
    return client, mount, key


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def transit_encrypt(params: dict[str, Any]) -> dict[str, Any]:
    client, mount, key = _transit(params)
    plaintext = _required(params, "plaintext", str)
    try:
        path = f"{mount}/encrypt/{key}"
        response = client.sys.get_capabilities(paths=[path])
        data = response.get("data") or response
        capabilities = data.get(path) or data.get("capabilities") or []
        if not isinstance(capabilities, list) or "update" not in capabilities:
            raise PackError("transit_update_capability_required")
        if any(capability in capabilities for capability in ("create", "sudo", "root")):
            raise PackError("transit_implicit_create_denied")
        response = client.secrets.transit.encrypt_data(name=key, plaintext=_b64(plaintext), mount_point=mount)
        return {"ok": True, "ciphertext": response["data"]["ciphertext"], "key_version": response["data"].get("key_version")}
    except PackError:
        raise
    except Exception:
        raise PackError("vault_transit_encrypt_failed") from None


def transit_decrypt(params: dict[str, Any]) -> dict[str, Any]:
    store = AttuneKeyStore()
    profile = _profile(params, store)
    client = _client(profile, _timeout(params))
    mount = _mount(params.get("mount", "transit"))
    key = _component(_required(params, "key_name", str))
    output_ref = _key_ref(_required(params, "output_key", str))
    try:
        metadata = client.secrets.transit.read_key(name=key, mount_point=mount)["data"]
        if metadata.get("derived"):
            raise PackError("derived_transit_key_unsupported")
        response = client.secrets.transit.decrypt_data(
            name=key,
            ciphertext=_required(params, "ciphertext", str),
            mount_point=mount,
        )
        plaintext = base64.b64decode(response["data"]["plaintext"], validate=True).decode("utf-8")
        store.put_secret(output_ref, plaintext, "Vault Transit plaintext")
        return {"ok": True, "output_key": output_ref}
    except PackError:
        raise
    except Exception:
        raise PackError("vault_transit_decrypt_failed") from None


def transit_sign(params: dict[str, Any]) -> dict[str, Any]:
    client, mount, key = _transit(params)
    hash_algorithm = params.get("hash_algorithm", "sha2-256")
    if hash_algorithm not in ("sha2-224", "sha2-256", "sha2-384", "sha2-512"):
        raise PackError("invalid_hash_algorithm")
    try:
        response = client.secrets.transit.sign_data(
            name=key,
            hash_input=_b64(_required(params, "input", str)),
            hash_algorithm=hash_algorithm,
            prehashed=False,
            mount_point=mount,
        )
        return {"ok": True, "signature": response["data"]["signature"]}
    except Exception:
        raise PackError("vault_transit_sign_failed") from None


def transit_verify(params: dict[str, Any]) -> dict[str, Any]:
    client, mount, key = _transit(params)
    hash_algorithm = params.get("hash_algorithm", "sha2-256")
    if hash_algorithm not in ("sha2-224", "sha2-256", "sha2-384", "sha2-512"):
        raise PackError("invalid_hash_algorithm")
    try:
        response = client.secrets.transit.verify_signed_data(
            name=key,
            hash_input=_b64(_required(params, "input", str)),
            signature=_required(params, "signature", str),
            hash_algorithm=hash_algorithm,
            prehashed=False,
            mount_point=mount,
        )
        return {"ok": True, "valid": bool(response["data"]["valid"])}
    except Exception:
        raise PackError("vault_transit_verify_failed") from None


OPERATIONS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    name: value
    for name, value in globals().copy().items()
    if name in {
        "health", "token_lookup_self", "token_renew_self", "token_revoke_self", "approle_login",
        "kv_read", "kv_write", "kv_patch", "kv_delete", "kv_undelete", "kv_destroy", "kv_list", "kv_metadata",
        "policy_list", "policy_read", "policy_write", "policy_delete", "token_create",
        "transit_encrypt", "transit_decrypt", "transit_sign", "transit_verify",
    }
}


def dispatch(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    handler = OPERATIONS.get(operation)
    if handler is None:
        raise PackError("unsupported_action")
    return {key: value for key, value in handler(params).items() if value is not None}
