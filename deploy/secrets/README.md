# Secrets

Files in this directory are git-ignored (except this README). Create:

- `master_keys` — `k1:<base64 32 bytes>`; generate with
  `printf 'k1:%s\n' "$(openssl rand -base64 32)" > deploy/secrets/master_keys && chmod 600 deploy/secrets/master_keys`
- optional `oidc_client_secret`, `tls_cert`, `tls_key`

Rotation (spec §6.2): append `k2:<new>` to `master_keys`, set `MASTER_KEY_ACTIVE=k2`, restart; remove `k1` 15 minutes later.
