-- 0001_init: users, pastes (metadata only), audit_events. Spec §5.1.
CREATE TABLE users (
  id            uuid PRIMARY KEY,
  username      text UNIQUE NOT NULL,
  display_name  text,
  auth_provider text NOT NULL CHECK (auth_provider IN ('local','oidc')),
  oidc_issuer   text,
  oidc_subject  text,
  password_hash text,
  is_admin      boolean NOT NULL DEFAULT false,
  disabled      boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz,
  UNIQUE (oidc_issuer, oidc_subject)
);

CREATE TABLE pastes (
  id                 uuid PRIMARY KEY,
  owner_id           uuid NOT NULL REFERENCES users(id),
  created_at         timestamptz NOT NULL,
  expires_at         timestamptz NOT NULL,
  ttl_seconds        integer NOT NULL,
  size_bytes         integer NOT NULL,
  hash_algo          text NOT NULL DEFAULT 'sha256',
  content_hash       text NOT NULL,
  password_protected boolean NOT NULL,
  kek_id             text,
  view_count         integer NOT NULL DEFAULT 0,
  expired_audited_at timestamptz,
  deleted_at         timestamptz,
  deleted_by         uuid REFERENCES users(id),
  CONSTRAINT ttl_bounds CHECK (ttl_seconds BETWEEN 1 AND 86400)
);
CREATE INDEX pastes_owner_created ON pastes (owner_id, created_at DESC);
CREATE INDEX pastes_created ON pastes (created_at);
CREATE INDEX pastes_expires_unaudited ON pastes (expires_at) WHERE expired_audited_at IS NULL AND deleted_at IS NULL;

CREATE TABLE audit_events (
  id          bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  event       text NOT NULL,
  actor_id    uuid,
  paste_id    uuid,
  ip          inet,
  user_agent  text,
  outcome     text NOT NULL,
  details     jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_events_at ON audit_events (at);
