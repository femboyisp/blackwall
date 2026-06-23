CREATE TABLE tenants (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ip_assignments (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    address     INET NOT NULL UNIQUE
);

CREATE TABLE services (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    address     INET NOT NULL,
    proto       TEXT NOT NULL CHECK (proto IN ('tcp', 'udp')),
    port        INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
    target      JSONB NOT NULL,
    UNIQUE (address, proto, port)
);

CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      JSONB NOT NULL
);
