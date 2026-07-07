CREATE TABLE cookie_secret (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    secret BYTEA NOT NULL CHECK (octet_length(secret) = 16),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
