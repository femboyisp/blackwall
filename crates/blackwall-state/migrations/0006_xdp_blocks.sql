CREATE TABLE xdp_entries (
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('block','rate_limit')),
    target INET NOT NULL,
    prefixlen INT,
    rate_pps BIGINT,
    origin TEXT NOT NULL CHECK (origin IN ('auto','manual')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE xdp_requests (
    id BIGSERIAL PRIMARY KEY,
    action TEXT NOT NULL CHECK (action IN ('block','unblock','rate_limit','clear_rate')),
    target INET NOT NULL,
    prefixlen INT,
    rate_pps BIGINT,
    created_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
