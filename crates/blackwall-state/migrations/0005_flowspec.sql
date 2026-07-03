CREATE TABLE flowspec_rules (
    id BIGSERIAL PRIMARY KEY,
    dst INET NOT NULL,
    proto INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    rate DOUBLE PRECISION NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('auto','manual')),
    announced_at TIMESTAMPTZ NOT NULL,
    withdrawn_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX flowspec_active_uniq ON flowspec_rules (dst, proto, dst_port)
    WHERE withdrawn_at IS NULL;

CREATE TABLE flowspec_requests (
    id BIGSERIAL PRIMARY KEY,
    dst INET NOT NULL,
    proto INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    rate DOUBLE PRECISION NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('add','remove')),
    created_by TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','rejected')),
    note TEXT,
    applied_at TIMESTAMPTZ
);
