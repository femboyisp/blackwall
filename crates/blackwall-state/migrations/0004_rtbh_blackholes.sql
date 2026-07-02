CREATE TABLE rtbh_blackholes (
    id BIGSERIAL PRIMARY KEY,
    target INET NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('auto','manual')),
    announced_at TIMESTAMPTZ NOT NULL,
    withdrawn_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX rtbh_active_uniq ON rtbh_blackholes (target) WHERE withdrawn_at IS NULL;

CREATE TABLE rtbh_requests (
    id BIGSERIAL PRIMARY KEY,
    target INET NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('add','remove')),
    created_by TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','rejected')),
    note TEXT,
    applied_at TIMESTAMPTZ
);
