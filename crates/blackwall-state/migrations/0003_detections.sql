CREATE TABLE detections (
    id           BIGSERIAL PRIMARY KEY,
    target       INET        NOT NULL,
    kind         TEXT        NOT NULL,
    observed_pps DOUBLE PRECISION NOT NULL,
    observed_bps DOUBLE PRECISION NOT NULL,
    proto        INTEGER     NOT NULL,
    top_sources  JSONB       NOT NULL,
    top_ports    JSONB       NOT NULL,
    severity     TEXT        NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    cleared_at   TIMESTAMPTZ
);
CREATE INDEX detections_active_idx ON detections (target) WHERE cleared_at IS NULL;
