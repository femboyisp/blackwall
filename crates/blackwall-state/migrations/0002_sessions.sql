CREATE TABLE deception_sessions (
    id          BIGSERIAL PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    local_addr  INET NOT NULL,
    local_port  INTEGER NOT NULL CHECK (local_port BETWEEN 0 AND 65535),
    peer_addr   INET NOT NULL,
    proto       TEXT NOT NULL CHECK (proto IN ('tcp', 'udp', 'icmp')),
    emulator    TEXT NOT NULL,
    bytes_in    BIGINT NOT NULL,
    bytes_out   BIGINT NOT NULL,
    note        TEXT
);
