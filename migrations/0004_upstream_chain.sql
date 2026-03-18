-- Upstream chain: stores the connection details for a reservation that has been
-- registered as a receiver with an upstream control plane (LB chaining).
CREATE TABLE upstream_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reservation_id INTEGER NOT NULL,
    upstream_grpc_host TEXT NOT NULL,
    upstream_grpc_port INTEGER NOT NULL,
    upstream_tls_enabled INTEGER NOT NULL DEFAULT 0,
    upstream_lb_id TEXT NOT NULL,
    upstream_ejfat_token TEXT,
    upstream_session_token TEXT NOT NULL,
    upstream_session_id TEXT NOT NULL,
    upstream_data_ipv4 TEXT,
    upstream_data_ipv6 TEXT,
    created_at REAL NOT NULL DEFAULT (unixepoch('subsec') * 1000),
    deleted_at REAL,
    FOREIGN KEY (reservation_id) REFERENCES reservation(id)
);
