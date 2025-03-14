CREATE TABLE IF NOT EXISTS token (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    parent_token_id INTEGER REFERENCES token(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS token_loadbalancer_permission (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    token_id INTEGER NOT NULL REFERENCES token(id) ON DELETE CASCADE,
    loadbalancer_id INTEGER NOT NULL REFERENCES loadbalancer(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(token_id, loadbalancer_id)
);

CREATE INDEX token_loadbalancer_permission_id_index ON token_loadbalancer_permission(token_id);

CREATE TABLE IF NOT EXISTS token_reservation_permission (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    token_id INTEGER NOT NULL REFERENCES token(id) ON DELETE CASCADE,
    reservation_id INTEGER NOT NULL REFERENCES reservation(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(token_id, reservation_id)
);

CREATE INDEX token_reservation_permission_token_id_index ON token_reservation_permission(token_id);

CREATE TABLE IF NOT EXISTS token_session_permission (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    token_id INTEGER NOT NULL REFERENCES token(id) ON DELETE CASCADE,
    session_id INTEGER NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(token_id, session_id)
);

CREATE INDEX token_session_permission_token_id_index ON token_session_permission(token_id);

CREATE TABLE IF NOT EXISTS token_global_permission (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    token_id INTEGER NOT NULL REFERENCES token(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(token_id)
);

CREATE TABLE IF NOT EXISTS loadbalancer (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    name TEXT NOT NULL,
    unicast_mac_address TEXT NOT NULL,
    broadcast_mac_address TEXT NOT NULL,
    unicast_ipv4_address TEXT NOT NULL,
    unicast_ipv6_address TEXT NOT NULL,
    event_number_udp_port INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at DATETIME
);

CREATE TABLE IF NOT EXISTS reservation (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    loadbalancer_id INTEGER NOT NULL REFERENCES loadbalancer(id) ON DELETE CASCADE,
    reserved_until DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at DATETIME
);

CREATE TABLE IF NOT EXISTS sender (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    reservation_id INTEGER NOT NULL REFERENCES reservation(id) ON DELETE CASCADE,
    ip_address TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at DATETIME
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sender_res_ip
ON sender (reservation_id, ip_address);

CREATE TABLE IF NOT EXISTS session (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    reservation_id INTEGER NOT NULL REFERENCES reservation(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    weight FLOAT NOT NULL,
    ip_address TEXT NOT NULL,
    udp_port INTEGER NOT NULL,
    port_range INTEGER NOT NULL,
    mac_address TEXT,
    min_factor FLOAT NOT NULL DEFAULT 0.0,
    max_factor FLOAT NOT NULL DEFAULT 0.0,
    keep_lb_header INTEGER NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at DATETIME
);

CREATE TABLE IF NOT EXISTS session_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    timestamp DATETIME NOT NULL,
    fill_percent FLOAT NOT NULL,
    control_signal FLOAT NOT NULL,
    is_ready BOOLEAN NOT NULL,
    total_events_recv INTEGER NOT NULL,
    total_events_reassembled INTEGER NOT NULL,
    total_events_reassembly_err INTEGER NOT NULL,
    total_events_dequeued INTEGER NOT NULL,
    total_event_enqueue_err INTEGER NOT NULL,
    total_bytes_recv INTEGER NOT NULL,
    total_packets_recv INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS epoch (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    reservation_id INTEGER NOT NULL REFERENCES reservation(id) ON DELETE CASCADE,
    epoch_fpga_id TEXT NOT NULL,
    boundary_event INTEGER NOT NULL,
    predicted_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at DATETIME,
    slots BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS event_number (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    reservation_id INTEGER NOT NULL REFERENCES reservation(id) ON DELETE CASCADE,
    event_number INTEGER NOT NULL,
    avg_event_rate_hz INTEGER NOT NULL,
    local_timestamp DATETIME NOT NULL,
    remote_timestamp DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
