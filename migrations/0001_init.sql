CREATE TABLE IF NOT EXISTS token (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    parent_token_id INTEGER REFERENCES token(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL DEFAULT(unixepoch('subsec') * 1000)
);
CREATE INDEX idx_token_created_at ON token(created_at);
CREATE INDEX idx_token_parent_token_id ON token(parent_token_id);

CREATE TABLE IF NOT EXISTS token_loadbalancer_permission (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    token_id INTEGER NOT NULL REFERENCES token(id) ON DELETE CASCADE,
    loadbalancer_id INTEGER NOT NULL REFERENCES loadbalancer(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT(unixepoch('subsec') * 1000),
    UNIQUE(token_id, loadbalancer_id)
);
CREATE INDEX token_loadbalancer_permission_id_index ON token_loadbalancer_permission(token_id);
CREATE INDEX idx_token_loadbalancer_permission_loadbalancer_id ON token_loadbalancer_permission(loadbalancer_id);
CREATE INDEX idx_token_loadbalancer_permission_created_at ON token_loadbalancer_permission(created_at);

CREATE TABLE IF NOT EXISTS token_reservation_permission (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    token_id INTEGER NOT NULL REFERENCES token(id) ON DELETE CASCADE,
    reservation_id INTEGER NOT NULL REFERENCES reservation(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT(unixepoch('subsec') * 1000),
    UNIQUE(token_id, reservation_id)
);
CREATE INDEX token_reservation_permission_token_id_index ON token_reservation_permission(token_id);
CREATE INDEX idx_token_reservation_permission_reservation_id ON token_reservation_permission(reservation_id);
CREATE INDEX idx_token_reservation_permission_created_at ON token_reservation_permission(created_at);

CREATE TABLE IF NOT EXISTS token_session_permission (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    token_id INTEGER NOT NULL REFERENCES token(id) ON DELETE CASCADE,
    session_id INTEGER NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT(unixepoch('subsec') * 1000),
    UNIQUE(token_id, session_id)
);
CREATE INDEX token_session_permission_token_id_index ON token_session_permission(token_id);
CREATE INDEX idx_token_session_permission_session_id ON token_session_permission(session_id);
CREATE INDEX idx_token_session_permission_created_at ON token_session_permission(created_at);

CREATE TABLE IF NOT EXISTS token_global_permission (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    token_id INTEGER NOT NULL REFERENCES token(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT(unixepoch('subsec') * 1000),
    UNIQUE(token_id)
);
CREATE INDEX idx_token_global_permission_created_at ON token_global_permission(created_at);

CREATE TABLE IF NOT EXISTS loadbalancer (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    name TEXT NOT NULL,
    unicast_mac_address TEXT NOT NULL,
    broadcast_mac_address TEXT NOT NULL,
    unicast_ipv4_address TEXT NOT NULL,
    unicast_ipv6_address TEXT NOT NULL,
    event_number_udp_port INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT(unixepoch('subsec') * 1000),
    deleted_at INTEGER
);
CREATE INDEX idx_loadbalancer_created_at ON loadbalancer(created_at);
CREATE INDEX idx_loadbalancer_deleted_at ON loadbalancer(deleted_at);

CREATE TABLE IF NOT EXISTS reservation (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    loadbalancer_id INTEGER NOT NULL REFERENCES loadbalancer(id) ON DELETE CASCADE,
    reserved_until INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT(unixepoch('subsec') * 1000),
    deleted_at INTEGER,
    fpga_lb_id INTEGER NOT NULL,
    current_epoch INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_reservation_loadbalancer_id ON reservation(loadbalancer_id);
CREATE INDEX idx_reservation_reserved_until ON reservation(reserved_until);
CREATE INDEX idx_reservation_created_at ON reservation(created_at);
CREATE INDEX idx_reservation_deleted_at ON reservation(deleted_at);

CREATE TABLE IF NOT EXISTS sender (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    reservation_id INTEGER NOT NULL REFERENCES reservation(id) ON DELETE CASCADE,
    ip_address TEXT,
    created_at INTEGER NOT NULL DEFAULT(unixepoch('subsec') * 1000),
    deleted_at INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sender_res_ip ON sender(reservation_id, ip_address);
CREATE INDEX idx_sender_reservation_id ON sender(reservation_id);
CREATE INDEX idx_sender_created_at ON sender(created_at);
CREATE INDEX idx_sender_deleted_at ON sender(deleted_at);

CREATE TABLE IF NOT EXISTS session (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    reservation_id INTEGER NOT NULL REFERENCES reservation(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    initial_weight_factor FLOAT NOT NULL,
    weight FLOAT NOT NULL,
    latest_session_state_id INTEGER REFERENCES session_state(id),
    ip_address TEXT NOT NULL,
    udp_port INTEGER NOT NULL,
    port_range INTEGER NOT NULL,
    mac_address TEXT,
    min_factor FLOAT NOT NULL DEFAULT 0.0,
    max_factor FLOAT NOT NULL DEFAULT 0.0,
    keep_lb_header INTEGER NOT NULL DEFAULT FALSE,
    created_at INTEGER NOT NULL DEFAULT(unixepoch('subsec') * 1000),
    deleted_at INTEGER
);
CREATE INDEX idx_session_reservation_id ON session(reservation_id);
CREATE INDEX idx_session_created_at ON session(created_at);
CREATE INDEX idx_session_deleted_at ON session(deleted_at);

CREATE TABLE IF NOT EXISTS session_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    timestamp INTEGER NOT NULL,
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
    created_at INTEGER NOT NULL DEFAULT(unixepoch('subsec') * 1000)
);
CREATE INDEX idx_session_state_session_id ON session_state(session_id);
CREATE INDEX idx_session_state_timestamp ON session_state(timestamp);
CREATE INDEX idx_session_state_created_at ON session_state(created_at);

CREATE TABLE IF NOT EXISTS epoch (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    reservation_id INTEGER NOT NULL REFERENCES reservation(id) ON DELETE CASCADE,
    boundary_event INTEGER NOT NULL,
    predicted_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT(unixepoch('subsec') * 1000),
    deleted_at INTEGER,
    slots BLOB NOT NULL,
    epoch_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_epoch_reservation_id ON epoch(reservation_id);
CREATE INDEX idx_epoch_predicted_at ON epoch(predicted_at);
CREATE INDEX idx_epoch_created_at ON epoch(created_at);
CREATE INDEX idx_epoch_deleted_at ON epoch(deleted_at);
CREATE INDEX idx_epoch_epoch_count ON epoch(epoch_count);

CREATE TABLE IF NOT EXISTS event_number (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    reservation_id INTEGER NOT NULL REFERENCES reservation(id) ON DELETE CASCADE,
    event_number INTEGER NOT NULL,
    avg_event_rate_hz INTEGER NOT NULL,
    local_timestamp INTEGER NOT NULL,
    remote_timestamp INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT(unixepoch('subsec') * 1000)
);
CREATE INDEX idx_event_number_reservation_id ON event_number(reservation_id);
CREATE INDEX idx_event_number_local_timestamp ON event_number(local_timestamp);
CREATE INDEX idx_event_number_remote_timestamp ON event_number(remote_timestamp);
CREATE INDEX idx_event_number_created_at ON event_number(created_at);
