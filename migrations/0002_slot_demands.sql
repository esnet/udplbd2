-- Migration for slot assignment strategy and slot demands

-- Add strategy column to reservation
ALTER TABLE reservation ADD COLUMN strategy TEXT DEFAULT 'dynamic';

-- Create slot_demand table
CREATE TABLE slot_demand (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reservation_id INTEGER NOT NULL REFERENCES reservation(id) ON DELETE CASCADE,
    session_id INTEGER REFERENCES session(id) ON DELETE CASCADE,
    slot_index INTEGER NOT NULL,
    slot_length INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    deleted_at INTEGER
);

-- Indexes for fast lookup
CREATE INDEX idx_slot_demand_reservation_id ON slot_demand (reservation_id);
CREATE INDEX idx_slot_demand_session_id ON slot_demand (session_id);
