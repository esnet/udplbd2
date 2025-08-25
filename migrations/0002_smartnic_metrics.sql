CREATE TABLE IF NOT EXISTS stat_global_sample (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    sample_ts_ms       INTEGER NOT NULL,

    -- RX result classification buckets (0..13)
    rx_rslt_0          INTEGER NOT NULL,
    rx_rslt_1          INTEGER NOT NULL,
    rx_rslt_2          INTEGER NOT NULL,
    rx_rslt_3          INTEGER NOT NULL,
    rx_rslt_4          INTEGER NOT NULL,
    rx_rslt_5          INTEGER NOT NULL,
    rx_rslt_6          INTEGER NOT NULL,
    rx_rslt_7          INTEGER NOT NULL,
    rx_rslt_8          INTEGER NOT NULL,
    rx_rslt_9          INTEGER NOT NULL,
    rx_rslt_10         INTEGER NOT NULL,
    rx_rslt_11         INTEGER NOT NULL,
    rx_rslt_12         INTEGER NOT NULL,
    rx_rslt_13         INTEGER NOT NULL,

    created_at         INTEGER NOT NULL DEFAULT (unixepoch('subsec') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_stat_global_ts
  ON stat_global_sample(sample_ts_ms);

CREATE TABLE IF NOT EXISTS stat_lb_sample (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    reservation_id           INTEGER REFERENCES reservation(id) ON DELETE CASCADE,
    sample_ts_ms             INTEGER NOT NULL,

    -- Drop counters (per LB)
    drop_blocked_src         INTEGER NOT NULL,
    drop_epoch_assign_miss   INTEGER NOT NULL,
    drop_lb_calendar_miss    INTEGER NOT NULL,
    drop_mbr_info_miss       INTEGER NOT NULL,
    drop_no_udplb_hdr        INTEGER NOT NULL,
    drop_not_ip              INTEGER NOT NULL,

    -- Receive counters (per LB)
    lb_ctx_rx_bytes          INTEGER NOT NULL,  -- lb_ctx_rx_byte_counter
    pkt_rx_bytes             INTEGER NOT NULL,  -- packet_rx_counter_bytes
    pkt_rx_pkts              INTEGER NOT NULL,  -- packet_rx_counter_packets

    created_at               INTEGER NOT NULL DEFAULT (unixepoch('subsec') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_stat_lb_ts
  ON stat_lb_sample(sample_ts_ms);
CREATE INDEX IF NOT EXISTS idx_stat_lb_res_ts
  ON stat_lb_sample(reservation_id, sample_ts_ms);


CREATE TABLE IF NOT EXISTS stat_member_sample (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    session_id               INTEGER REFERENCES session(id) ON DELETE SET NULL,
    sample_ts_ms             INTEGER NOT NULL,

    -- Per-member counters
    mbr_tx_pkts              INTEGER NOT NULL,  -- lb_mbr_tx_pkt_counter[member_id]
    mbr_tx_bytes             INTEGER NOT NULL,  -- lb_mbr_tx_byte_counter[member_id]

    created_at               INTEGER NOT NULL DEFAULT (unixepoch('subsec') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_stat_member_ts
  ON stat_member_sample(sample_ts_ms);
CREATE INDEX IF NOT EXISTS idx_stat_member_session_ts
  ON stat_member_sample(session_id, sample_ts_ms);
