CREATE TABLE IF NOT EXISTS stat_global_sample (
    id                                      INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    sample_ts_ms                            INTEGER NOT NULL,

    -- RX result classification buckets (0..13)
    rx_rslt_drop_parse_fail                  INTEGER NOT NULL,  -- 0
    rx_rslt_drop_mac_dst_miss                INTEGER NOT NULL,  -- 1
    rx_rslt_drop_not_ip                      INTEGER NOT NULL,  -- 2
    rx_rslt_drop_ip_dst_miss                 INTEGER NOT NULL,  -- 3
    rx_rslt_drop_arp_bad_tpa                 INTEGER NOT NULL,  -- 4
    rx_rslt_drop_icmpv4_echo_bad_dst         INTEGER NOT NULL,  -- 5
    rx_rslt_drop_icmpv6_echo_bad_dst         INTEGER NOT NULL,  -- 6 (unused)
    rx_rslt_drop_ipv6nd_neigh_sol_bad_target INTEGER NOT NULL, -- 7
    rx_rslt_ok_arp_req                       INTEGER NOT NULL,  -- 8
    rx_rslt_ok_icmpv4_echo                   INTEGER NOT NULL,  -- 9
    rx_rslt_ok_icmpv6_echo                   INTEGER NOT NULL,  -- 10
    rx_rslt_ok_ipv6nd_neigh_sol              INTEGER NOT NULL,  -- 11
    rx_rslt_ok_host                          INTEGER NOT NULL,  -- 12 (unused)
    rx_rslt_ok_lb                            INTEGER NOT NULL,  -- 13

    created_at                              INTEGER NOT NULL DEFAULT (unixepoch('subsec') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_stat_global_ts
  ON stat_global_sample(sample_ts_ms);

CREATE TABLE IF NOT EXISTS stat_lb_sample (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    reservation_id           INTEGER REFERENCES reservation(id) ON DELETE CASCADE,
    sample_ts_ms             INTEGER NOT NULL,

    -- Drop counters (per LB)
    drop_bad_udplb_version   INTEGER NOT NULL,
    drop_blocked_src         INTEGER NOT NULL,
    drop_epoch_assign_miss   INTEGER NOT NULL,
    drop_lb_calendar_miss    INTEGER NOT NULL,
    drop_mbr_info_miss       INTEGER NOT NULL,
    drop_no_udplb_hdr        INTEGER NOT NULL,
    drop_not_ip              INTEGER NOT NULL,

    -- Receive counters (per LB)
    rx_bytes                 INTEGER NOT NULL,
    rx_packets               INTEGER NOT NULL,
    rx_v2                    INTEGER NOT NULL,
    rx_v3                    INTEGER NOT NULL,

    created_at               INTEGER NOT NULL DEFAULT (unixepoch('subsec') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_stat_lb_ts
  ON stat_lb_sample(sample_ts_ms);
CREATE INDEX IF NOT EXISTS idx_stat_lb_res_ts
  ON stat_lb_sample(reservation_id, sample_ts_ms);

CREATE TABLE IF NOT EXISTS stat_scope (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    domain                   TEXT,
    zone                     TEXT,
    block                    TEXT,
    created_at               INTEGER NOT NULL DEFAULT (unixepoch('subsec') * 1000)
);

CREATE TABLE IF NOT EXISTS stat_lb_scoped_sample (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    reservation_id           INTEGER REFERENCES reservation(id) ON DELETE CASCADE,
    stat_scope_id            INTEGER REFERENCES stat_scope(id) ON DELETE CASCADE,
    sample_ts_ms             INTEGER NOT NULL,

    -- Track packets per-FPGA to characterize LAG
    rx_bytes                 INTEGER NOT NULL,
    rx_packets               INTEGER NOT NULL,

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
