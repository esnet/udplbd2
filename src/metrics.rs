use prometheus::{
    exponential_buckets, register_counter, register_counter_vec, register_gauge_vec,
    register_histogram, Counter, CounterVec, GaugeVec, Histogram, HistogramOpts, Opts,
};
use std::sync::LazyLock;

use crate::constants::MAX_LB_INSTANCES;

// Counters
pub static EPOCHS_PROCESSED: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(Opts::new(
        "udplbd_epochs_processed_total",
        "The total number of processed epochs"
    ))
    .unwrap()
});

pub static INBOUND_GRPC: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(Opts::new(
        "udplbd_inbound_grpc_total",
        "The total number of inbound control plane gRPC requests"
    ))
    .unwrap()
});

pub static INBOUND_REST: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(Opts::new(
        "udplbd_inbound_rest_total",
        "The total number of inbound control plane REST requests"
    ))
    .unwrap()
});

pub static SMARTNIC_GRPC: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "udplbd_smartnic_grpc_total",
            "Total number of errors occurred during gRPC operations"
        ),
        &["operation"]
    )
    .unwrap()
});

pub static SMARTNIC_GRPC_ERRORS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "udplbd_smartnic_grpc_errors_total",
            "Total number of errors occurred during gRPC operations"
        ),
        &["operation"]
    )
    .unwrap()
});

// Histograms
pub static BULK_UPDATE_DURATION: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(HistogramOpts::new(
        "udplbd_bulk_update_duration_seconds",
        "Duration of BulkUpdate gRPC calls in seconds"
    )
    .buckets(exponential_buckets(0.001, 2.0, 15).unwrap()))
    .unwrap()
});

// Gauges
pub static LB_ACTIVE_SESSIONS: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "udplbd_lb_active_sessions_total",
            "The number of currently connected nodes"
        ),
        &["fpga_lb_id"]
    )
    .unwrap()
});

pub static LB_TICK_DURATION: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "udplbd_lb_tick_duration_seconds",
            "Duration of the load balancer tick operation"
        ),
        &["fpga_lb_id"]
    )
    .unwrap()
});

pub static LB_IS_ACTIVE: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "udplbd_lb_is_active",
            "Whether the load balancer instance is active (1) or not (0)"
        ),
        &["fpga_lb_id"]
    )
    .unwrap()
});

pub static LB_SLOTS_AVG: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "udplbd_lb_slots_avg",
            "Average number of slots assigned across all nodes"
        ),
        &["fpga_lb_id"]
    )
    .unwrap()
});

pub static LB_SLOTS_STDDEV: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "udplbd_lb_slots_stddev",
            "Standard deviation of slots assigned across all nodes"
        ),
        &["fpga_lb_id"]
    )
    .unwrap()
});

pub static LB_SLOTS_MAX: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "udplbd_lb_slots_max",
            "Maximum number of slots assigned to a single node"
        ),
        &["fpga_lb_id"]
    )
    .unwrap()
});

pub static LB_SLOTS_MIN: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "udplbd_lb_slots_min",
            "Minimum number of slots assigned to a single node"
        ),
        &["fpga_lb_id"]
    )
    .unwrap()
});

pub static LB_EPOCH_BOUNDARY: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "udplbd_lb_epoch_boundary",
            "Event number that begins the next epoch"
        ),
        &["fpga_lb_id"]
    )
    .unwrap()
});

pub static LB_FILL_PERCENT_AVG: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "udplbd_lb_fill_percent_avg",
            "Average fill percentage across all nodes"
        ),
        &["fpga_lb_id"]
    )
    .unwrap()
});

pub static LB_FILL_PERCENT_STDDEV: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "udplbd_lb_fill_percent_stddev",
            "Standard deviation of fill percentages across all nodes"
        ),
        &["fpga_lb_id"]
    )
    .unwrap()
});

pub static LB_FILL_PERCENT_MAX: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "udplbd_lb_fill_percent_max",
            "Maximum fill percentage across all nodes"
        ),
        &["fpga_lb_id"]
    )
    .unwrap()
});

pub static LB_FILL_PERCENT_MIN: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "udplbd_lb_fill_percent_min",
            "Minimum fill percentage across all nodes"
        ),
        &["fpga_lb_id"]
    )
    .unwrap()
});

/// Initialize all metrics with default values
pub fn init_metrics() {
    let operations = [
        "get_pipeline_info",
        "clear_tables",
        "clear_table",
        "insert_rule",
        "update_rule",
        "delete_rule",
        "get_device_info",
        "get_pipeline_stats",
        "clear_pipeline_stats",
        "get_stats",
        "clear_stats",
        "get_server_config",
        "set_server_config",
        "get_server_status",
    ];

    for op in operations {
        SMARTNIC_GRPC.with_label_values(&[op]).inc_by(0.0);
        SMARTNIC_GRPC_ERRORS.with_label_values(&[op]).inc_by(0.0);
    }

    for i in 0..MAX_LB_INSTANCES {
        let lb_id = i.to_string();
        LB_TICK_DURATION.with_label_values(&[&lb_id]).set(0.0);
        LB_IS_ACTIVE.with_label_values(&[&lb_id]).set(0.0);
        LB_ACTIVE_SESSIONS.with_label_values(&[&lb_id]).set(0.0);
        LB_SLOTS_AVG.with_label_values(&[&lb_id]).set(0.0);
        LB_SLOTS_STDDEV.with_label_values(&[&lb_id]).set(0.0);
        LB_SLOTS_MAX.with_label_values(&[&lb_id]).set(0.0);
        LB_SLOTS_MIN.with_label_values(&[&lb_id]).set(0.0);
        LB_EPOCH_BOUNDARY.with_label_values(&[&lb_id]).set(0.0);
        LB_FILL_PERCENT_AVG.with_label_values(&[&lb_id]).set(0.0);
        LB_FILL_PERCENT_STDDEV.with_label_values(&[&lb_id]).set(0.0);
        LB_FILL_PERCENT_MAX.with_label_values(&[&lb_id]).set(0.0);
        LB_FILL_PERCENT_MIN.with_label_values(&[&lb_id]).set(0.0);
    }
}
