// SPDX-License-Identifier: BSD-3-Clause-LBNL
// Centralized application state and constants

// --- Configuration ---
export const API_BASE_URL = '/api/v1';
export const AUTH_COOKIE_NAME = 'loadBalancerAuthToken';
export const COOKIE_EXPIRY_DAYS = 7;

// --- Permission/Resource Type Mappings ---
export const ResourceTypeMap = {
    0: 'All',
    1: 'Load Balancer',
    2: 'Reservation',
    3: 'Session',
    default: 'Unknown Resource'
};

export const PermissionTypeMap = {
    0: 'Read Only',
    1: 'Register',
    2: 'Reserve',
    3: 'Update',
    default: 'Unknown Permission'
};

export const ResourceTypeOptions = [
    { value: 0, label: 'All' },
    { value: 1, label: 'Load Balancer' },
    { value: 2, label: 'Reservation' },
    { value: 3, label: 'Session' }
];

export const PermissionTypeOptions = [
    { value: 0, label: 'Read Only' },
    { value: 1, label: 'Register' },
    { value: 2, label: 'Reserve' },
    { value: 3, label: 'Update' }
];

// --- Metric Categorization ---
// Session metrics for workflow tab: control signal, fill percent, and event-related
export const WORKFLOW_SESSION_METRICS = [
    'control_signal', 'fill_percent', 'total_events_recv',
    'total_events_reassembled', 'total_events_reassembly_err',
    'total_events_dequeued', 'total_event_enqueue_err'
];

// Session metrics for network tab: packet/byte counters
export const NETWORK_SESSION_METRICS = [
    'total_bytes_recv', 'total_packets_recv', 'mbr_tx_pkts', 'mbr_tx_bytes'
];

// Metrics to exclude entirely
export const EXCLUDED_METRICS = ['is_ready'];

// LB-level workflow metrics
export const WORKFLOW_LB_METRICS = ['event_number', 'avg_event_rate_hz'];

// LB-level network metrics
export const NETWORK_LB_METRICS = ['rx_bytes', 'rx_packets'];

// --- Mutable Application State ---
export const state = {
    authToken: null,
    currentSelectedLbId: null,
    activeView: 'placeholder-view',
    currentPath: window.location.pathname,
    uPlotCharts: {},
    chartMetrics: {},
    timeseriesBuffer: {},
    lastTimestamp: null,
    sessionIdToName: {},
    filteredSessionIds: new Set(),
    allSessionIds: new Set(),
    activeChartTab: 'workflow'
};
