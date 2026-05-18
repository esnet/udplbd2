// SPDX-License-Identifier: BSD-3-Clause-LBNL
// Chart rendering, timeseries buffering, LTTB sampling, polling

import {
    state,
    WORKFLOW_SESSION_METRICS,
    NETWORK_SESSION_METRICS,
    EXCLUDED_METRICS,
    WORKFLOW_LB_METRICS,
    NETWORK_LB_METRICS
} from './state.js';
import { apiFetch } from './api.js';
import { showLbAlert } from './ui.js';

// --- Chart Lifecycle ---

export const destroyAllCharts = () => {
    Object.values(state.uPlotCharts).forEach(chart => chart?.destroy());
    state.uPlotCharts = {};
};

// --- LTTB Sampling ---

export const sampleDataPoints = (data, targetPoints = 500) => {
    if (!data || data.length <= targetPoints) {
        return data;
    }

    const sampledData = [];
    const bucketSize = (data.length - 2) / (targetPoints - 2);

    // Always include first point
    sampledData.push(data[0]);

    for (let i = 1; i < targetPoints - 1; i++) {
        const avgRangeStart = Math.floor(i * bucketSize) + 1;
        const avgRangeEnd = Math.floor((i + 1) * bucketSize) + 1;
        const rangeEnd = Math.min(avgRangeEnd, data.length);

        let avgTimestamp = 0;
        let avgValue = 0;
        let avgRangeLength = 0;

        for (let j = avgRangeStart; j < rangeEnd; j++) {
            avgTimestamp += data[j].timestamp;
            avgValue += data[j].value;
            avgRangeLength++;
        }

        avgTimestamp /= avgRangeLength;
        avgValue /= avgRangeLength;

        const rangeStart = Math.floor((i - 1) * bucketSize) + 1;
        const rangeOffs = Math.floor(i * bucketSize) + 1;

        let maxArea = -1;
        let maxAreaPoint = null;

        const pointA = sampledData[sampledData.length - 1];

        for (let j = rangeStart; j < rangeOffs && j < data.length; j++) {
            const pointB = data[j];
            const area = Math.abs(
                (pointA.timestamp - avgTimestamp) * (pointB.value - pointA.value) -
                (pointA.timestamp - pointB.timestamp) * (avgValue - pointA.value)
            ) * 0.5;

            if (area > maxArea) {
                maxArea = area;
                maxAreaPoint = pointB;
            }
        }

        if (maxAreaPoint) {
            sampledData.push(maxAreaPoint);
        }
    }

    // Always include last point
    sampledData.push(data[data.length - 1]);

    return sampledData;
};

// --- Session Color Palette ---

export const getSessionColor = (sessionId) => {
    const colors = [
        '#4285F4', '#EA4335', '#FBBC05', '#34A853',
        '#FF6D01', '#46BDC6', '#7BAAF7', '#F07B72',
        '#00C9A7', '#C355F5', '#FF5A5F', '#FFCF44',
        '#0072B5', '#E54C21', '#8A2BE2', '#00BFFF',
        '#32CD32', '#FF8C00', '#1E90FF', '#FF1493'
    ];
    return colors[parseInt(sessionId) % colors.length];
};

// --- Timeseries Buffering (de-duplicated) ---

const FIVE_MINUTES_MS = 5 * 60 * 1000;

export const bufferTimeseriesData = (timeseriesData) => {
    if (!timeseriesData?.timeseries?.length) return;

    timeseriesData.timeseries.forEach(series => {
        const name = series.name;
        const newPoints = series.timeseries?.FloatSamples?.data || [];
        if (!state.timeseriesBuffer[name]) {
            state.timeseriesBuffer[name] = [];
        }
        // Append new points, deduplicate by timestamp
        const existingTimestamps = new Set(state.timeseriesBuffer[name].map(p => p.timestamp));
        newPoints.forEach(point => {
            if (!existingTimestamps.has(point.timestamp)) {
                state.timeseriesBuffer[name].push(point);
            }
        });
        // Sort by timestamp
        state.timeseriesBuffer[name].sort((a, b) => a.timestamp - b.timestamp);
        // Trim old points beyond 5 minutes
        if (state.timeseriesBuffer[name].length > 0) {
            const latestTs = state.timeseriesBuffer[name][state.timeseriesBuffer[name].length - 1].timestamp;
            const minTs = latestTs - FIVE_MINUTES_MS;
            if (state.timeseriesBuffer[name][0].timestamp < minTs) {
                state.timeseriesBuffer[name] = state.timeseriesBuffer[name].filter(p => p.timestamp >= minTs);
            }
        }
    });
};

// --- Build buffered timeseries data object ---

export const getBufferedTimeseriesData = () => {
    return {
        timeseries: Object.entries(state.timeseriesBuffer).map(([name, data]) => ({
            name,
            timeseries: { FloatSamples: { data } }
        }))
    };
};

// --- Fetch Timeseries Data ---

export const fetchTimeseriesData = async (lbId) => {
    if (!state.authToken) return null;
    try {
        let url = `/timeseries?series=*`;
        if (state.lastTimestamp) {
            const date = new Date(state.lastTimestamp);
            const rfc3339Timestamp = date.toISOString();
            url += `&since=${rfc3339Timestamp}`;
        }
        const data = await apiFetch(url);
        if (data?.timeseries?.length > 0) {
            let maxTimestamp = state.lastTimestamp || 0;
            data.timeseries.forEach(series => {
                const points = series.timeseries?.FloatSamples?.data || [];
                points.forEach(point => {
                    if (point.timestamp > maxTimestamp) {
                        maxTimestamp = point.timestamp;
                    }
                });
            });
            state.lastTimestamp = maxTimestamp;
        }
        return data;
    } catch (error) {
        console.error('Failed to fetch timeseries data:', error);
        return null;
    }
};

// --- Chart Rendering ---

const renderCharts = (timeseriesData) => {
    const neededChartIds = new Set();
    const dynamicChartsArea = document.getElementById('dynamic-charts-area');
    const workflowArea = document.getElementById('workflow-charts');
    const networkArea = document.getElementById('network-charts');

    if (!timeseriesData?.timeseries?.length) {
        if (workflowArea) workflowArea.innerHTML = '<div class="no-data-message">No timeseries data available</div>';
        if (networkArea) networkArea.innerHTML = '';
        destroyAllCharts();
        return;
    }

    // Group timeseries by type
    const sessionSeries = new Map();
    const lbSeries = new Map();
    const dropSeries = new Map();
    const predictionData = { boundary_event: null, event_number: null };

    timeseriesData.timeseries.forEach(series => {
        const name = series.name;
        const data = series.timeseries?.FloatSamples?.data || [];
        if (!data.length) return;

        // /lb/{lb_id}/epoch/boundary_event
        const epochMatch = name.match(/^\/lb\/(\d+)\/epoch\/([^\/]+)$/);
        if (epochMatch) {
            if (epochMatch[1] !== state.currentSelectedLbId) return;
            if (epochMatch[2] === 'boundary_event') {
                predictionData.boundary_event = data;
            }
            return;
        }

        // /lb/{lb_id}/{metric} - LB-level metrics
        const lbMatch = name.match(/^\/lb\/(\d+)\/([^\/]+)$/);
        if (lbMatch) {
            if (lbMatch[1] !== state.currentSelectedLbId) return;
            const metricName = lbMatch[2];
            if (metricName.startsWith('drop_')) {
                dropSeries.set(metricName, data);
            } else if (metricName === 'event_number') {
                predictionData.event_number = data;
                lbSeries.set(metricName, data);
            } else {
                lbSeries.set(metricName, data);
            }
            return;
        }

        // /lb/{lb_id}/session/{session_id}/{metric}
        const sessionMatch = name.match(/^\/lb\/(\d+)\/session\/(\d+)\/([^\/]+)$/);
        if (sessionMatch) {
            if (sessionMatch[1] !== state.currentSelectedLbId) return;
            const sessionId = sessionMatch[2];
            const metricName = sessionMatch[3];
            if (EXCLUDED_METRICS.includes(metricName)) return;
            if (!sessionSeries.has(sessionId)) {
                sessionSeries.set(sessionId, new Map());
            }
            sessionSeries.get(sessionId).set(metricName, data);
            return;
        }
    });

    // Helper to update or create a chart container in a specific area
    function ensureChartContainer(title, id, targetArea) {
        if (!targetArea) {
            console.warn(`Target area not found for chart ${id}`);
            return null;
        }
        let container = document.getElementById(id);
        if (!container) {
            const wrapper = document.createElement('div');
            wrapper.className = 'chart-container';
            wrapper.innerHTML = `<h3>${title}</h3><div id="${id}"></div>`;
            targetArea.appendChild(wrapper);
            container = document.getElementById(id);
        } else {
            const currentParent = container.parentElement?.parentElement;
            if (currentParent !== targetArea) {
                targetArea.appendChild(container.parentElement);
            }
        }
        return container;
    }

    // Helper to create chart options
    function createChartOptions(container, seriesLabels, seriesColors, yLabel, specialOptions = {}) {
        const width = container.clientWidth > 0 ? container.clientWidth : 800;
        const defaultOptions = {
            width: width,
            height: 350,
            series: seriesLabels.map((label, i) => ({
                label,
                stroke: seriesColors[i],
                width: i > 0 ? 2.5 : 0,
                points: { show: false },
                spanGaps: true
            })),
            axes: [
                { stroke: 'white', grid: { stroke: '#444444' }, ticks: { count: 6 } },
                {
                    label: yLabel,
                    labelSize: 20,
                    stroke: 'white',
                    grid: { stroke: '#444444' },
                    font: '14px Arial',
                    color: 'white'
                }
            ],
            scales: { x: { time: true } },
            legend: { show: true }
        };
        return { ...defaultOptions, ...specialOptions };
    }

    // Helper to render a session metric chart
    function renderSessionMetricChart(metricKey, targetArea) {
        const formattedMetricName = metricKey.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        const chartId = `chart-${metricKey}`;
        neededChartIds.add(chartId);

        const chartContainer = ensureChartContainer(formattedMetricName, chartId, targetArea);
        if (!chartContainer) return;

        const timestamps = [];
        const seriesData = [];
        const seriesLabels = ['Time'];
        const seriesColors = ['transparent'];
        const sessionIds = [];

        sessionSeries.forEach((metrics, sessionId) => {
            if (state.filteredSessionIds.size > 0 && !state.filteredSessionIds.has(sessionId)) return;
            if (metrics.has(metricKey)) {
                const rawData = metrics.get(metricKey);
                const data = sampleDataPoints(rawData, 500);
                sessionIds.push(sessionId);
                const label = state.sessionIdToName[sessionId] || `Session ${sessionId}`;
                seriesLabels.push(label);
                seriesColors.push(getSessionColor(sessionId));
                data.forEach((point) => {
                    const ts = point.timestamp / 1000;
                    if (!timestamps.includes(ts)) {
                        timestamps.push(ts);
                    }
                });
            }
        });
        timestamps.sort((a, b) => a - b);
        seriesData.push(timestamps);

        sessionSeries.forEach((metrics, sessionId) => {
            if (state.filteredSessionIds.size > 0 && !state.filteredSessionIds.has(sessionId)) return;
            if (metrics.has(metricKey)) {
                const rawData = metrics.get(metricKey);
                const data = sampleDataPoints(rawData, 500);
                const values = new Array(timestamps.length).fill(null);
                data.forEach(point => {
                    const idx = timestamps.indexOf(point.timestamp / 1000);
                    if (idx !== -1) values[idx] = point.value;
                });
                seriesData.push(values);
            }
        });

        if (seriesLabels.length <= 1) return;

        const specialOptions = metricKey === 'fill_percent' ? { scales: { y: { range: [0, 1] } } } : {};
        const chartOptions = createChartOptions(chartContainer, seriesLabels, seriesColors, formattedMetricName, specialOptions);

        const existingChart = state.uPlotCharts[chartId];
        const labelsChanged = existingChart && (
            existingChart.series.length !== seriesLabels.length ||
            existingChart.series.some((s, i) => s.label !== seriesLabels[i])
        );

        if (existingChart && !labelsChanged) {
            existingChart.setData(seriesData);
            existingChart.sessionIds = sessionIds;
        } else {
            if (existingChart) {
                existingChart.destroy();
                chartContainer.innerHTML = '';
            }
            const chart = new uPlot(chartOptions, seriesData, chartContainer);
            chart.sessionIds = sessionIds;
            state.uPlotCharts[chartId] = chart;
        }
    }

    // Helper to render an LB-level metric chart
    function renderLbMetricChart(metricName, rawData, targetArea) {
        const formattedMetricName = metricName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        const chartId = `chart-lb-${metricName}`;
        neededChartIds.add(chartId);

        const chartContainer = ensureChartContainer(formattedMetricName, chartId, targetArea);
        if (!chartContainer) return;

        const data = sampleDataPoints(rawData, 500);
        const timestamps = data.map(point => point.timestamp / 1000);
        const values = data.map(point => point.value);
        const seriesData = [timestamps, values];
        const seriesLabels = ['Time', formattedMetricName];
        const seriesColors = ['transparent', '#4285F4'];

        const chartOptions = createChartOptions(chartContainer, seriesLabels, seriesColors, formattedMetricName);

        if (state.uPlotCharts[chartId]) {
            state.uPlotCharts[chartId].setData(seriesData);
        } else {
            state.uPlotCharts[chartId] = new uPlot(chartOptions, seriesData, chartContainer);
        }
    }

    // --- Collect all session metrics ---
    const sessionMetrics = new Set();
    sessionSeries.forEach(metrics => {
        metrics.forEach((_, metricName) => {
            if (!EXCLUDED_METRICS.includes(metricName)) {
                sessionMetrics.add(metricName);
            }
        });
    });

    // ==================== WORKFLOW TAB ====================

    // Prediction Accuracy Chart
    if (predictionData.boundary_event && predictionData.event_number) {
        const chartId = 'chart-prediction-accuracy';
        neededChartIds.add(chartId);

        const chartContainer = ensureChartContainer('Prediction Accuracy', chartId, workflowArea);

        const boundaryEventData = sampleDataPoints(predictionData.boundary_event, 500);
        const eventNumberData = sampleDataPoints(predictionData.event_number, 500);

        const allTimestamps = new Set();
        boundaryEventData.forEach(point => allTimestamps.add(point.timestamp));
        eventNumberData.forEach(point => allTimestamps.add(point.timestamp));
        const timestamps = Array.from(allTimestamps).sort((a, b) => a - b);

        const boundaryValues = new Array(timestamps.length).fill(null);
        const eventNumberValues = new Array(timestamps.length).fill(null);
        const differenceValues = new Array(timestamps.length).fill(null);

        boundaryEventData.forEach(point => {
            const idx = timestamps.indexOf(point.timestamp);
            if (idx !== -1) boundaryValues[idx] = point.value;
        });
        eventNumberData.forEach(point => {
            const idx = timestamps.indexOf(point.timestamp);
            if (idx !== -1) eventNumberValues[idx] = point.value;
        });
        for (let i = 0; i < timestamps.length; i++) {
            if (boundaryValues[i] !== null && eventNumberValues[i] !== null) {
                differenceValues[i] = Math.abs(boundaryValues[i] - eventNumberValues[i]);
            }
        }

        const seriesData = [timestamps, boundaryValues, eventNumberValues, differenceValues];
        const seriesLabels = ['Time', 'Boundary Event', 'Event Number', 'Difference'];
        const seriesColors = ['transparent', '#4285F4', '#34A853', '#EA4335'];

        const chartOptions = createChartOptions(chartContainer, seriesLabels, seriesColors, 'Event Number');

        if (state.uPlotCharts[chartId]) {
            state.uPlotCharts[chartId].setData(seriesData);
        } else {
            state.uPlotCharts[chartId] = new uPlot(chartOptions, seriesData, chartContainer);
        }
    }

    // Workflow Session Metrics
    WORKFLOW_SESSION_METRICS.forEach(metricKey => {
        if (sessionMetrics.has(metricKey)) {
            renderSessionMetricChart(metricKey, workflowArea);
        }
    });

    // Workflow LB Metrics
    WORKFLOW_LB_METRICS.forEach(metricName => {
        if (lbSeries.has(metricName)) {
            renderLbMetricChart(metricName, lbSeries.get(metricName), workflowArea);
        }
    });

    // ==================== NETWORK TAB ====================

    // Network Session Metrics
    NETWORK_SESSION_METRICS.forEach(metricKey => {
        if (sessionMetrics.has(metricKey)) {
            renderSessionMetricChart(metricKey, networkArea);
        }
    });

    // Network LB Metrics
    NETWORK_LB_METRICS.forEach(metricName => {
        if (lbSeries.has(metricName)) {
            renderLbMetricChart(metricName, lbSeries.get(metricName), networkArea);
        }
    });

    // Consolidated Drops Chart
    if (dropSeries.size > 0) {
        const chartId = 'chart-drops-consolidated';
        neededChartIds.add(chartId);

        const chartContainer = ensureChartContainer('Drops', chartId, networkArea);
        if (chartContainer) {
            const allTimestamps = new Set();
            dropSeries.forEach((data) => {
                data.forEach(point => allTimestamps.add(point.timestamp));
            });
            const timestamps = Array.from(allTimestamps).sort((a, b) => a - b).map(t => t / 1000);

            const seriesData = [timestamps];
            const seriesLabels = ['Time'];
            const seriesColors = ['transparent'];
            const dropColors = ['#EA4335', '#FF6D01', '#FBBC05', '#34A853', '#4285F4', '#46BDC6', '#7BAAF7', '#F07B72'];
            let colorIdx = 0;

            dropSeries.forEach((rawData, metricName) => {
                const data = sampleDataPoints(rawData, 500);
                const formattedName = metricName.replace('drop_', '').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                seriesLabels.push(formattedName);
                seriesColors.push(dropColors[colorIdx % dropColors.length]);
                colorIdx++;

                const values = new Array(timestamps.length).fill(null);
                data.forEach(point => {
                    const idx = timestamps.indexOf(point.timestamp / 1000);
                    if (idx !== -1) values[idx] = point.value;
                });
                seriesData.push(values);
            });

            const chartOptions = createChartOptions(chartContainer, seriesLabels, seriesColors, 'Drop Count');

            if (state.uPlotCharts[chartId]) {
                state.uPlotCharts[chartId].setData(seriesData);
            } else {
                state.uPlotCharts[chartId] = new uPlot(chartOptions, seriesData, chartContainer);
            }
        }
    }

    // Remove unused charts and DOM nodes
    Object.keys(state.uPlotCharts).forEach(chartId => {
        if (!neededChartIds.has(chartId)) {
            const chartDiv = document.getElementById(chartId);
            if (chartDiv && chartDiv.parentElement) {
                chartDiv.parentElement.remove();
            }
            state.uPlotCharts[chartId].destroy();
            delete state.uPlotCharts[chartId];
        }
    });
};

// --- Chart Update ---

const updateCharts = async (lbId) => {
    const timeseriesData = await fetchTimeseriesData(lbId);
    if (!timeseriesData) return;

    bufferTimeseriesData(timeseriesData);
    renderCharts(getBufferedTimeseriesData());
};

// --- Chart Polling ---

let chartUpdateInterval = null;

export const startChartPolling = (lbId) => {
    if (chartUpdateInterval) {
        clearInterval(chartUpdateInterval);
    }
    state.lastTimestamp = null;
    state.timeseriesBuffer = {};
    state.filteredSessionIds.clear();
    const clearReceiverFilter = document.getElementById('clear-receiver-filter');
    if (clearReceiverFilter) clearReceiverFilter.classList.add('hidden');

    // Initial update
    updateCharts(lbId);

    // Poll every 1 second
    chartUpdateInterval = setInterval(async () => {
        try {
            const data = await fetchTimeseriesData(lbId);
            if (!data) return;

            if (!data.timeseries || data.timeseries.length === 0) {
                showLbAlert(`Load Balancer ${lbId} disappeared or no data available.`);
                if (chartUpdateInterval) {
                    clearInterval(chartUpdateInterval);
                }
                return;
            }

            bufferTimeseriesData(data);
            renderCharts(getBufferedTimeseriesData());
        } catch (error) {
            console.error('Error during chart polling:', error);
        }
    }, 1000);
};

export const stopChartPolling = () => {
    if (chartUpdateInterval) {
        clearInterval(chartUpdateInterval);
        chartUpdateInterval = null;
    }
};

// --- Chart Tab Reset ---

export const resetChartTabs = () => {
    const dynamicChartsArea = document.getElementById('dynamic-charts-area');
    let workflowCharts = document.getElementById('workflow-charts');
    let networkCharts = document.getElementById('network-charts');

    if (!workflowCharts || !networkCharts) {
        dynamicChartsArea.innerHTML = `
            <div id="workflow-charts" class="chart-tab-content active">
                <div class="loading">Loading charts...</div>
            </div>
            <div id="network-charts" class="chart-tab-content">
            </div>
        `;
    } else {
        workflowCharts.innerHTML = '';
        networkCharts.innerHTML = '';
    }

    state.activeChartTab = 'workflow';
    document.querySelectorAll('.chart-tab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === 'workflow');
    });
    document.querySelectorAll('.chart-tab-content').forEach(content => {
        content.classList.toggle('active', content.id === 'workflow-charts');
    });
};

// --- Session Highlighting ---

export const highlightSession = (receiverName) => {
    let sessionId = null;
    for (const [sid, name] of Object.entries(state.sessionIdToName)) {
        if (name === receiverName) {
            sessionId = sid;
            break;
        }
    }
    if (!sessionId) return;

    Object.values(state.uPlotCharts).forEach(chart => {
        if (!chart || !chart.sessionIds) return;
        const seriesIdx = chart.sessionIds.indexOf(sessionId) + 1;
        if (seriesIdx > 0 && seriesIdx < chart.series.length) {
            chart.setSeries(seriesIdx, { focus: true });
        }
    });
};

// --- Receiver Filter ---

export const handleReceiverFilter = (sessionId) => {
    if (!sessionId) return;

    if (state.filteredSessionIds.has(sessionId)) {
        state.filteredSessionIds.delete(sessionId);
    } else {
        state.filteredSessionIds.add(sessionId);
    }

    const clearReceiverFilter = document.getElementById('clear-receiver-filter');
    if (state.filteredSessionIds.size === 0) {
        clearReceiverFilter.classList.add('hidden');
    } else {
        clearReceiverFilter.classList.remove('hidden');
    }

    // Update receiver list styling
    document.querySelectorAll('#receiver-list li').forEach(li => {
        const liSessionId = li.dataset.sessionId;
        if (state.filteredSessionIds.size === 0) {
            li.classList.remove('filtered-receiver');
        } else if (state.filteredSessionIds.has(liSessionId)) {
            li.classList.add('filtered-receiver');
        } else {
            li.classList.remove('filtered-receiver');
        }
    });

    // Re-render charts with filter applied
    renderCharts(getBufferedTimeseriesData());
};

// --- Chart Tab Switching ---

export const setupChartTabSwitching = () => {
    document.addEventListener('click', (event) => {
        const tabBtn = event.target.closest('.chart-tab');
        if (tabBtn) {
            const targetTab = tabBtn.dataset.tab;

            document.querySelectorAll('.chart-tab').forEach(btn => btn.classList.remove('active'));
            tabBtn.classList.add('active');

            document.querySelectorAll('.chart-tab-content').forEach(content => content.classList.remove('active'));
            const targetContent = document.getElementById(`${targetTab}-charts`);
            if (targetContent) {
                targetContent.classList.add('active');

                // Resize charts on the newly visible tab
                setTimeout(() => {
                    Object.entries(state.uPlotCharts).forEach(([chartId, chart]) => {
                        const chartEl = document.getElementById(chartId);
                        if (chartEl && targetContent.contains(chartEl)) {
                            const container = chartEl.parentElement;
                            if (container && container.clientWidth > 0) {
                                chart.setSize({ width: container.clientWidth, height: 350 });
                            }
                        }
                    });
                }, 10);
            }

            state.activeChartTab = targetTab;
        }
    });
};

// --- Clear Filter Button ---

export const setupClearFilter = () => {
    const clearReceiverFilter = document.getElementById('clear-receiver-filter');
    if (clearReceiverFilter) {
        clearReceiverFilter.addEventListener('click', () => {
            state.filteredSessionIds.clear();
            clearReceiverFilter.classList.add('hidden');

            document.querySelectorAll('#receiver-list li').forEach(li => {
                li.classList.remove('filtered-receiver');
            });

            renderCharts(getBufferedTimeseriesData());
        });
    }
};
