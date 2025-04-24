document.addEventListener('DOMContentLoaded', () => {
    // --- Configuration ---
    const API_BASE_URL = '/api/v1';
    const AUTH_COOKIE_NAME = 'loadBalancerAuthToken';
    const COOKIE_EXPIRY_DAYS = 7;

    // --- State ---
    let AUTH_TOKEN = null;
    let currentSelectedLbId = null;
    let activeView = 'placeholder-view';
    let uPlotCharts = {};
    let currentPath = window.location.pathname; // Store current path for comparison

    // Mapping for rendering permissions
    const ResourceTypeMap = { 0: 'All', 1: 'Load Balancer', 2: 'Reservation', 3: 'Session', default: 'Unknown Resource' };
    const PermissionTypeMap = { 0: 'Read Only', 1: 'Register', 2: 'Reserve', 3: 'Update', default: 'Unknown Permission' };

    // --- DOM Elements ---
    const lbList = document.getElementById('lb-list');
    const receiverList = document.getElementById('receiver-list');
    const mainContentArea = document.getElementById('main-content-area');
    const placeholderView = document.getElementById('placeholder-view');
    const initialLoadIndicator = document.getElementById('initial-load-indicator');
    const dashboardView = document.getElementById('dashboard-view');
    const tokenMgmtView = document.getElementById('token-management-view');
    const systemInfoView = document.getElementById('system-info-view');
    const dashboardTitle = document.getElementById('dashboard-lb-title');
    const senderListUl = document.querySelector('#sender-list ul');

    // Tool View Content/Loading Elements
    const tokenViewLoading = document.getElementById('token-view-loading');
    const tokenViewContent = document.getElementById('token-view-content');
    const currentTokenDetailsDiv = document.getElementById('current-token-details');
    const childTokensListUl = document.getElementById('child-tokens-list');
    const systemViewLoading = document.getElementById('system-view-loading');
    const systemViewContent = document.getElementById('system-view-content');
    const versionDetailsDiv = document.getElementById('version-details');

    // Buttons
    const tokenMgmtBtn = document.getElementById('token-mgmt-btn');
    const sysInfoBtn = document.getElementById('sys-info-btn');
    const addSenderBtn = document.getElementById('add-sender-btn');
    const removeSenderBtn = document.getElementById('remove-sender-btn');
    const generateChildTokenBtn = document.getElementById('generate-child-token-btn');
    const fullResetBtn = document.getElementById('full-reset-btn');
    const createTokenBtn = document.getElementById('create-token-btn'); // Added

    // Modals
    const addSenderModal = document.getElementById('add-sender-modal');
    const closeModalBtn = addSenderModal.querySelector('.close-button');
    const confirmAddSenderBtn = document.getElementById('confirm-add-sender-btn');
    const newSenderIpInput = document.getElementById('new-sender-ip');
    const authModal = document.getElementById('auth-modal');
    const authForm = document.getElementById('auth-form');
    const authInput = document.getElementById('auth-input');
    const authError = document.getElementById('auth-error');
    const authSubmitBtn = document.getElementById('auth-submit-btn');

    // --- Cookie Functions (Unchanged) ---
    const setCookie = (name, value, days) => {
        let expires = "";
        if (days) {
            const date = new Date();
            date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
            expires = "; expires=" + date.toUTCString();
        }
        document.cookie = `${name}=${value || ""}${expires}; path=/; SameSite=Lax; Secure`; // Assume HTTPS -> Secure
    };

    const getCookie = (name) => {
        const nameEQ = name + "=";
        const ca = document.cookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i].trimStart();
            if (c.startsWith(nameEQ)) return c.substring(nameEQ.length, c.length);
        }
        return null;
    };

    const eraseCookie = (name) => {
        document.cookie = `${name}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT; SameSite=Lax; Secure`; // Assume HTTPS -> Secure
    };

    // --- API Call Function (Unchanged from previous step) ---
    const apiFetch = async (endpoint, options = {}) => {
        if (!AUTH_TOKEN) {
            console.error("API call attempted without AUTH_TOKEN.");
            showAuthModal("Authentication token is missing. Please authenticate.");
            throw new Error("Authentication required");
        }
        const url = `${API_BASE_URL}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${AUTH_TOKEN}`,
            ...options.headers
        };
        try {
            const response = await fetch(url, { ...options, headers });
            if (response.status === 401 || response.status === 403) {
                console.error(`Authentication/Authorization Error (${response.status})`);
                eraseCookie(AUTH_COOKIE_NAME);
                AUTH_TOKEN = null;
                showAuthModal("Authentication failed or token expired. Please re-authenticate.");
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: 'Failed to parse error response' }));
                console.error(`API Error (${response.status}) ${options.method || 'GET'} ${endpoint}:`, errorData);
                alert(`Error: ${errorData.error || `HTTP status ${response.status}`}`);
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.status === 204 ? null : await response.json();
        } catch (error) {
            console.error(`Workspace Error ${options.method || 'GET'} ${endpoint}:`, error);
            if (!error.message.startsWith('HTTP error!') && error.message !== "Authentication required") {
                alert(`Network or fetch error: ${error.message}`);
            }
            throw error;
        }
    };

    // --- UI Update & Rendering Functions ---

    const switchView = (viewId) => {
        document.getElementById(activeView)?.classList.remove('active');
        document.getElementById(viewId)?.classList.add('active');
        activeView = viewId;
         // Clear right sidebar if not showing dashboard
         if (viewId !== 'dashboard-view') {
            receiverList.innerHTML = '<li class="no-receivers">Select an LB to see receivers.</li>';
        }
    };

    const updateActiveSidebarItem = (targetPath) => {
        document.querySelectorAll('.left-sidebar li.active, .left-sidebar .tool-button.active').forEach(el => {
            el.classList.remove('active');
        });
         if (targetPath?.startsWith('/lb/')) {
            const lbId = targetPath.split('/')[2];
            document.querySelector(`.left-sidebar li[data-lb-id="${lbId}"]`)?.classList.add('active');
        } else if (targetPath?.startsWith('/tools/')) {
             document.querySelector(`.left-sidebar .tool-button[data-target-path="${targetPath}"]`)?.classList.add('active');
        }
    };

    const renderLoadBalancers = (overviewData) => {
        lbList.innerHTML = ''; // Clear loading/previous

        // Always show all 8 load balancers
        const totalLoadBalancers = 8;

        // Create a map of active LBs from the overview data
        const activeLBMap = new Map();
        if (overviewData["load_balancers"]) {
            overviewData["load_balancers"].forEach(lbOverview => {
                if (lbOverview.reservation) {
                    const fpgaLbId = lbOverview.reservation["fpga_lb_id"];
                    activeLBMap.set(fpgaLbId, {
                        name: lbOverview.name || 'Unnamed LB',
                        reservation: lbOverview.reservation,
                        status: lbOverview.status
                    });
                }
            });
        }

        // Render all 8 load balancers
        for (let i = 0; i < totalLoadBalancers; i++) {
            const fpgaLbId = i.toString();
            const li = document.createElement('li');
            // Check if this LB has an active reservation
            const activeLB = activeLBMap.get(i);
            if (activeLB) {
                // LB has an active reservation
                const lb = activeLB.reservation;
                const status = activeLB.status;
                const name = activeLB.name;

                // Determine Status
                let statusClass = 'unreserved', statusTitle = 'Unreserved';
                let disabledClass = '';
                const expiresDate = status["expires_at"];

                if (status["workers"] && status["workers"].length) {
                    statusClass = 'active';
                    statusTitle = `Active (Expires: ${expiresDate ? new Date(expiresDate.seconds * 1000).toLocaleString() : 'N/A'})`;
                } else {
                    statusClass = 'idle';
                    statusTitle = expiresDate ?
                        `Idle (Expires: ${new Date(expiresDate.seconds * 1000).toLocaleString()})` :
                        'Idle (No expiry info)';
                    disabledClass = 'disabled-lb'; // Add disabled class
                }

                li.innerHTML = `
                    <span class="status-dot ${statusClass}" title="${statusTitle}"></span>
                    <div class="lb-info">
                        <div class="lb-name">${name} (/lb/${lb.lb_id})</div>
                        <div class="lb-details">
                            <span>IPv4: ${lb.dataIpv4Address || 'N/A'}</span>
                            <span>IPv6: ${lb.dataIpv6Address || 'N/A'}</span>
                        </div>
                    </div>
                `;
                if (disabledClass) {
                    li.classList.add(disabledClass);
                }
                li.dataset.lbId = lb.lb_id;
                li.dataset.targetPath = `/lb/${lb.lb_id}`; // For SPA navigation
            } else {
                // LB does not have an active reservation
                li.innerHTML = `
                    <span class="status-dot unreserved" title="Unreserved"></span>
                    <div class="lb-info">
                        <div class="lb-name">Load Balancer ${fpgaLbId}</div>
                        <div class="lb-details">
                            <span>IPv4: Unreserved</span>
                            <span>IPv6: Unreserved</span>
                        </div>
                    </div>
                `;
                li.classList.add('disabled-lb'); // Add disabled class
                li.dataset.lbId = null;
                li.dataset.targetPath = `/`; // For SPA navigation
            }

            lbList.appendChild(li);
        }
    };

    const renderSessions = (workers) => {
        receiverList.innerHTML = '';
        if (!workers?.length) {
            receiverList.innerHTML = '<li class="no-receivers">No active receivers.</li>';
            return;
        }
        workers.forEach(worker => {
            const li = document.createElement('li');
            const lastUpdatedSeconds = worker.last_updated?.seconds;
            const lastUpdated = lastUpdatedSeconds ? new Date(lastUpdatedSeconds * 1000).toLocaleString() : 'N/A';
            const receiverId = worker.name; // Still assuming name is usable ID

            li.innerHTML = `
                <button class="deregister-btn" data-receiver-id="${receiverId}" title="Deregister Session ${receiverId}">
                    <i class="fas fa-times"></i> Deregister
                </button>
                <div class="receiver-name">${worker.name}</div>
                <div class="receiver-details">
                    <span>IP Address: <strong>${worker.ip_address}</strong></span>
                    <span>Queue Fill: <strong>${(worker.fill_percent * 100).toFixed(1)}%</strong></span>
                    <span>Control Signal: <strong>${worker.control_signal?.toFixed(4) ?? 'N/A'}</strong></span>
                    <span>Slots: <strong>${worker.slots_assigned ?? 'N/A'}</strong></span>
                    <span>Last Update: ${lastUpdated}</span>
                </div>
            `;
            // Listener added via event delegation
            receiverList.appendChild(li);
        });
    };

    const renderSenders = (senderAddresses) => {
        senderListUl.innerHTML = '';
        if (senderAddresses?.length) {
            senderAddresses.forEach(ip => {
                const li = document.createElement('li');
                li.textContent = ip;
                senderListUl.appendChild(li);
            });
        } else {
            senderListUl.innerHTML = '<li>No senders configured.</li>';
        }
    };

     const renderChildTokens = (data) => {
         childTokensListUl.innerHTML = ''; // Clear previous
         if (!data?.tokens?.length) {
             childTokensListUl.innerHTML = '<li>No child tokens found.</li>';
             return;
         }

         data.tokens.forEach(token => {
             const { name, permissions, created_at, id, token: tokenValue } = token; // Get potential identifiers
             const createdAtDate = created_at ? new Date(created_at).toLocaleString() : 'N/A';
             // Prefer numeric ID if available, otherwise use token string itself for revoke target
             const revokeTarget = id || tokenValue || 'unknown';

             let permissionsHtml = '<span>No specific permissions found.</span>';
             if (permissions?.length) {
                 permissionsHtml = permissions.map(p => {
                     const resource = ResourceTypeMap[p.resource_type] || ResourceTypeMap.default;
                     const permission = PermissionTypeMap[p.permission] || PermissionTypeMap.default;
                     const resourceId = p.resource_id ? ` (ID: <code>${p.resource_id}</code>)` : '';
                      return `<span><strong>${permission}</strong> on <strong>${resource}</strong>${resourceId}</span>`;
                 }).join('');
             }

             const li = document.createElement('li');
             li.innerHTML = `
                 <h4>${name || 'Unnamed Token'}</h4>
                 <button class="revoke-child-btn danger-button" data-token-id="${revokeTarget}" ${revokeTarget === 'unknown' ? 'disabled title="Cannot revoke unknown token"' : 'title="Revoke this token"'}>Revoke</button>
                 <p><small>Created: ${createdAtDate}</small></p>
                 <div class="permissions-list">
                     ${permissionsHtml}
                 </div>
             `;
             childTokensListUl.appendChild(li);
         });
         // Add revoke listeners via delegation later
     };

    // --- Charting Functions ---
    const destroyAllCharts = () => {
        Object.values(uPlotCharts).forEach(chart => chart?.destroy());
        uPlotCharts = {};
    };

    // Show toast notification
    const showToast = (message, type = 'info', duration = 4000) => {
        const container = document.getElementById('toast-container');
        if (!container) {
            console.error("Toast container element not found in DOM.");
            return;
        }
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => {
            toast.classList.add('fade-out');
            toast.addEventListener('transitionend', () => {
                toast.remove();
            });
        }, duration);
    };

    // Show load balancer alert on page (non-blocking)
    const showLbAlert = (message) => {
        const lbAlertArea = document.getElementById('lb-alert-area');
        if (!lbAlertArea) {
            console.error("Load balancer alert area element not found in DOM.");
            return;
        }
        const alertDiv = document.createElement('div');
        alertDiv.className = 'lb-alert';
        alertDiv.textContent = message;
        lbAlertArea.appendChild(alertDiv);
        setTimeout(() => {
            alertDiv.classList.add('fade-out');
            alertDiv.addEventListener('transitionend', () => {
                alertDiv.remove();
            });
        }, 8000);
    };

    // Function to fetch timeseries data with since parameter support
    let lastTimestamp = null;
    const fetchTimeseriesData = async (lbId) => {
        if (!AUTH_TOKEN) return null;
        try {
            let url = `/timeseries?series=*`;
            if (lastTimestamp) {
                url += `&since=${lastTimestamp}`;
            }
            const data = await apiFetch(url);
            // Update lastTimestamp if new data present
            if (data && data.timeseries && data.timeseries.length > 0) {
                // Find max timestamp in all series
                let maxTimestamp = lastTimestamp || 0;
                data.timeseries.forEach(series => {
                    const points = series.timeseries?.FloatSamples?.data || [];
                    points.forEach(point => {
                        if (point.timestamp > maxTimestamp) {
                            maxTimestamp = point.timestamp;
                        }
                    });
                });
                lastTimestamp = maxTimestamp;
            }
            return data;
        } catch (error) {
            console.error("Failed to fetch timeseries data:", error);
            return null;
        }
    };

    // Function to update charts with real data
    const updateCharts = async (lbId) => {
        const timeseriesData = await fetchTimeseriesData(lbId);
        if (!timeseriesData) return;

        // Process the timeseries data and update charts
        renderCharts(timeseriesData);
    };

    // Set up polling for chart updates
    let chartUpdateInterval = null;

    const startChartPolling = (lbId) => {
        // Clear any existing interval
        if (chartUpdateInterval) {
            clearInterval(chartUpdateInterval);
        }
        lastTimestamp = null; // Reset lastTimestamp on new LB selection

        // Initial update
        updateCharts(lbId);

        // Set up polling every 5 seconds
        chartUpdateInterval = setInterval(async () => {
            try {
                const data = await fetchTimeseriesData(lbId);
                if (!data) return;

                // If timeseries is empty, show alert but keep charts visible
                if (!data.timeseries || data.timeseries.length === 0) {
                    showLbAlert(`Load Balancer ${lbId} disappeared or no data available.`);
                    // Do not clear charts, keep last known data visible
                    return;
                }

                renderCharts(data);
            } catch (error) {
                console.error("Error during chart polling:", error);
            }
        }, 5000);
    };

    const stopChartPolling = () => {
        if (chartUpdateInterval) {
            clearInterval(chartUpdateInterval);
            chartUpdateInterval = null;
        }
    };

    // Function to render charts with timeseries data
    const renderCharts = (timeseriesData) => {
        destroyAllCharts();

        if (!timeseriesData || !timeseriesData.timeseries || !timeseriesData.timeseries.length) {
            console.warn("No timeseries data available for charts");
            return;
        }

        // Map to store series data by session ID
        const sessionDataMap = new Map();

        // Process timeseries data
        timeseriesData.timeseries.forEach(series => {
            const name = series.name;
            const data = series.timeseries?.FloatSamples?.data || [];

            // Extract session ID from the series name if it contains session info
            const sessionMatch = name.match(/\/session\/(\d+)\//);
            const sessionId = sessionMatch ? sessionMatch[1] : null;

            if (sessionId) {
                // Group data by session ID
                if (!sessionDataMap.has(sessionId)) {
                    sessionDataMap.set(sessionId, new Map());
                }

                // Store the series data under the appropriate metric name
                const metricName = name.split('/').pop(); // Get the last part of the path
                if (metricName) {
                    sessionDataMap.get(sessionId).set(metricName, data);
                }
            }
        });

        // Create charts
        createQueueFillChart(sessionDataMap);
        createEventRateChart(sessionDataMap);
        createLatencyChart(sessionDataMap);
        createBytesReceivedChart(sessionDataMap);
        createPacketsReceivedChart(sessionDataMap);

        // Resize charts after rendering
        setTimeout(() => requestAnimationFrame(() => {
            Object.values(uPlotCharts).forEach(chart => {
                if (chart && chart.root) {
                    const rect = chart.root.getBoundingClientRect();
                    chart.setSize({ width: rect.width, height: rect.height });
                }
            });
        }), 50);
    };

    // Helper function to create a chart with session data
    const createChart = (chartId, title, sessionDataMap, metricKey, options = {}) => {
        const chartContainer = document.getElementById(chartId);
        if (!chartContainer) return;

        // Prepare data for uPlot
        const timestamps = [];
        const seriesData = [];
        const seriesLabels = ['Time'];
        const seriesColors = ['transparent']; // First series is time (x-axis)
        const sessionIds = [];

        // Add a series for each session
        sessionDataMap.forEach((metrics, sessionId) => {
            if (metrics.has(metricKey)) {
                const data = metrics.get(metricKey);
                sessionIds.push(sessionId);
                seriesLabels.push(`Session ${sessionId}`);
                seriesColors.push(getSessionColor(sessionId));

                // Extract timestamps and values
                data.forEach((point, idx) => {
                    if (idx === 0 || !timestamps.includes(point.timestamp)) {
                        timestamps.push(point.timestamp);
                    }
                });
            }
        });

        // Sort timestamps
        timestamps.sort((a, b) => a - b);

        // First series is timestamps
        seriesData.push(timestamps);

        // Add data for each session
        sessionDataMap.forEach((metrics, sessionId) => {
            if (metrics.has(metricKey)) {
                const data = metrics.get(metricKey);
                const values = new Array(timestamps.length).fill(null);

                // Map values to timestamps
                data.forEach(point => {
                    const idx = timestamps.indexOf(point.timestamp);
                    if (idx !== -1) {
                        values[idx] = point.value;
                    }
                });

                seriesData.push(values);
            }
        });

        // Default chart options
        const defaultOptions = {
            width: chartContainer.clientWidth,
            height: 300,
            series: seriesLabels.map((label, i) => ({
                label,
                stroke: seriesColors[i],
                width: i > 0 ? 2 : 0,
                points: { show: false }
            })),
            axes: [
                {}, // x-axis (time)
                {
                    label: title,
                    labelSize: 20,
                    grid: { show: true }
                }
            ],
            scales: {
                x: {
                    time: true
                }
            },
            legend: {
                show: true
            }
        };

        // Merge with custom options
        const chartOptions = { ...defaultOptions, ...options };

        // Create the chart
        const chart = new uPlot(chartOptions, seriesData, chartContainer);
        uPlotCharts[chartId] = chart;

        // Store session IDs for highlighting
        chart.sessionIds = sessionIds;

        return chart;
    };

    // Get a color for a session (for consistent coloring across charts)
    const getSessionColor = (sessionId) => {
        const colors = [
            '#4285F4', '#EA4335', '#FBBC05', '#34A853',
            '#FF6D01', '#46BDC6', '#7BAAF7', '#F07B72'
        ];
        return colors[parseInt(sessionId) % colors.length];
    };

    // Create specific charts
    const createQueueFillChart = (sessionDataMap) => {
        return createChart('queue-fill-chart', 'Queue Fill %', sessionDataMap, 'fill_percent', {
            scales: {
                y: {
                    range: [0, 1]
                }
            }
        });
    };

    const createEventRateChart = (sessionDataMap) => {
        return createChart('mean-queue-chart', 'Event Rate', sessionDataMap, 'avg_event_rate_hz');
    };

    const createLatencyChart = (sessionDataMap) => {
        return createChart('latency-chart', 'Latency', sessionDataMap, 'control_signal');
    };

    const createBytesReceivedChart = (sessionDataMap) => {
        return createChart('prediction-accuracy-chart', 'Bytes Received', sessionDataMap, 'total_bytes_recv');
    };

    const createPacketsReceivedChart = (sessionDataMap) => {
        return createChart('slot-assignments-chart', 'Packets Received', sessionDataMap, 'total_packets_recv');
    };

    // Highlight session in charts when hovering over a session in the sidebar
    const highlightSession = (sessionId) => {
        // Find all charts
        Object.values(uPlotCharts).forEach(chart => {
            if (!chart || !chart.sessionIds) return;

            // Get the series index for this session
            const seriesIdx = chart.sessionIds.indexOf(sessionId) + 1; // +1 because first series is time

            if (seriesIdx > 0) {
                // Highlight this series
                const allSeries = chart.series;

                // Reset all series to normal width
                allSeries.forEach((s, i) => {
                    if (i > 0) { // Skip time series
                        s.width = 2;
                        s.stroke = getSessionColor(chart.sessionIds[i-1]);
                    }
                });

                // Highlight the selected series
                if (allSeries[seriesIdx]) {
                    allSeries[seriesIdx].width = 4;
                }

                // Redraw the chart
                chart.redraw();
            }
        });
    };

    // Add event listeners for session highlighting
    document.addEventListener('mouseover', (event) => {
        const receiverItem = event.target.closest('#receiver-list li');
        if (receiverItem) {
            const receiverName = receiverItem.querySelector('.receiver-name')?.textContent;
            if (receiverName) {
                // Extract session ID from name if possible
                const sessionMatch = receiverName.match(/(\d+)/);
                if (sessionMatch && sessionMatch[1]) {
                    highlightSession(sessionMatch[1]);
                }
            }
        }
    });

    const renderVersionInfo = (data) => {
         if (!data) {
            versionDetailsDiv.innerHTML = '<p>Error loading version info.</p>';
            return;
        }
         versionDetailsDiv.innerHTML = `
            <p><strong>Build:</strong> ${data.build || 'N/A'}</p>
            <p><strong>Commit:</strong> <code>${data.commit || 'N/A'}</code></p>
            <p><strong>Compatible With:</strong> ${data.compat_tag || data.compatTag || 'N/A'}</p>
        `; // Check both snake_case and camelCase if API response varies
    };

     const renderTokenPermissions = (data) => {
         if (!data?.token) {
             currentTokenDetailsDiv.innerHTML = '<p>Error loading token details.</p>';
             return;
         }
         const { name, permissions, created_at } = data.token;
         const createdAtDate = created_at ? new Date(created_at).toLocaleString() : 'N/A'; // Assuming ISO string

         let permissionsHtml = '<p>No specific permissions found.</p>';
         if (permissions?.length) {
             permissionsHtml = permissions.map(p => {
                 const resource = ResourceTypeMap[p.resource_type] || ResourceTypeMap.default;
                 const permission = PermissionTypeMap[p.permission] || PermissionTypeMap.default;
                 const resourceId = p.resource_id ? ` (ID: <code>${p.resource_id}</code>)` : '';
                 return `<li><strong>${permission}</strong> on <strong>${resource}</strong>${resourceId}</li>`;
             }).join('');
             permissionsHtml = `<ul class="permissions-list">${permissionsHtml}</ul>`;
         }

         currentTokenDetailsDiv.innerHTML = `
            <p><strong>Name:</strong> ${name || 'Unnamed'}</p>
            <p><strong>Created:</strong> ${createdAtDate}</p>
            <h4>Permissions:</h4>
            ${permissionsHtml}
        `;
     };


    // Update the showDashboardView function to use the new chart polling


    // --- View Loading Functions (Handle showing/hiding loading indicators) ---

    const showDashboardView = async (lbId) => {
        // Stop any existing chart polling
        stopChartPolling();

        if (currentSelectedLbId === lbId && activeView === 'dashboard-view') return;
        currentSelectedLbId = lbId;
        switchView('dashboard-view');
        dashboardTitle.textContent = `Loading Dashboard for ${lbId}...`;
        receiverList.innerHTML = '<li class="loading">Loading receivers...</li>';
        senderListUl.innerHTML = '<li class="loading">Loading senders...</li>';
        destroyAllCharts();

        try {
             const statusData = await apiFetch(`/lb/${lbId}/status`);
             dashboardTitle.textContent = `Dashboard: ${lbId}`;
             renderSessions(statusData.workers);
             renderSenders(statusData.senderAddresses);

             // Start polling for chart updates
             startChartPolling(lbId);
        } catch (error) {
            dashboardTitle.textContent = `Error loading dashboard for ${lbId}`;
            receiverList.innerHTML = '<li class="no-receivers">Error loading receivers.</li>';
            senderListUl.innerHTML = '<li>Error loading senders.</li>';
        }
    };

    const showTokenManagementView = async () => {
        currentSelectedLbId = null;
        switchView('token-management-view');
        tokenViewLoading.style.display = 'block';
        tokenViewContent.style.display = 'none';
        currentTokenDetailsDiv.innerHTML = ''; // Clear previous
        childTokensListUl.innerHTML = ''; // Clear previous

        try {
            // Fetch permissions and child tokens in parallel
            const [permissionsData, childrenData] = await Promise.all([
                apiFetch('/tokens/self/permissions'),
                apiFetch('/tokens/self/children')
            ]);
            renderTokenPermissions(permissionsData);
            renderChildTokens(childrenData);
        } catch (error) {
            console.error("Failed to load token management data:", error);
            currentTokenDetailsDiv.innerHTML = '<p>Error loading token details.</p>';
            childTokensListUl.innerHTML = '<li>Error loading child tokens.</li>';
        } finally {
             tokenViewLoading.style.display = 'none';
             tokenViewContent.style.display = 'block';
        }
    };

     const showSystemInfoView = async () => {
        currentSelectedLbId = null;
        switchView('system-info-view');
        systemViewLoading.style.display = 'block';
        systemViewContent.style.display = 'none';
        versionDetailsDiv.innerHTML = ''; // Clear previous

        try {
            const versionData = await apiFetch('/version');
            renderVersionInfo(versionData);
        } catch (error) {
            console.error("Failed to load system info:", error);
            renderVersionInfo(null); // Show error state
        } finally {
            systemViewLoading.style.display = 'none';
            systemViewContent.style.display = 'block';
        }
    };


    // --- Event Handlers ---
    // Note: Specific data loading moved to show*View functions

    // Event delegation for dynamically added items
    document.addEventListener('click', (event) => {
        // Left Sidebar LB items
        const lbItem = event.target.closest('.left-sidebar li[data-target-path]');
        if (lbItem && lbItem.dataset.targetPath) {
             event.preventDefault();
             navigateTo(lbItem.dataset.targetPath);
             return; // Handled
        }

        // Left Sidebar Tool buttons
         const toolButton = event.target.closest('.left-sidebar button[data-target-path]');
         if (toolButton && toolButton.dataset.targetPath) {
            event.preventDefault();
             navigateTo(toolButton.dataset.targetPath);
            return; // Handled
        }

        // Deregister Session buttons
        const deregisterBtn = event.target.closest('.deregister-btn[data-receiver-id]');
        if (deregisterBtn) {
            event.stopPropagation(); // Prevent other clicks
            handleDeregisterSession(deregisterBtn.dataset.receiverId);
            return; // Handled
        }

         // Revoke Child Token buttons
        const revokeBtn = event.target.closest('.revoke-child-btn[data-token-id]');
        if (revokeBtn) {
             handleRevokeToken(revokeBtn.dataset.tokenId);
            return; // Handled
        }

        // Add Sender Button
        if (event.target.closest('#add-sender-btn')) {
            handleAddSender();
            return;
        }
         // Remove Sender Button
        if (event.target.closest('#remove-sender-btn')) {
            handleRemoveSender();
            return;
        }
        // Generate Child Token Button
        if (event.target.closest('#generate-child-token-btn')) {
            handleGenerateChildToken();
            return;
        }
         // Full Reset Button
        if (event.target.closest('#full-reset-btn')) {
            handleFullReset();
            return;
        }
         // Create Token WIP Button
        if (event.target.closest('#create-token-btn')) {
             alert("Token creation UI not yet implemented.");
             return;
        }

        // Add Sender Modal Close/Confirm
        if (event.target === closeModalBtn) {
             addSenderModal.style.display = 'none';
             return;
        }
        if (event.target === confirmAddSenderBtn) {
            handleConfirmAddSender();
             return;
        }
        // Close modal on outside click
        if (event.target === addSenderModal) {
             addSenderModal.style.display = 'none';
            return;
        }
    });


    const handleDeregisterSession = async (receiverId) => { /* ... as before, ensure AUTH_TOKEN check is implicit via apiFetch ... */
         if (!receiverId) return alert("Error: Session ID missing.");
         if (!confirm(`Deregister receiver "${receiverId}"?`)) return;
         console.log(`Attempting to deregister receiver: ${receiverId}`);
         try {
            await apiFetch(`/receivers/${receiverId}`, { method: 'DELETE' });
            alert(`Session ${receiverId} deregistered successfully.`);
            if (currentSelectedLbId) { // Refresh if dashboard is visible
                const statusData = await apiFetch(`/lb/${currentSelectedLbId}/status`);
                renderSessions(statusData.workers);
            }
         } catch (error) { /* Handled by apiFetch */ }
    };

    const handleRevokeToken = async (tokenIdOrToken) => { /* ... as before ... */
        if (!tokenIdOrToken || tokenIdOrToken === 'unknown') return alert('Error: Token identifier missing or invalid.');
        if (!confirm(`Revoke token "${tokenIdOrToken}" and its children? This is irreversible.`)) return;
         console.log("Revoking token:", tokenIdOrToken);
         try {
             await apiFetch(`/tokens/${tokenIdOrToken}`, { method: 'DELETE' });
             alert(`Token ${tokenIdOrToken} revoked successfully.`);
             // Refresh token view data if currently visible
             if (activeView === 'token-management-view') {
                 // Re-fetch both permissions and children
                 const [permissionsData, childrenData] = await Promise.all([
                    apiFetch('/tokens/self/permissions'),
                    apiFetch('/tokens/self/children')
                 ]);
                 renderTokenPermissions(permissionsData);
                 renderChildTokens(childrenData);
             }
         } catch (error) { /* Handled by apiFetch */ }
    };

    const handleAddSender = () => { /* ... as before, ensure AUTH_TOKEN check implicit ... */
         if (!currentSelectedLbId) return alert("Select a Load Balancer first.");
         newSenderIpInput.value = '';
         addSenderModal.style.display = 'block';
    };
    const handleConfirmAddSender = async () => { /* ... as before ... */
        const ipToAdd = newSenderIpInput.value.trim();
        if (!ipToAdd) return alert("Please enter an IP address.");
        if (!currentSelectedLbId) return alert("Error: No Load Balancer selected.");
        console.log(`Adding sender ${ipToAdd} to LB ${currentSelectedLbId}`);
         try {
            await apiFetch(`/lb/${currentSelectedLbId}/senders`, { method: 'POST', body: JSON.stringify({ sender_addresses: [ipToAdd] }) });
             alert(`Sender ${ipToAdd} added successfully.`);
             addSenderModal.style.display = 'none';
             const statusData = await apiFetch(`/lb/${currentSelectedLbId}/status`); // Refresh list
             renderSenders(statusData.senderAddresses);
         } catch(error) { addSenderModal.style.display = 'none'; /* Handled by apiFetch */ }
    };
    const handleRemoveSender = async () => { /* ... as before ... */
        if (!currentSelectedLbId) return alert("Select a Load Balancer first.");
         const ipToRemove = prompt(`Enter Sender IP to remove from LB ${currentSelectedLbId}:`);
         if (!ipToRemove) return;
         if (!confirm(`Remove sender ${ipToRemove}?`)) return;
         console.log(`Removing sender ${ipToRemove} from LB ${currentSelectedLbId}`);
         try {
            await apiFetch(`/lb/${currentSelectedLbId}/senders`, { method: 'DELETE', body: JSON.stringify({ sender_addresses: [ipToRemove] }) });
            alert(`Sender ${ipToRemove} removed.`);
            const statusData = await apiFetch(`/lb/${currentSelectedLbId}/status`); // Refresh list
            renderSenders(statusData.senderAddresses);
         } catch(error) { console.error("Failed to remove sender:", error); }
    };
    const handleGenerateChildToken = async () => { /* ... as before ... */
        const tokenName = prompt("Enter name for new child token (basic read-only permissions):");
        if (!tokenName) return;
        const basicPermissions = [{ resource_type: 0, resource_id: '*', permission: 0 }];
        try {
           const reply = await apiFetch('/tokens', { method: 'POST', body: JSON.stringify({ name: tokenName, permissions: basicPermissions }) });
            alert(`Child token created:\n\n${reply.token}\n\nStore securely!`);
            if (activeView === 'token-management-view') { // Refresh child list if visible
                 const childrenData = await apiFetch('/tokens/self/children');
                 renderChildTokens(childrenData);
            }
        } catch(error) { console.error("Failed to create child token:", error); }
    };
    const handleFullReset = async () => { /* ... as before, minor cleanup ... */
        if (!currentSelectedLbId) return alert("Select a Load Balancer to reset.");
        if (!confirm(`FULL RESET: Deregister ALL receivers and remove ALL senders for LB ${currentSelectedLbId}? IRREVERSIBLE.`)) return;
        console.warn(`Performing FULL RESET on LB: ${currentSelectedLbId}`);
        alert('Starting FULL RESET...');
         try {
            const statusData = await apiFetch(`/lb/${currentSelectedLbId}/status`);
            const workers = statusData.workers || [];
            const senders = statusData.senderAddresses || [];
            // Deregister workers
            console.log(`Deregistering ${workers.length} workers...`);
            const deregPromises = workers.map(w => apiFetch(`/receivers/${w.name}`, { method: 'DELETE' }).catch(err => console.error(`Failed deregister ${w.name}:`, err)));
            await Promise.allSettled(deregPromises);
            console.log("Finished worker deregistration attempt.");
            // Remove senders
            if (senders.length > 0) {
                console.log(`Removing ${senders.length} senders...`);
                await apiFetch(`/lb/${currentSelectedLbId}/senders`, { method: 'DELETE', body: JSON.stringify({ sender_addresses: senders }) });
                console.log("Finished removing senders.");
            }
             alert(`FULL RESET attempt complete for LB ${currentSelectedLbId}.`);
             // Refresh UI
             const finalStatus = await apiFetch(`/lb/${currentSelectedLbId}/status`);
             renderSessions(finalStatus.workers);
             renderSenders(finalStatus.senders);
        } catch (error) { console.error("Error during FULL RESET:", error); alert(`Error during FULL RESET: ${error.message}.`); }
    };


    // --- Authentication Flow (Updated EJFAT Parsing) ---
    const showAuthModal = (errorMessage = null) => { /* ... as before ... */
        console.log("Authentication required. Showing modal.");
        authInput.value = '';
        authError.textContent = errorMessage || '';
        authError.style.display = errorMessage ? 'block' : 'none';
        authModal.style.display = 'block';
         authInput.focus();
    };
    const hideAuthModal = () => { /* ... as before ... */
        authModal.style.display = 'none';
        authError.style.display = 'none';
    };

    const extractTokenFromInput = (inputValue) => {
        const trimmedValue = inputValue.trim();
        try {
            // Check for EJFAT URI specifically
            if (trimmedValue.toLowerCase().startsWith('ejfats://')) {
                const url = new URL(trimmedValue);
                // Token is in the 'username' part for ejfats://token@host...
                if (url.username) {
                     console.log("Extracted token from EJFAT URI username.");
                    return url.username; // The part before '@'
                } else {
                    console.warn("EJFAT URI detected but no token found in username part.");
                    return null;
                }
            }

            // If not EJFAT, check if it's a regular URL with ?token= param
            const url = new URL(trimmedValue);
            const tokenParam = url.searchParams.get('token');
            if (tokenParam) {
                console.log("Extracted token from URL parameter.");
                return tokenParam.trim();
            }
        } catch (_) {
            // If not a valid URL (of any kind we parse), treat as raw token.
            // Remove Bearer prefix if present. Basic length check.
            if (trimmedValue.length > 10) {
                console.log("Treating input as raw token.");
                return trimmedValue.startsWith('Bearer ') ? trimmedValue.substring(7) : trimmedValue;
            }
        }
        // If none of the above matched
        return null;
    };

    const handleAuthSubmit = async (event) => { /* ... mostly as before ... */
        event.preventDefault();
        authError.style.display = 'none';
        authSubmitBtn.disabled = true;
        authSubmitBtn.textContent = 'Authenticating...';

        const inputValue = authInput.value;
        const extractedToken = extractTokenFromInput(inputValue);

        if (!extractedToken) {
            authError.textContent = 'Invalid input. Enter token or ejfats://token@host...';
            authError.style.display = 'block';
            authSubmitBtn.disabled = false;
            authSubmitBtn.textContent = 'Authenticate';
            return;
        }

        AUTH_TOKEN = extractedToken; // Tentatively set token
        console.log("Attempting authentication with extracted token...");

        try {
             await apiFetch('/version'); // Use /version as a lightweight validation endpoint
             console.log("Authentication successful.");
             setCookie(AUTH_COOKIE_NAME, AUTH_TOKEN, COOKIE_EXPIRY_DAYS);
             hideAuthModal();
             initializeApp(); // Start the main app loading process *after* auth success

        } catch (error) {
             console.error("Authentication test failed:", error.message);
             // apiFetch handles showing modal again on auth error
        } finally {
             if (authModal.style.display === 'block') { // Re-enable button only if modal is still shown
                authSubmitBtn.disabled = false;
                authSubmitBtn.textContent = 'Authenticate';
            }
        }
    };

    // --- SPA Routing ---

    const navigateTo = (path, replace = false) => {
        if (!AUTH_TOKEN) return showAuthModal("Please authenticate first."); // Don't navigate if not logged in

        // Check if the target is a disabled LB
        const targetElement = document.querySelector(`.left-sidebar li[data-target-path="${path}"]`);
        if (targetElement && targetElement.classList.contains('disabled-lb')) {
            console.log("Navigation prevented: Target LB is disabled.");
            return; // Do not navigate
        }

        // Prevent pushing the same path multiple times consecutively
        if (path === currentPath && !replace) return;

        console.log(`Navigating to: ${path}`);
        currentPath = path;

        // Update browser history
        const state = { path: path };
        if (replace) {
            history.replaceState(state, '', path);
        } else {
             history.pushState(state, '', path);
        }

        // Handle the route change to update the UI
        handleRouteChange(path);
    };

    const handleRouteChange = (path) => {
         if (!AUTH_TOKEN) { // Should ideally not happen if navigateTo checks, but belt-and-suspenders
            checkAuth(); // Re-run auth check if route changes while unauthed
            return;
         }

        updateActiveSidebarItem(path);

        // Basic routing logic based on path segments
        const segments = path.split('/').filter(Boolean); // Filter out empty strings

        if (segments.length === 0) { // Root path "/"
             switchView('placeholder-view');
             currentSelectedLbId = null;
        } else if (segments[0] === 'lb' && segments[1]) {
            // Load Balancer Detail View
            const lbId = segments[1];
            showDashboardView(lbId);
        } else if (segments[0] === 'tools') {
            if (segments[1] === 'tokens') {
                // Token Management View
                showTokenManagementView();
            } else if (segments[1] === 'system') {
                // System Info View
                showSystemInfoView();
            } else {
                 // Unknown tool, show placeholder
                switchView('placeholder-view');
                currentSelectedLbId = null;
            }
        } else {
             // Unknown path, show placeholder
             switchView('placeholder-view');
             currentSelectedLbId = null;
        }
    };

    const handlePopState = (event) => {
        // Handle browser back/forward button clicks
        const path = event.state?.path || window.location.pathname;
        console.log(`Handling popstate to: ${path}`);
        currentPath = path; // Update internal state
        handleRouteChange(path);
    };

    // Add popstate listener
    window.addEventListener('popstate', handlePopState);


    // Set up polling for overview data
    let overviewUpdateInterval = null;

    const startOverviewPolling = () => {
        // Clear any existing interval
        if (overviewUpdateInterval) {
            clearInterval(overviewUpdateInterval);
        }

        // Initial update is done in initializeApp

        // Set up polling every 5 seconds
        overviewUpdateInterval = setInterval(async () => {
            try {
                const overviewData = await apiFetch('/overview');
                renderLoadBalancers(overviewData);

                // If we're on a dashboard view, update the session info for the current LB
                if (activeView === 'dashboard-view' && currentSelectedLbId) {
                    const activeLB = overviewData.load_balancers?.find(lb =>
                        lb.reservation && lb.reservation.lb_id === currentSelectedLbId);

                    if (activeLB && activeLB.status) {
                        renderSessions(activeLB.status.workers || []);
                        renderSenders(activeLB.status.senderAddresses || []);
                    }
                }
            } catch (error) {
                console.error("Failed to update overview data:", error);
            }
        }, 5000); // Update every 5 seconds
    };

    const stopOverviewPolling = () => {
        if (overviewUpdateInterval) {
            clearInterval(overviewUpdateInterval);
            overviewUpdateInterval = null;
        }
    };

    // --- Initialization ---

    // Loads essential data and sets up non-route-specific listeners
    const initializeApp = async () => {
        console.log("Initializing authenticated application...");
        initialLoadIndicator.style.display = 'block'; // Show loading

        // Load initial LB list for the sidebar
        try {
            const overviewData = await apiFetch('/overview');
            renderLoadBalancers(overviewData);

            // Start polling for overview updates
            startOverviewPolling();
        } catch (error) {
            lbList.innerHTML = '<li class="no-receivers">Error loading LBs.</li>';
            console.error("Failed to load overview on init:", error);
            // Proceed without LB list for now, maybe show error to user
        }

        // Setup non-dynamic listeners (auth modal handled separately)
        // Event delegation handles most dynamic elements now

        // Handle initial route based on URL path
        handleRouteChange(window.location.pathname);
        initialLoadIndicator.style.display = 'none'; // Hide loading
    };

    // Checks auth status and starts the appropriate flow
    const checkAuth = () => {
        console.log("Checking authentication...");
        const tokenFromCookie = getCookie(AUTH_COOKIE_NAME);
        if (tokenFromCookie) {
            console.log("Found auth token cookie.");
            AUTH_TOKEN = tokenFromCookie; // Tentatively set token
            // Validate token by making a lightweight API call
            apiFetch('/version').then(() => {
                console.log("Token validated successfully.");
                initializeApp(); // Token is valid, start the main app
            }).catch(error => {
                 console.error("Token validation failed on load:", error.message);
                 // apiFetch should have handled clearing cookie & showing modal if it was 401/403
                 if (!authModal.style.display || authModal.style.display === 'none') {
                     showAuthModal("Your receiver may have expired. Please re-authenticate.");
                 }
            });
        } else {
            console.log("No auth token cookie found.");
            showAuthModal(); // Show login if no token
        }
    };

    // --- Start the Application ---
    authForm.addEventListener('submit', handleAuthSubmit); // Auth form listener
    checkAuth(); // Start the authentication check on page load

}); // End DOMContentLoaded
