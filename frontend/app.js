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
    let chartMetrics = {}; // Store available metrics for chart generation
let sessionIdToName = {}; // Map session ID to receiver name for chart labeling/highlighting

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
    const dynamicChartsArea = document.getElementById('dynamic-charts-area');
    const newSenderIpInput = document.getElementById('new-sender-ip');

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
    const generateChildTokenBtn = document.getElementById('generate-child-token-btn');
    const fullResetBtn = document.getElementById('full-reset-btn');

    // --- Token Creation UI Elements ---
    const createTokenCard = document.getElementById('create-token-card');
    const createTokenForm = document.getElementById('create-token-form');
    const newTokenNameInput = document.getElementById('new-token-name');
    const permissionsListDiv = document.getElementById('permissions-list');
    const addPermissionBtn = document.getElementById('add-permission-btn');
    const createTokenResultDiv = document.getElementById('create-token-result');

    // Modals
    const authModal = document.getElementById('auth-modal');
    const authForm = document.getElementById('auth-form');
    const authInput = document.getElementById('auth-input');
    const authError = document.getElementById('auth-error');
    const authSubmitBtn = document.getElementById('auth-submit-btn');

    // --- Cookie Functions ---
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

    // --- API Call Function ---
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
                showToast(`Error: ${errorData.error || `HTTP status ${response.status}`}`);
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.status === 204 ? null : await response.json();
        } catch (error) {
            console.error(`Workspace Error ${options.method || 'GET'} ${endpoint}:`, error);
            if (!error.message.startsWith('HTTP error!') && error.message !== "Authentication required") {
                showToast(`Network or fetch error: ${error.message}`);
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
    sessionIdToName = {}; // Reset mapping each time
    if (!workers?.length) {
        receiverList.innerHTML = '<li class="no-receivers">No active receivers.</li>';
        return;
    }
    workers.forEach(worker => {
        const li = document.createElement('li');
        const lastUpdatedSeconds = worker.last_updated?.seconds;
        const lastUpdated = lastUpdatedSeconds ? new Date(lastUpdatedSeconds * 1000).toLocaleString() : 'N/A';
        const receiverId = worker.name; // Still assuming name is usable ID

        // Map session ID (worker.session_id or fallback) to receiver name
        let sessionId = null;
        if (worker.session_id !== undefined) {
            sessionId = String(worker.session_id);
        } else {
            // Try to extract a number from the name (e.g., "Session 13" or "13")
            const match = worker.name && worker.name.match(/(\d+)/);
            if (match) sessionId = match[1];
        }
        if (sessionId) {
            sessionIdToName[sessionId] = worker.name;
        }

        // --- Color mapping functions ---
        function getQueueFillColor(fillPercent) {
            // fillPercent: 0.0 to 1.0
            if (fillPercent === 0) return '#fff';
            if (fillPercent <= 0.001) return '#fff';
            if (fillPercent <= 0.0011) return '#00ff00'; // 0.1% = green
            // 0.1% (0.001) = green, 100% (1.0) = red, gradient in between
            // We'll interpolate from green (0.001) to red (1.0)
            // 0.001 = green (#00ff00), 0.8 = red (#ff0000)
            // Use white for 0
            if (fillPercent < 0.001) return '#fff';
            // Linear interpolation between green and red
            // t = (fillPercent - 0.001) / (1.0 - 0.001)
            const t = Math.max(0, Math.min(1, (fillPercent - 0.001) / (0.8 - 0.001)));
            // Interpolate RGB
            const r = Math.round(0 + t * (255 - 0));
            const g = Math.round(255 - t * 255);
            const b = 0;
            return `rgb(${r},${g},${b})`;
        }

        function getControlSignalColor(signal) {
            // signal: -50 (red) to 0 (white) to +50 (green)
            if (signal === 0) return '#fff';
            if (signal <= -50) return '#ff0000';
            if (signal >= 50) return '#00ff00';
            // Interpolate: -50 to 0 = red to white, 0 to +50 = white to green
            if (signal < 0) {
                // t = (signal + 50) / 50, from 0 (at -50) to 1 (at 0)
                const t = (signal + 50) / 50;
                // Red to white: #ff0000 to #ffffff
                const r = 255;
                const g = Math.round(0 + t * 255);
                const b = Math.round(0 + t * 255);
                return `rgb(${r},${g},${b})`;
            } else {
                // t = signal / 50, from 0 (at 0) to 1 (at +50)
                const t = signal / 50;
                // White to green: #ffffff to #00ff00
                const r = Math.round(255 - t * 255);
                const g = 255;
                const b = Math.round(255 - t * 255);
                return `rgb(${r},${g},${b})`;
            }
        }

        const fillPercent = worker.fill_percent ?? 0;
        const controlSignal = worker.control_signal ?? 0;

        li.innerHTML = `
            <button class="deregister-btn" data-receiver-id="${receiverId}" title="Deregister Session ${receiverId}">
                <i class="fas fa-times"></i> Deregister
            </button>
            <div class="receiver-name">${worker.name}</div>
            <div class="receiver-details">
                <span>IP Address: <strong>${worker.ip_address}</strong></span>
                <span>Queue Fill: <strong style="color: ${getQueueFillColor(fillPercent)}">${(fillPercent * 100).toFixed(1)}%</strong></span>
                <span>Control Signal: <strong style="color: ${getControlSignalColor(controlSignal)}">${worker.control_signal?.toFixed(4) ?? 'N/A'}</strong></span>
                <span>Slots: <strong>${worker.slots_assigned ?? 'N/A'}</strong></span>
                <span>Last Update: ${lastUpdated}</span>
            </div>
        `;
        // Attach direct event listener to the deregister button
        const deregBtn = li.querySelector('.deregister-btn[data-receiver-id]');
        if (deregBtn) {
            deregBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                handleDeregisterSession(receiverId);
            });
        }
        receiverList.appendChild(li);
    });
};

    const renderSenders = (senderAddresses) => {
        senderListUl.innerHTML = '';
        if (senderAddresses?.length) {
            senderAddresses.forEach(ip => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <span>${ip}</span>
                    <button class="delete-sender" data-ip="${ip}" title="Remove sender">
                        <i class="fas fa-trash"></i>
                    </button>
                `;
                // Attach direct event listener to the delete sender button
                const deleteBtn = li.querySelector('.delete-sender[data-ip]');
                if (deleteBtn) {
                    deleteBtn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        handleRemoveSender(ip);
                    });
                }
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
            // Attach direct event listener to the revoke button
            const revokeBtn = li.querySelector('.revoke-child-btn[data-token-id]');
            if (revokeBtn && revokeTarget !== 'unknown') {
                revokeBtn.addEventListener('click', () => {
                    handleRevokeToken(revokeTarget);
                });
            }
            childTokensListUl.appendChild(li);
        });
    };

    const renderVersionInfo = (data) => {
        if (!data) {
            versionDetailsDiv.innerHTML = '<p>Error loading version info.</p>';
            return;
        }
        versionDetailsDiv.innerHTML = `
            <p><strong>Build:</strong> ${data.build || 'N/A'}</p>
            <p><strong>Commit:</strong> <code>${data.commit || 'N/A'}</code></p>
            <p><strong>Compatible With:</strong> ${data.compat_tag || data.compatTag || 'N/A'}</p>
        `;
    };

    const renderTokenPermissions = (data) => {
        if (!data?.token) {
            currentTokenDetailsDiv.innerHTML = '<p>Error loading token details.</p>';
            return;
        }
        const { name, permissions, created_at } = data.token;
        const createdAtDate = created_at ? new Date(created_at).toLocaleString() : 'N/A';

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

    // --- Timeseries Buffer for Appending Data ---
    // Buffer to store all timeseries data by series name
    let timeseriesBuffer = {};
    let lastTimestamp = null;

    // Function to fetch timeseries data with since parameter support
    const fetchTimeseriesData = async (lbId) => {
        if (!AUTH_TOKEN) return null;
        try {
            let url = `/timeseries?series=*`;
            if (lastTimestamp) {
                // Convert timestamp from ms since epoch to RFC3339 format
                const date = new Date(lastTimestamp);
                const rfc3339Timestamp = date.toISOString();
                url += `&since=${rfc3339Timestamp}`;
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

        // --- Buffering logic: append new data to buffer, keep up to 5 minutes ---
        const FIVE_MINUTES_MS = 5 * 60 * 1000;
        if (timeseriesData && timeseriesData.timeseries && timeseriesData.timeseries.length > 0) {
            timeseriesData.timeseries.forEach(series => {
                const name = series.name;
                const newPoints = series.timeseries?.FloatSamples?.data || [];
                if (!timeseriesBuffer[name]) {
                    timeseriesBuffer[name] = [];
                }
                // Append new points, deduplicate by timestamp
                const existingTimestamps = new Set(timeseriesBuffer[name].map(p => p.timestamp));
                newPoints.forEach(point => {
                    if (!existingTimestamps.has(point.timestamp)) {
                        timeseriesBuffer[name].push(point);
                    }
                });
                // Sort by timestamp
                timeseriesBuffer[name].sort((a, b) => a.timestamp - b.timestamp);
                // If more than 5 minutes of data, trim old points
                if (timeseriesBuffer[name].length > 0) {
                    const latestTs = timeseriesBuffer[name][timeseriesBuffer[name].length - 1].timestamp;
                    const minTs = latestTs - FIVE_MINUTES_MS;
                    // Only trim if window exceeds 5 minutes
                    if (timeseriesBuffer[name][0].timestamp < minTs) {
                        // Only start trimming after 5 minutes of data
                        timeseriesBuffer[name] = timeseriesBuffer[name].filter(p => p.timestamp >= minTs);
                    }
                }
            });
        }

        // Build a timeseriesData-like object from the buffer for rendering
        const bufferedTimeseriesData = {
            timeseries: Object.entries(timeseriesBuffer).map(([name, data]) => ({
                name,
                timeseries: { FloatSamples: { data } }
            }))
        };

        renderCharts(bufferedTimeseriesData);
    };

    // Set up polling for chart updates
    let chartUpdateInterval = null;

    const startChartPolling = (lbId) => {
        // Clear any existing interval
        if (chartUpdateInterval) {
            clearInterval(chartUpdateInterval);
        }
        lastTimestamp = null; // Reset lastTimestamp on new LB selection
        timeseriesBuffer = {}; // Reset buffer on new LB selection

        // Initial update
        updateCharts(lbId);

        // Set up polling every 1 second (faster updates)
        chartUpdateInterval = setInterval(async () => {
            try {
                const data = await fetchTimeseriesData(lbId);
                if (!data) return;

                // If timeseries is empty, show alert but keep charts visible
                if (!data.timeseries || data.timeseries.length === 0) {
                    showLbAlert(`Load Balancer ${lbId} disappeared or no data available.`);
                    if (chartUpdateInterval) {
                        clearInterval(chartUpdateInterval);
                    }
                    // Do not clear charts, keep last known data visible
                    return;
                }

                // --- Buffering logic: append new data to buffer, keep up to 5 minutes ---
                const FIVE_MINUTES_MS = 5 * 60 * 1000;
                data.timeseries.forEach(series => {
                    const name = series.name;
                    const newPoints = series.timeseries?.FloatSamples?.data || [];
                    if (!timeseriesBuffer[name]) {
                        timeseriesBuffer[name] = [];
                    }
                    // Append new points, deduplicate by timestamp
                    const existingTimestamps = new Set(timeseriesBuffer[name].map(p => p.timestamp));
                    newPoints.forEach(point => {
                        if (!existingTimestamps.has(point.timestamp)) {
                            timeseriesBuffer[name].push(point);
                        }
                    });
                    // Sort by timestamp
                    timeseriesBuffer[name].sort((a, b) => a.timestamp - b.timestamp);
                    // If more than 5 minutes of data, trim old points
                    if (timeseriesBuffer[name].length > 0) {
                        const latestTs = timeseriesBuffer[name][timeseriesBuffer[name].length - 1].timestamp;
                        const minTs = latestTs - FIVE_MINUTES_MS;
                        // Only trim if window exceeds 5 minutes
                        if (timeseriesBuffer[name][0].timestamp < minTs) {
                            // Only start trimming after 5 minutes of data
                            timeseriesBuffer[name] = timeseriesBuffer[name].filter(p => p.timestamp >= minTs);
                        }
                    }
                });

                // Build a timeseriesData-like object from the buffer for rendering
                const bufferedTimeseriesData = {
                    timeseries: Object.entries(timeseriesBuffer).map(([name, data]) => ({
                        name,
                        timeseries: { FloatSamples: { data } }
                    }))
                };

                renderCharts(bufferedTimeseriesData);
            } catch (error) {
                console.error("Error during chart polling:", error);
            }
        }, 1000);
    };

    const stopChartPolling = () => {
        if (chartUpdateInterval) {
            clearInterval(chartUpdateInterval);
            chartUpdateInterval = null;
        }
    };

    // Function to organize timeseries data by type
    const organizeTimeseriesData = (timeseriesData) => {
        if (!timeseriesData || !timeseriesData.timeseries || !timeseriesData.timeseries.length) {
            return null;
        }

        // Reset chart metrics
        chartMetrics = {
            sessions: new Map(), // Session metrics by session ID
            reservation: new Map(), // Reservation metrics
            prediction: {
                boundary_event: null,
                event_number: null
            }
        };

        // Process timeseries data
        timeseriesData.timeseries.forEach(series => {
            const name = series.name;
            const data = series.timeseries?.FloatSamples?.data || [];

            // Skip empty series
            if (!data.length) return;

            // Extract session ID from the series name if it contains session info
            const sessionMatch = name.match(/\/session\/(\d+)\//);
            if (sessionMatch) {
                const sessionId = sessionMatch[1];

                // Group data by session ID
                if (!chartMetrics.sessions.has(sessionId)) {
                    chartMetrics.sessions.set(sessionId, new Map());
                }

                // Store the series data under the appropriate metric name
                const metricName = name.split('/').pop(); // Get the last part of the path
                if (metricName) {
                    chartMetrics.sessions.get(sessionId).set(metricName, data);
                }
            } else if (name.includes('/epoch/boundary_event')) {
                // Store epoch boundary event data for prediction accuracy
                chartMetrics.prediction.boundary_event = data;
            } else if (name.includes('/event_number')) {
                // Store event number data for prediction accuracy
                chartMetrics.prediction.event_number = data;
            } else if (name.includes('/reservation/')) {
                // Store reservation metrics
                const metricName = name.split('/').pop();
                if (metricName) {
                    chartMetrics.reservation.set(metricName, data);
                }
            }
        });

        return chartMetrics;
    };

    // Create a chart container
    const createChartContainer = (title, id) => {
        const container = document.createElement('div');
        container.className = 'chart-container';
        container.innerHTML = `
            <h3>${title}</h3>
            <div id="${id}"></div>
        `;
        dynamicChartsArea.appendChild(container);
        return document.getElementById(id);
    };

    // Get a color for a session (for consistent coloring across charts)
    const getSessionColor = (sessionId) => {
        // Extended color palette for more sessions
        const colors = [
            '#4285F4', '#EA4335', '#FBBC05', '#34A853', // Google colors
            '#FF6D01', '#46BDC6', '#7BAAF7', '#F07B72', // Additional colors
            '#00C9A7', '#C355F5', '#FF5A5F', '#FFCF44', // More colors
            '#0072B5', '#E54C21', '#8A2BE2', '#00BFFF', // Even more colors
            '#32CD32', '#FF8C00', '#1E90FF', '#FF1493'  // Yet more colors
        ];
        return colors[parseInt(sessionId) % colors.length];
    };

    // Function to render charts with timeseries data
    // --- In-place Chart Updating ---
    const renderCharts = (timeseriesData) => {
        // Track which chart IDs are still needed this render
        const neededChartIds = new Set();

        if (!timeseriesData || !timeseriesData.timeseries || !timeseriesData.timeseries.length) {
            // If no data, show message and remove all charts
            dynamicChartsArea.innerHTML = '<div class="no-data-message">No timeseries data available</div>';
            destroyAllCharts();
            return;
        }

        // Group timeseries by type
        const sessionSeries = new Map(); // Map of session ID -> Map of metric name -> data
        const reservationSeries = new Map(); // Map of metric name -> data
        const predictionData = {
            boundary_event: null,
            event_number: null
        };

        // Process all timeseries
        timeseriesData.timeseries.forEach(series => {
            const name = series.name;
            const data = series.timeseries?.FloatSamples?.data || [];

            // Skip empty series
            if (!data.length) return;

            // Extract session ID from the series name if it contains session info
            const sessionMatch = name.match(/\/session\/(\d+)\//);
            if (sessionMatch) {
                const sessionId = sessionMatch[1];
                const metricName = name.split('/').pop(); // Get the last part of the path

                if (!sessionSeries.has(sessionId)) {
                    sessionSeries.set(sessionId, new Map());
                }

                if (metricName) {
                    sessionSeries.get(sessionId).set(metricName, data);
                }
            }
            // Check for prediction-related series
            else if (name.includes('/epoch/boundary_event')) {
                predictionData.boundary_event = data;
            }
            else if (name.includes('/event_number')) {
                predictionData.event_number = data;
            }
            // Check for reservation metrics
            else if (name.includes('/reservation/')) {
                const metricName = name.split('/').pop();
                if (metricName && !metricName.includes('session')) {
                    reservationSeries.set(metricName, data);
                }
            }
        });

        // Helper to update or create a chart container
        function ensureChartContainer(title, id) {
            let container = document.getElementById(id);
            if (!container) {
                // Create new container only if it doesn't exist
                const wrapper = document.createElement('div');
                wrapper.className = 'chart-container';
                wrapper.innerHTML = `<h3>${title}</h3><div id="${id}"></div>`;
                dynamicChartsArea.appendChild(wrapper);
                container = document.getElementById(id);
            }
            return container;
        }

        // --- Prediction Accuracy Chart ---
        if (predictionData.boundary_event && predictionData.event_number) {
            const chartId = 'chart-prediction-accuracy';
            neededChartIds.add(chartId);

            const chartContainer = ensureChartContainer('Prediction Accuracy', chartId);
            const boundaryEventData = predictionData.boundary_event;
            const eventNumberData = predictionData.event_number;

            // Collect all timestamps from both datasets
            const allTimestamps = new Set();
            boundaryEventData.forEach(point => allTimestamps.add(point.timestamp));
            eventNumberData.forEach(point => allTimestamps.add(point.timestamp));
            const timestamps = Array.from(allTimestamps).sort((a, b) => a - b);

            // Create value arrays for both datasets
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

            const chartOptions = {
                width: chartContainer.clientWidth,
                height: 350,
                series: seriesLabels.map((label, i) => ({
                    label,
                    stroke: seriesColors[i],
                    width: i > 0 ? 2.5 : 0,
                    points: { show: false },
                    spanGaps: true
                })),
                axes: [
                    { stroke: "white", grid: { stroke: "#444444" } },
                    {
                        label: "Event Number",
                        labelSize: 20,
                        stroke: "white",
                        grid: { stroke: "#444444" },
                        font: "14px Arial",
                        color: "white"
                    }
                ],
                scales: { x: { time: true } },
                legend: { show: true }
            };

            if (uPlotCharts[chartId]) {
                uPlotCharts[chartId].setData(seriesData);
            } else {
                uPlotCharts[chartId] = new uPlot(chartOptions, seriesData, chartContainer);
            }
        }

        // --- Session Metric Charts ---
        const sessionMetrics = new Set();
        sessionSeries.forEach(metrics => {
            metrics.forEach((_, metricName) => {
                sessionMetrics.add(metricName);
            });
        });

        sessionMetrics.forEach(metricKey => {
            const formattedMetricName = metricKey.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            const chartId = `chart-${metricKey}`;
            neededChartIds.add(chartId);

            const chartContainer = ensureChartContainer(formattedMetricName, chartId);
            if (!chartContainer) return;

            // Prepare data for uPlot
            const timestamps = [];
            const seriesData = [];
            const seriesLabels = ['Time'];
            const seriesColors = ['transparent'];
            const sessionIds = [];

            sessionSeries.forEach((metrics, sessionId) => {
                if (metrics.has(metricKey)) {
                    const data = metrics.get(metricKey);
                    sessionIds.push(sessionId);
                    // Always use receiver name if available, else fallback to sessionId
                    const label = sessionIdToName[sessionId] ? sessionIdToName[sessionId] : `Session ${sessionId}`;
                    seriesLabels.push(label);
                    seriesColors.push(getSessionColor(sessionId));
                    data.forEach((point, idx) => {
                        if (idx === 0 || !timestamps.includes(point.timestamp  / 1000)) {
                            timestamps.push(point.timestamp  / 1000);
                        }
                    });
                }
            });
            timestamps.sort((a, b) => a - b);
            seriesData.push(timestamps);

            sessionSeries.forEach((metrics, sessionId) => {
                if (metrics.has(metricKey)) {
                    const data = metrics.get(metricKey);
                    const values = new Array(timestamps.length).fill(null);
                    data.forEach(point => {
                        const idx = timestamps.indexOf(point.timestamp  / 1000);
                        if (idx !== -1) values[idx] = point.value;
                    });
                    seriesData.push(values);
                }
            });

            const defaultOptions = {
                width: chartContainer.clientWidth,
                height: 350,
                series: seriesLabels.map((label, i) => ({
                    label,
                    stroke: seriesColors[i],
                    width: i > 0 ? 2.5 : 0,
                    points: { show: false },
                    spanGaps: true
                })),
                axes: [
                    { stroke: "white", grid: { stroke: "#444444" }, ticks: { count: 6 } },
                    {
                        label: formattedMetricName,
                        labelSize: 20,
                        stroke: "white",
                        grid: { stroke: "#444444" },
                        font: "14px Arial",
                        color: "white"
                    }
                ],
                scales: { x: { time: true } },
                legend: { show: true }
            };
            const specialOptions = {};
            if (metricKey === 'fill_percent') {
                specialOptions.scales = { y: { range: [0, 1] } };
            }
            const chartOptions = { ...defaultOptions, ...specialOptions };

            if (uPlotCharts[chartId]) {
                uPlotCharts[chartId].setData(seriesData);
                uPlotCharts[chartId].sessionIds = sessionIds;
            } else {
                const chart = new uPlot(chartOptions, seriesData, chartContainer);
                chart.sessionIds = sessionIds;
                uPlotCharts[chartId] = chart;
            }
        });

        // --- Reservation Metric Charts ---
        reservationSeries.forEach((data, metricName) => {
            const formattedMetricName = metricName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            const chartId = `chart-reservation-${metricName}`;
            neededChartIds.add(chartId);

            const chartContainer = ensureChartContainer(`Reservation ${formattedMetricName}`, chartId);
            if (!chartContainer) return;

            const timestamps = data.map(point => point.timestamp / 1000);
            const values = data.map(point => point.value);
            const seriesData = [timestamps, values];
            const seriesLabels = ['Time', formattedMetricName];
            const seriesColors = ['transparent', '#4285F4'];

            const chartOptions = {
                width: chartContainer.clientWidth,
                height: 350,
                series: seriesLabels.map((label, i) => ({
                    label,
                    stroke: seriesColors[i],
                    width: i > 0 ? 2.5 : 0,
                    points: { show: false },
                    spanGaps: true
                })),
                axes: [
                    { stroke: "white", grid: { stroke: "#444444" } },
                    {
                        label: formattedMetricName,
                        labelSize: 20,
                        stroke: "white",
                        grid: { stroke: "#444444" },
                        font: "14px Arial",
                        color: "white"
                    }
                ],
                scales: { x: { time: true } },
                legend: { show: true }
            };

            if (uPlotCharts[chartId]) {
                uPlotCharts[chartId].setData(seriesData);
            } else {
                uPlotCharts[chartId] = new uPlot(chartOptions, seriesData, chartContainer);
            }
        });

        // --- Remove unused charts and DOM nodes ---
        Object.keys(uPlotCharts).forEach(chartId => {
            if (!neededChartIds.has(chartId)) {
                // Remove chart DOM
                const chartDiv = document.getElementById(chartId);
                if (chartDiv && chartDiv.parentElement) {
                    chartDiv.parentElement.remove();
                }
                // Destroy uPlot instance
                uPlotCharts[chartId].destroy();
                delete uPlotCharts[chartId];
            }
        });

        // --- Reorder chart containers to match needed order ---
        // (Optional: could be added for strict order, but not strictly necessary)

        // --- Resize charts after rendering ---
        // Removed dynamic resizing to prevent chart growth
    };

    // Highlight session in charts when hovering over a session in the sidebar
    const highlightSession = (receiverName) => {
        // Find the sessionId for this receiver name
        let sessionId = null;
        for (const [sid, name] of Object.entries(sessionIdToName)) {
            if (name === receiverName) {
                sessionId = sid;
                break;
            }
        }
        if (!sessionId) return;

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
                        s.width = 2.5;
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

    // --- View Loading Functions ---
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
        dynamicChartsArea.innerHTML = '<div class="loading">Loading charts...</div>';

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
            dynamicChartsArea.innerHTML = '<div class="error-message">Error loading chart data.</div>';
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

    // --- Token Creation UI Logic ---
    // Permission type and resource type mappings
    const ResourceTypeOptions = [
        { value: 0, label: "All" },
        { value: 1, label: "Load Balancer" },
        { value: 2, label: "Reservation" },
        { value: 3, label: "Session" }
    ];
    const PermissionTypeOptions = [
        { value: 0, label: "Read Only" },
        { value: 1, label: "Register" },
        { value: 2, label: "Reserve" },
        { value: 3, label: "Update" }
    ];

    // Helper to create a permission row
    function createPermissionRow(initial = {}) {
        const row = document.createElement('div');
        row.className = 'permission-row';
        row.style.display = 'flex';
        row.style.gap = '8px';
        row.style.marginBottom = '8px';
        // Resource Type
        const resourceTypeSelect = document.createElement('select');
        resourceTypeSelect.className = 'perm-resource-type';
        resourceTypeSelect.name = 'resource_type';
        ResourceTypeOptions.forEach(opt => {
            const option = document.createElement('option');
            option.value = opt.value;
            option.textContent = opt.label;
            resourceTypeSelect.appendChild(option);
        });
        resourceTypeSelect.value = initial.resource_type !== undefined ? initial.resource_type : 0;

        // Resource ID
        const resourceIdInput = document.createElement('input');
        resourceIdInput.type = 'text';
        resourceIdInput.className = 'perm-resource-id';
        resourceIdInput.name = 'resource_id';
        resourceIdInput.placeholder = 'Resource ID';
        resourceIdInput.style.width = '120px';
        resourceIdInput.value = initial.resource_id || '';
        // Hide for "All"
        if (parseInt(resourceTypeSelect.value) === 0) {
            resourceIdInput.style.display = 'none';
        }

        // Permission Type
        const permissionTypeSelect = document.createElement('select');
        permissionTypeSelect.className = 'perm-permission-type';
        permissionTypeSelect.name = 'permission';
        PermissionTypeOptions.forEach(opt => {
            const option = document.createElement('option');
            option.value = opt.value;
            option.textContent = opt.label;
            permissionTypeSelect.appendChild(option);
        });
        permissionTypeSelect.value = initial.permission !== undefined ? initial.permission : 0;

        // Remove button
        const removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.className = 'remove-permission-btn danger-button';
        removeBtn.innerHTML = '<i class="fas fa-trash"></i>';
        removeBtn.title = 'Remove permission';

        // Only show remove if more than one row
        removeBtn.style.display = permissionsListDiv.childElementCount > 0 ? 'inline-block' : 'none';

        // Show/hide resource id input based on resource type
        resourceTypeSelect.addEventListener('change', () => {
            if (parseInt(resourceTypeSelect.value) === 0) {
                resourceIdInput.style.display = 'none';
                resourceIdInput.value = '';
            } else {
                resourceIdInput.style.display = 'inline-block';
            }
        });

        removeBtn.addEventListener('click', () => {
            row.remove();
            // If only one row left, hide its remove button
            if (permissionsListDiv.childElementCount === 1) {
                permissionsListDiv.querySelector('.remove-permission-btn').style.display = 'none';
            }
        });

        row.appendChild(resourceTypeSelect);
        row.appendChild(resourceIdInput);
        row.appendChild(permissionTypeSelect);
        row.appendChild(removeBtn);

        return row;
    }

    // Add a permission row (at least one by default)
    function ensureAtLeastOnePermissionRow() {
        if (!permissionsListDiv.querySelector('.permission-row')) {
            permissionsListDiv.appendChild(createPermissionRow());
        }
        // Hide remove button if only one row
        const removeBtns = permissionsListDiv.querySelectorAll('.remove-permission-btn');
        removeBtns.forEach(btn => btn.style.display = removeBtns.length > 1 ? 'inline-block' : 'none');
    }

    if (addPermissionBtn) {
        addPermissionBtn.addEventListener('click', () => {
            permissionsListDiv.appendChild(createPermissionRow());
            // Show all remove buttons if more than one row
            const removeBtns = permissionsListDiv.querySelectorAll('.remove-permission-btn');
            removeBtns.forEach(btn => btn.style.display = removeBtns.length > 1 ? 'inline-block' : 'none');
        });
    }

    // On form load, ensure at least one permission row
    if (permissionsListDiv) {
        ensureAtLeastOnePermissionRow();
    }

    // Handle form submit
    if (createTokenForm) {
        createTokenForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            createTokenResultDiv.textContent = '';
            createTokenResultDiv.className = 'create-token-result';

            const name = newTokenNameInput.value.trim();
            if (!name) {
                createTokenResultDiv.textContent = 'Token name is required.';
                createTokenResultDiv.classList.add('error-message');
                return;
            }

            // Gather permissions
            const permissionRows = permissionsListDiv.querySelectorAll('.permission-row');
            const permissions = [];
            let hasError = false;
            permissionRows.forEach(row => {
                const resourceType = parseInt(row.querySelector('.perm-resource-type').value);
                const resourceId = row.querySelector('.perm-resource-id').value.trim();
                const permission = parseInt(row.querySelector('.perm-permission-type').value);

                // For resource types other than "All", require resource id
                if (resourceType !== 0 && !resourceId) {
                    hasError = true;
                    row.querySelector('.perm-resource-id').style.borderColor = 'var(--danger-color)';
                } else {
                    row.querySelector('.perm-resource-id').style.borderColor = '';
                }

                permissions.push({
                    resource_type: resourceType,
                    resource_id: resourceType === 0 ? '' : resourceId,
                    permission: permission
                });
            });

            if (hasError) {
                createTokenResultDiv.textContent = 'Please fill in all required Resource IDs.';
                createTokenResultDiv.classList.add('error-message');
                return;
            }

            // POST to /api/v1/tokens
            try {
                createTokenResultDiv.textContent = 'Creating token...';
                createTokenResultDiv.classList.remove('error-message');
                const reply = await apiFetch('/tokens', {
                    method: 'POST',
                    body: JSON.stringify({ name, permissions })
                });
                createTokenResultDiv.innerHTML = `<span style="color:var(--success-color);">Token created:</span><br><code>${reply.token}</code><br><small>Store this token securely. It will not be shown again.</small>`;
                createTokenResultDiv.classList.remove('error-message');
                createTokenResultDiv.classList.add('success-message');
                createTokenForm.reset();
                permissionsListDiv.innerHTML = '';
                ensureAtLeastOnePermissionRow();

                // Refresh child tokens list
                if (activeView === 'token-management-view') {
                    const childrenData = await apiFetch('/tokens/self/children');
                    renderChildTokens(childrenData);
                }
            } catch (error) {
                createTokenResultDiv.textContent = 'Failed to create token: ' + (error?.message || 'Unknown error');
                createTokenResultDiv.classList.add('error-message');
            }
        });
    }
    if (tokenMgmtBtn) {
        tokenMgmtBtn.addEventListener('click', () => {
            navigateTo('/tools/tokens');
        });
    }
    if (sysInfoBtn) {
        sysInfoBtn.addEventListener('click', () => {
            navigateTo('/tools/system');
        });
    }

    // Event delegation only for sidebar navigation
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
    });

    // Add event listener for session highlighting
    document.addEventListener('mouseover', (event) => {
        const receiverItem = event.target.closest('#receiver-list li');
        if (receiverItem) {
            const receiverName = receiverItem.querySelector('.receiver-name')?.textContent;
            if (receiverName) {
                highlightSession(receiverName);
            }
        }
    });

    const handleDeregisterSession = async (receiverId) => {
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

    const handleRevokeToken = async (tokenIdOrToken) => {
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

    const handleAddSender = () => {
        if (!currentSelectedLbId) return alert("Select a Load Balancer first.");

        // Check if form already exists
        if (document.querySelector('.sender-form')) return;

        // Show the sender input form
        const senderForm = document.createElement('div');
        senderForm.className = 'sender-form';
        senderForm.innerHTML = `
            <input type="text" id="new-sender-ip" placeholder="Enter sender IP address">
            <button id="confirm-add-sender" class="action-button"><i class="fas fa-plus"></i></button>
        `;

        // Add the form to the sender list
        senderListUl.appendChild(senderForm);

        // Focus the input
        document.getElementById('new-sender-ip').focus();

        // Add event listener for the confirm button
        document.getElementById('confirm-add-sender').addEventListener('click', handleConfirmAddSender);

        // Add event listener for Enter key
        document.getElementById('new-sender-ip').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                handleConfirmAddSender();
            }
        });
    };

    const handleConfirmAddSender = async () => {
        const ipInput = document.getElementById('new-sender-ip');
        if (!ipInput) return;

        const ipToAdd = ipInput.value.trim();
        if (!ipToAdd) return alert("Please enter an IP address.");
        if (!currentSelectedLbId) return alert("Error: No Load Balancer selected.");

        console.log(`Adding sender ${ipToAdd} to LB ${currentSelectedLbId}`);
        try {
            await apiFetch(`/lb/${currentSelectedLbId}/senders`, {
                method: 'POST',
                body: JSON.stringify({ sender_addresses: [ipToAdd] })
            });

            // Remove the form
            document.querySelector('.sender-form')?.remove();

            // Refresh the sender list
            const statusData = await apiFetch(`/lb/${currentSelectedLbId}/status`);
            renderSenders(statusData.senderAddresses);

            showToast(`Sender ${ipToAdd} added successfully.`, 'success');
        } catch(error) {
            document.querySelector('.sender-form')?.remove();
            // Error handled by apiFetch
        }
    };

    const handleRemoveSender = async (ipToRemove) => {
        if (!currentSelectedLbId) return alert("Select a Load Balancer first.");
        if (!ipToRemove) return;

        if (!confirm(`Remove sender ${ipToRemove}?`)) return;

        console.log(`Removing sender ${ipToRemove} from LB ${currentSelectedLbId}`);
        try {
            await apiFetch(`/lb/${currentSelectedLbId}/senders`, {
                method: 'DELETE',
                body: JSON.stringify({ sender_addresses: [ipToRemove] })
            });

            // Refresh the sender list
            const statusData = await apiFetch(`/lb/${currentSelectedLbId}/status`);
            renderSenders(statusData.senderAddresses);

            showToast(`Sender ${ipToRemove} removed.`, 'success');
        } catch(error) {
            console.error("Failed to remove sender:", error);
        }
    };

    const handleGenerateChildToken = async () => {
        const tokenName = prompt("Enter name for new child token (basic read-only permissions):");
        if (!tokenName) return;

        const basicPermissions = [{ resource_type: 0, resource_id: '*', permission: 0 }];
        try {
            const reply = await apiFetch('/tokens', {
                method: 'POST',
                body: JSON.stringify({ name: tokenName, permissions: basicPermissions })
            });

            alert(`Child token created:\n\n${reply.token}\n\nStore securely!`);

            if (activeView === 'token-management-view') { // Refresh child list if visible
                const childrenData = await apiFetch('/tokens/self/children');
                renderChildTokens(childrenData);
            }
        } catch(error) {
            console.error("Failed to create child token:", error);
        }
    };

    const handleFullReset = async () => {
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
            const deregPromises = workers.map(w =>
                apiFetch(`/receivers/${w.name}`, { method: 'DELETE' })
                    .catch(err => console.error(`Failed deregister ${w.name}:`, err))
            );
            await Promise.allSettled(deregPromises);
            console.log("Finished worker deregistration attempt.");

            // Remove senders
            if (senders.length > 0) {
                console.log(`Removing ${senders.length} senders...`);
                await apiFetch(`/lb/${currentSelectedLbId}/senders`, {
                    method: 'DELETE',
                    body: JSON.stringify({ sender_addresses: senders })
                });
                console.log("Finished removing senders.");
            }

            alert(`FULL RESET complete for LB ${currentSelectedLbId}.`);

            // Refresh UI
            const finalStatus = await apiFetch(`/lb/${currentSelectedLbId}/status`);
            renderSessions(finalStatus.workers);
            renderSenders(finalStatus.senderAddresses);
        } catch (error) {
            console.error("Error during FULL RESET:", error);
            alert(`Error during FULL RESET: ${error.message}.`);
        }
    };

    // Attach direct event listeners to static buttons (moved after function definitions)
    if (addSenderBtn) {
        addSenderBtn.addEventListener('click', handleAddSender);
    }
    if (generateChildTokenBtn) {
        generateChildTokenBtn.addEventListener('click', handleGenerateChildToken);
    }
    if (fullResetBtn) {
        fullResetBtn.addEventListener('click', handleFullReset);
    }

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

    // --- Authentication Flow ---
    const showAuthModal = (errorMessage = null) => {
        console.log("Authentication required. Showing modal.");
        authInput.value = '';
        authError.textContent = errorMessage || '';
        authError.style.display = errorMessage ? 'block' : 'none';
        authModal.style.display = 'block';
        authInput.focus();
    };

    const hideAuthModal = () => {
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

    const handleAuthSubmit = async (event) => {
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

    // --- Initialization ---
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
                        renderSenders(activeLB.status.sender_addresses || []);
                    }
                }
            } catch (error) {
                console.error("Failed to update overview data:", error);
            }
        }, 1000); // Update every second
    };

    const stopOverviewPolling = () => {
        if (overviewUpdateInterval) {
            clearInterval(overviewUpdateInterval);
            overviewUpdateInterval = null;
        }
    };

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
                    showAuthModal("Your session may have expired. Please re-authenticate.");
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
});
