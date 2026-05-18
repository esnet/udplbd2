// SPDX-License-Identifier: BSD-3-Clause-LBNL
// LB list rendering and overview polling

import { state } from './state.js';
import { apiFetch } from './api.js';
import { renderSessions, renderSenders } from './views/dashboard.js';

// --- LB List Rendering ---

export const renderLoadBalancers = (overviewData) => {
    const lbList = document.getElementById('lb-list');
    lbList.innerHTML = '';

    const totalLoadBalancers = 8;

    // Create a map of active LBs from the overview data
    const activeLBMap = new Map();
    if (overviewData['load_balancers']) {
        overviewData['load_balancers'].forEach(lbOverview => {
            if (lbOverview.reservation) {
                const fpgaLbId = String(lbOverview.reservation['fpga_lb_id']);
                activeLBMap.set(fpgaLbId, {
                    name: lbOverview.name || 'Unnamed LB',
                    reservation: lbOverview.reservation,
                    status: lbOverview.status
                });
            }
        });
    }

    // Render all 8 load balancers
    for (let i = 1; i <= totalLoadBalancers; i++) {
        const fpgaLbId = i.toString();
        const li = document.createElement('li');
        const activeLB = activeLBMap.get(fpgaLbId);
        if (activeLB) {
            const lb = activeLB.reservation;
            const status = activeLB.status;
            const name = activeLB.name;

            let statusClass = 'unreserved', statusTitle = 'Unreserved';
            let disabledClass = '';
            const expiresDate = status['expires_at'];

            if (status['workers'] && status['workers'].length) {
                statusClass = 'active';
                statusTitle = `Active (Expires: ${expiresDate ? new Date(expiresDate.seconds * 1000).toLocaleString() : 'N/A'})`;
            } else {
                statusClass = 'idle';
                statusTitle = expiresDate ?
                    `Idle (Expires: ${new Date(expiresDate.seconds * 1000).toLocaleString()})` :
                    'Idle (No expiry info)';
            }

            li.innerHTML = `
                <span class="status-dot ${statusClass}" title="${statusTitle}"></span>
                <div class="lb-info">
                    <div class="lb-name"></div>
                    <div class="lb-details">
                        <span>IPv4: ${lb.data_ipv4_address || 'N/A'}</span>
                        <span>IPv6: ${lb.data_ipv6_address || 'N/A'}</span>
                    </div>
                </div>
            `;
            // Set name safely using textContent to prevent XSS
            li.querySelector('.lb-name').textContent = `${name} (/lb/${lb.lb_id})`;
            if (disabledClass) {
                li.classList.add(disabledClass);
            }
            li.dataset.lbId = lb.lb_id;
            li.dataset.targetPath = `/lb/${lb.lb_id}`;
        } else {
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
            li.classList.add('disabled-lb');
            li.dataset.targetPath = `/lb/reserve`;
        }

        lbList.appendChild(li);
    }
};

// --- Overview Polling ---

let overviewUpdateInterval = null;

export const startOverviewPolling = () => {
    if (overviewUpdateInterval) {
        clearInterval(overviewUpdateInterval);
    }

    overviewUpdateInterval = setInterval(async () => {
        try {
            const overviewData = await apiFetch('/overview');
            renderLoadBalancers(overviewData);

            // If on dashboard view, update session/sender info for the current LB
            if (state.activeView === 'dashboard-view' && state.currentSelectedLbId) {
                const activeLB = overviewData.load_balancers?.find(lb =>
                    lb.reservation && lb.reservation.lb_id === state.currentSelectedLbId);

                if (activeLB && activeLB.status) {
                    renderSessions(activeLB.status.workers || []);
                    renderSenders(activeLB.status.sender_addresses || []);
                }
            }
        } catch (error) {
            console.error('Failed to update overview data:', error);
        }
    }, 1000);
};

export const stopOverviewPolling = () => {
    if (overviewUpdateInterval) {
        clearInterval(overviewUpdateInterval);
        overviewUpdateInterval = null;
    }
};
