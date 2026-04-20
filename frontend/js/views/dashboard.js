// SPDX-License-Identifier: BSD-3-Clause-LBNL
// Dashboard view: LB status, health issues, senders, receivers

import { state } from '../state.js';
import { apiFetch } from '../api.js';
import { switchView, showToast } from '../ui.js';
import {
    destroyAllCharts,
    resetChartTabs,
    startChartPolling,
    stopChartPolling,
    handleReceiverFilter
} from '../charts.js';

// --- Health Issues ---

export const renderHealthIssues = (healthIssues) => {
    const healthPanel = document.getElementById('health-issues-panel');
    const healthList = document.getElementById('health-issues-list');

    if (!healthIssues || healthIssues.length === 0) {
        healthPanel.classList.add('hidden');
        return;
    }

    healthPanel.classList.remove('hidden');
    healthList.innerHTML = '';

    healthIssues.forEach(issue => {
        const issueDiv = document.createElement('div');
        issueDiv.className = `health-issue health-issue-${issue.severity || 'warning'}`;

        const detectedAt = issue.detected_at
            ? new Date(issue.detected_at.seconds * 1000).toLocaleString()
            : 'N/A';

        issueDiv.innerHTML = `
            <div class="health-issue-header">
                <span class="health-issue-type">${issue.type || 'Unknown Issue'}</span>
                <span class="health-issue-severity">${issue.severity || 'warning'}</span>
            </div>
            <div class="health-issue-message">${issue.message || 'No message provided'}</div>
            <div class="health-issue-time">Detected: ${detectedAt}</div>
        `;

        healthList.appendChild(issueDiv);
    });
};

// --- Receivers (Sessions) ---

// Color mapping helpers
function getQueueFillColor(fillPercent) {
    if (fillPercent === 0) return '#fff';
    if (fillPercent <= 0.001) return '#fff';
    if (fillPercent <= 0.0011) return '#00ff00';
    if (fillPercent < 0.001) return '#fff';
    const t = Math.max(0, Math.min(1, (fillPercent - 0.001) / (0.8 - 0.001)));
    const r = Math.round(0 + t * (255 - 0));
    const g = Math.round(255 - t * 255);
    const b = 0;
    return `rgb(${r},${g},${b})`;
}

function getControlSignalColor(signal) {
    if (signal === 0) return '#fff';
    if (signal <= -50) return '#ff0000';
    if (signal >= 50) return '#00ff00';
    if (signal < 0) {
        const t = (signal + 50) / 50;
        const r = 255;
        const g = Math.round(0 + t * 255);
        const b = Math.round(0 + t * 255);
        return `rgb(${r},${g},${b})`;
    } else {
        const t = signal / 50;
        const r = Math.round(255 - t * 255);
        const g = 255;
        const b = Math.round(255 - t * 255);
        return `rgb(${r},${g},${b})`;
    }
}

export const renderSessions = (workers) => {
    const receiverList = document.getElementById('receiver-list');
    receiverList.innerHTML = '';
    state.sessionIdToName = {};
    state.allSessionIds.clear();
    if (!workers?.length) {
        receiverList.innerHTML = '<li class="no-receivers">No active receivers.</li>';
        return;
    }
    workers.forEach(worker => {
        const li = document.createElement('li');
        const lastUpdatedSeconds = worker.last_updated?.seconds;
        const lastUpdated = lastUpdatedSeconds ? new Date(lastUpdatedSeconds * 1000).toLocaleString() : 'N/A';
        const receiverId = worker.name;

        let sessionId = null;
        if (worker.session_id !== undefined) {
            sessionId = String(worker.session_id);
        } else {
            const match = worker.name && worker.name.match(/(\d+)/);
            if (match) sessionId = match[1];
        }
        if (sessionId) {
            state.sessionIdToName[sessionId] = worker.name;
            state.allSessionIds.add(sessionId);
        }

        const fillPercent = worker.fill_percent ?? 0;
        const controlSignal = worker.control_signal ?? 0;
        const isFiltered = state.filteredSessionIds.size > 0 && state.filteredSessionIds.has(sessionId);
        const filterClass = isFiltered ? 'filtered-receiver' : '';

        let healthIssuesHtml = '';
        if (worker.health_issues && worker.health_issues.length > 0) {
            const issuesText = worker.health_issues.map(issue =>
                `${issue.severity || 'warning'}: ${issue.type || 'issue'}`
            ).join(', ');
            healthIssuesHtml = `<span class="receiver-health-warning"><i class="fas fa-exclamation-triangle"></i> ${issuesText}</span>`;
        }

        li.innerHTML = `
            <button class="deregister-btn" data-receiver-id="${sessionId}" title="Deregister ${receiverId}">
                <i class="fas fa-times"></i> Deregister
            </button>
            <div class="receiver-name"></div>
            <div class="receiver-details">
                <span>IP Address: <strong>${worker.ip_address}</strong></span>
                <span>Queue Fill: <strong style="color: ${getQueueFillColor(fillPercent)}">${(fillPercent * 100).toFixed(1)}%</strong></span>
                <span>Control Signal: <strong style="color: ${getControlSignalColor(controlSignal)}">${worker.control_signal?.toFixed(4) ?? 'N/A'}</strong></span>
                <span>Slots: <strong>${worker.slots_assigned ?? 'N/A'}</strong></span>
                <span>Last Update: ${lastUpdated}</span>
                ${healthIssuesHtml}
            </div>
        `;
        // Set receiver name safely using textContent to prevent XSS
        li.querySelector('.receiver-name').textContent = worker.name;
        li.className = filterClass;
        li.dataset.sessionId = sessionId;
        li.dataset.receiverName = worker.name;

        const deregBtn = li.querySelector('.deregister-btn[data-receiver-id]');
        if (deregBtn) {
            deregBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                handleDeregisterSession(sessionId);
            });
        }

        li.addEventListener('click', (e) => {
            if (!e.target.closest('.deregister-btn')) {
                handleReceiverFilter(sessionId);
            }
        });

        receiverList.appendChild(li);
    });
};

// --- Senders ---

export const renderSenders = (senderAddresses) => {
    const senderListUl = document.querySelector('#sender-list ul');
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

// --- Dashboard View ---

export const showDashboardView = async (lbId) => {
    stopChartPolling();

    if (state.currentSelectedLbId === lbId && state.activeView === 'dashboard-view') return;
    state.currentSelectedLbId = lbId;
    switchView('dashboard-view');

    const dashboardTitle = document.getElementById('dashboard-lb-title');
    const receiverList = document.getElementById('receiver-list');
    const senderListUl = document.querySelector('#sender-list ul');
    const dynamicChartsArea = document.getElementById('dynamic-charts-area');

    dashboardTitle.textContent = `Loading Dashboard for ${lbId}...`;
    receiverList.innerHTML = '<li class="loading">Loading receivers...</li>';
    senderListUl.innerHTML = '<li class="loading">Loading senders...</li>';
    destroyAllCharts();
    resetChartTabs();

    try {
        const statusData = await apiFetch(`/lb/${lbId}/status`);
        dashboardTitle.textContent = `Dashboard: ${lbId}`;
        renderHealthIssues(statusData.health_issues);
        renderSessions(statusData.workers);
        renderSenders(statusData.sender_addresses);
        startChartPolling(lbId);
    } catch (error) {
        dashboardTitle.textContent = `Error loading dashboard for ${lbId}`;
        receiverList.innerHTML = '<li class="no-receivers">Error loading receivers.</li>';
        senderListUl.innerHTML = '<li>Error loading senders.</li>';
        dynamicChartsArea.innerHTML = '<div class="error-message">Error loading chart data.</div>';
    }
};

// --- Event Handlers ---

const handleDeregisterSession = async (receiverId) => {
    if (!receiverId) return alert('Error: Session ID missing.');
    if (!confirm(`Deregister receiver "${receiverId}"?`)) return;
    console.log(`Attempting to deregister receiver: ${receiverId}`);
    try {
        await apiFetch(`/sessions/${receiverId}`, { method: 'DELETE' });
        showToast(`session ${receiverId} deregistered`);
        if (state.currentSelectedLbId) {
            const statusData = await apiFetch(`/lb/${state.currentSelectedLbId}/status`);
            renderSessions(statusData.workers);
        }
    } catch (error) { /* Handled by apiFetch */ }
};

export const handleAddSender = () => {
    if (!state.currentSelectedLbId) return alert('Select a Load Balancer first.');
    handleConfirmAddSender();
};

const handleConfirmAddSender = async () => {
    const ipInput = document.getElementById('new-sender-ip');
    if (!ipInput) return;

    const ipToAdd = ipInput.value.trim();
    if (!ipToAdd) return alert('Please enter an IP address.');
    if (!state.currentSelectedLbId) return alert('Error: No Load Balancer selected.');

    console.log(`Adding sender ${ipToAdd} to LB ${state.currentSelectedLbId}`);
    try {
        await apiFetch(`/lb/${state.currentSelectedLbId}/senders`, {
            method: 'POST',
            body: JSON.stringify({ sender_addresses: [ipToAdd] })
        });
        document.querySelector('.sender-form')?.remove();
        const statusData = await apiFetch(`/lb/${state.currentSelectedLbId}/status`);
        renderSenders(statusData.sender_addresses);
        showToast(`Sender ${ipToAdd} added successfully.`, 'success');
    } catch (error) {
        document.querySelector('.sender-form')?.remove();
    }
};

const handleRemoveSender = async (ipToRemove) => {
    if (!state.currentSelectedLbId) return alert('Select a Load Balancer first.');
    if (!ipToRemove) return;
    if (!confirm(`Remove sender ${ipToRemove}?`)) return;

    console.log(`Removing sender ${ipToRemove} from LB ${state.currentSelectedLbId}`);
    try {
        await apiFetch(`/lb/${state.currentSelectedLbId}/senders`, {
            method: 'DELETE',
            body: JSON.stringify({ sender_addresses: [ipToRemove] })
        });
        const statusData = await apiFetch(`/lb/${state.currentSelectedLbId}/status`);
        renderSenders(statusData.sender_addresses);
        showToast(`Sender ${ipToRemove} removed.`, 'success');
    } catch (error) {
        console.error('Failed to remove sender:', error);
    }
};

export const handleGenerateChildToken = async () => {
    const tokenName = prompt('Enter name for new child token (basic read-only permissions):');
    if (!tokenName) return;

    const basicPermissions = [{ resource_type: 0, resource_id: '*', permission: 0 }];
    try {
        const reply = await apiFetch('/tokens', {
            method: 'POST',
            body: JSON.stringify({ name: tokenName, permissions: basicPermissions })
        });

        const uriMsg = reply.ejfat_uri ? `\n\nEJFAT URI:\n${reply.ejfat_uri}` : '';
        alert(`Child token created:\n\n${reply.token}${uriMsg}\n\nStore securely!`);

        if (state.activeView === 'token-management-view') {
            const { renderChildTokens } = await import('./tokens.js');
            const childrenData = await apiFetch('/tokens/self/children');
            renderChildTokens(childrenData);
        }
    } catch (error) {
        console.error('Failed to create child token:', error);
    }
};

export const handleFreeLb = async () => {
    if (!state.currentSelectedLbId) {
        showToast('No load balancer selected', 'error');
        return;
    }

    if (!confirm(`Free Load Balancer ${state.currentSelectedLbId}? This will remove the reservation and all sessions.`)) {
        return;
    }

    const freeLbBtn = document.getElementById('free-lb-btn');
    try {
        freeLbBtn.disabled = true;
        freeLbBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Freeing...';

        await apiFetch(`/lb/${state.currentSelectedLbId}`, { method: 'DELETE' });
        showToast(`Load Balancer ${state.currentSelectedLbId} freed successfully!`, 'success');

        // Refresh sidebar and navigate home
        const { renderLoadBalancers } = await import('../sidebar.js');
        const overviewData = await apiFetch('/overview');
        renderLoadBalancers(overviewData);

        const { navigateTo } = await import('../router.js');
        navigateTo('/');
    } catch (error) {
        console.error('Failed to free load balancer:', error);
    } finally {
        freeLbBtn.disabled = false;
        freeLbBtn.innerHTML = '<i class="fas fa-unlock"></i> Free Load Balancer';
    }
};
