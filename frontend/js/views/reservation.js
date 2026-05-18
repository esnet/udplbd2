// SPDX-License-Identifier: BSD-3-Clause-LBNL
// Reservation form and EJFAT URI construction

import { state } from '../state.js';
import { apiFetch } from '../api.js';
import { switchView, showToast } from '../ui.js';
import { stopChartPolling } from '../charts.js';

// --- Reservation View ---

export const showReservationView = () => {
    stopChartPolling();
    state.currentSelectedLbId = null;
    switchView('reservation-view');

    const reservationForm = document.getElementById('reservation-form');
    const submitReservationBtn = document.getElementById('submit-reservation-btn');
    const reservationNameInput = document.getElementById('reservation-name');
    const reservationSendersInput = document.getElementById('reservation-senders');
    const reservationIpFamilySelect = document.getElementById('reservation-ip-family');
    const reservationStrategySelect = document.getElementById('reservation-strategy');
    const reservationResultDiv = document.getElementById('reservation-result');

    // Reset the form completely
    reservationForm.reset();
    submitReservationBtn.style.display = 'inline-block';
    submitReservationBtn.disabled = false;
    submitReservationBtn.textContent = 'Reserve';
    reservationNameInput.disabled = false;
    reservationSendersInput.disabled = false;
    reservationIpFamilySelect.disabled = false;
    reservationStrategySelect.disabled = false;

    if (reservationResultDiv) {
        reservationResultDiv.innerHTML = '';
        reservationResultDiv.className = 'reservation-result';
    }

    reservationNameInput.focus();
};

// --- Form Submission ---

export const handleReservationSubmit = async (e) => {
    e.preventDefault();

    const reservationNameInput = document.getElementById('reservation-name');
    const reservationSendersInput = document.getElementById('reservation-senders');
    const reservationIpFamilySelect = document.getElementById('reservation-ip-family');
    const reservationStrategySelect = document.getElementById('reservation-strategy');
    const submitReservationBtn = document.getElementById('submit-reservation-btn');
    const reservationResultDiv = document.getElementById('reservation-result');

    const name = reservationNameInput.value.trim();
    if (!name) {
        showToast('Reservation name is required', 'error');
        return;
    }

    const sendersText = reservationSendersInput.value.trim();
    const senderAddresses = sendersText
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);

    if (senderAddresses.length === 0) {
        showToast('At least one sender address is required', 'error');
        return;
    }

    const ipFamily = reservationIpFamilySelect.value;
    const strategy = reservationStrategySelect.value;

    try {
        submitReservationBtn.disabled = true;
        submitReservationBtn.textContent = 'Reserving...';
        reservationResultDiv.textContent = '';
        reservationResultDiv.className = 'reservation-result';

        const response = await apiFetch('/lb', {
            method: 'POST',
            body: JSON.stringify({
                name: name,
                sender_addresses: senderAddresses,
                ip_family: ipFamily,
                strategy: strategy
            })
        });

        // Construct EJFAT_URI from response
        const token = response.token;
        const lbId = response.lb_id;
        const syncAddrV4 = response.sync_ipv4_address;
        const syncAddrV6 = response.sync_ipv6_address;
        const syncPort = response.sync_udp_port;
        const dataAddrV4 = response.data_ipv4_address;
        const dataAddrV6 = response.data_ipv6_address;
        const dataMinPort = response.data_min_port;
        const dataMaxPort = response.data_max_port;

        const currentHost = window.location.host;
        const queryParams = [];

        if (syncAddrV4) queryParams.push(`sync=${syncAddrV4}:${syncPort}`);
        if (syncAddrV6) queryParams.push(`sync=[${syncAddrV6}]:${syncPort}`);
        if (dataAddrV4) queryParams.push(`data=${dataAddrV4}:${dataMinPort}-${dataMaxPort}`);
        if (dataAddrV6) queryParams.push(`data=[${dataAddrV6}]:${dataMinPort}-${dataMaxPort}`);

        const ejfatUri = `ejfats://${token}@${currentHost}/lb/${lbId}?${queryParams.join('&')}`;

        reservationResultDiv.innerHTML = `
            <div class="reservation-result-success">
                <h4 class="reservation-result-heading">
                    <i class="fas fa-check-circle"></i> Reservation Successful
                </h4>
                <p class="reservation-result-label"><strong>EJFAT_URI</strong></p>
                <div class="reservation-result-uri">
                    <code>${ejfatUri}</code>
                </div>
                <div class="reservation-result-warning">
                    <p>
                        <i class="fas fa-exclamation-triangle"></i> <strong>IMPORTANT:</strong>
                        This EJFAT URI contains your authentication token and will only be shown once.
                        Store it securely before navigating away from this page.
                    </p>
                </div>
                <button type="button" id="copy-ejfat-uri-btn" class="action-button">
                    <i class="fas fa-copy"></i> Copy to Clipboard
                </button>
                <button type="button" id="view-lb-dashboard-btn" class="action-button">
                    <i class="fas fa-chart-line"></i> View Dashboard
                </button>
            </div>
        `;

        // Copy functionality
        const copyBtn = document.getElementById('copy-ejfat-uri-btn');
        if (copyBtn) {
            copyBtn.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(ejfatUri);
                    copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    showToast('EJFAT URI copied to clipboard', 'success');
                    setTimeout(() => {
                        copyBtn.innerHTML = '<i class="fas fa-copy"></i> Copy to Clipboard';
                    }, 2000);
                } catch (err) {
                    showToast('Failed to copy to clipboard', 'error');
                }
            });
        }

        // Dashboard navigation
        const viewDashboardBtn = document.getElementById('view-lb-dashboard-btn');
        if (viewDashboardBtn) {
            viewDashboardBtn.addEventListener('click', async () => {
                const { renderLoadBalancers } = await import('../sidebar.js');
                const overviewData = await apiFetch('/overview');
                renderLoadBalancers(overviewData);
                const { navigateTo } = await import('../router.js');
                navigateTo(`/lb/${response.lb_id}`);
            });
        }

        showToast('Load Balancer reserved successfully!', 'success');

        // Disable form to prevent re-submission
        submitReservationBtn.style.display = 'none';
        reservationNameInput.disabled = true;
        reservationSendersInput.disabled = true;
        reservationIpFamilySelect.disabled = true;
        reservationStrategySelect.disabled = true;

    } catch (error) {
        console.error('Failed to reserve load balancer:', error);
        reservationResultDiv.textContent = '';
    } finally {
        if (!reservationResultDiv.innerHTML) {
            submitReservationBtn.disabled = false;
            submitReservationBtn.textContent = 'Reserve';
        }
    }
};
