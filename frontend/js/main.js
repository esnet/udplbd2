// SPDX-License-Identifier: BSD-3-Clause-LBNL
// Entry point: wires modules together, initializes the application

import { state } from './state.js';
import { apiFetch } from './api.js';
import { checkAuth, handleAuthSubmit, setupLogout } from './auth.js';
import { navigateTo, handleRouteChange, initRouter } from './router.js';
import { renderLoadBalancers, startOverviewPolling } from './sidebar.js';
import { highlightSession, setupChartTabSwitching, setupClearFilter } from './charts.js';
import { handleAddSender, handleGenerateChildToken, handleFreeLb } from './views/dashboard.js';
import { handleReservationSubmit } from './views/reservation.js';
import { setupTokenCreationForm } from './views/tokens.js';

// --- Application Initialization ---

const initializeApp = async () => {
    console.log('Initializing authenticated application...');
    const initialLoadIndicator = document.getElementById('initial-load-indicator');
    initialLoadIndicator.classList.remove('hidden');

    // Load initial LB list for the sidebar
    try {
        const overviewData = await apiFetch('/overview');
        renderLoadBalancers(overviewData);
        startOverviewPolling();
    } catch (error) {
        const lbList = document.getElementById('lb-list');
        lbList.innerHTML = '<li class="no-receivers">Error loading LBs.</li>';
        console.error('Failed to load overview on init:', error);
    }

    // Handle initial route based on URL path
    handleRouteChange(window.location.pathname);
    initialLoadIndicator.classList.add('hidden');
};

// --- DOM Content Loaded ---

document.addEventListener('DOMContentLoaded', () => {
    // Setup event listeners for static buttons
    setupLogout();

    const tokenMgmtBtn = document.getElementById('token-mgmt-btn');
    const sysInfoBtn = document.getElementById('sys-info-btn');
    if (tokenMgmtBtn) {
        tokenMgmtBtn.addEventListener('click', () => navigateTo('/tools/tokens'));
    }
    if (sysInfoBtn) {
        sysInfoBtn.addEventListener('click', () => navigateTo('/tools/system'));
    }

    // Dashboard action buttons
    const addSenderBtn = document.getElementById('add-sender-btn');
    const generateChildTokenBtn = document.getElementById('generate-child-token-btn');
    const freeLbBtn = document.getElementById('free-lb-btn');

    if (addSenderBtn) addSenderBtn.addEventListener('click', handleAddSender);
    const newSenderIpInput = document.getElementById('new-sender-ip');
    if (newSenderIpInput) newSenderIpInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleAddSender();
    });
    if (generateChildTokenBtn) generateChildTokenBtn.addEventListener('click', handleGenerateChildToken);
    if (freeLbBtn) freeLbBtn.addEventListener('click', handleFreeLb);

    // Reservation form
    const reservationForm = document.getElementById('reservation-form');
    const cancelReservationBtn = document.getElementById('cancel-reservation-btn');
    if (reservationForm) reservationForm.addEventListener('submit', handleReservationSubmit);
    if (cancelReservationBtn) {
        cancelReservationBtn.addEventListener('click', (e) => {
            e.preventDefault();
            navigateTo('/');
        });
    }

    // Token creation form
    setupTokenCreationForm();

    // Chart tab switching
    setupChartTabSwitching();

    // Clear receiver filter
    setupClearFilter();

    // Sidebar navigation (event delegation)
    document.addEventListener('click', (event) => {
        // Left Sidebar LB items
        const lbItem = event.target.closest('.left-sidebar li[data-target-path]');
        if (lbItem && lbItem.dataset.targetPath) {
            event.preventDefault();
            navigateTo(lbItem.dataset.targetPath);
            return;
        }

        // Left Sidebar Tool buttons
        const toolButton = event.target.closest('.left-sidebar button[data-target-path]');
        if (toolButton && toolButton.dataset.targetPath) {
            event.preventDefault();
            navigateTo(toolButton.dataset.targetPath);
            return;
        }
    });

    // Session highlighting on hover
    document.addEventListener('mouseover', (event) => {
        const receiverItem = event.target.closest('#receiver-list li');
        if (receiverItem) {
            const receiverName = receiverItem.querySelector('.receiver-name')?.textContent;
            if (receiverName) highlightSession(receiverName);
        }
    });

    document.addEventListener('mouseout', (event) => {
        const receiverItem = event.target.closest('#receiver-list li');
        if (receiverItem && !receiverItem.contains(event.relatedTarget)) {
            Object.values(state.uPlotCharts).forEach(chart => {
                if (chart) chart.setSeries(null, { focus: false });
            });
        }
    });

    // Auth form listener
    const authForm = document.getElementById('auth-form');
    if (authForm) {
        authForm.addEventListener('submit', (event) => {
            event.preventDefault();
            handleAuthSubmit(event, initializeApp);
        });
    }

    // Initialize router
    initRouter();

    // Start authentication check
    checkAuth(initializeApp);
});
