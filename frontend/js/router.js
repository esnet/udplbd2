// SPDX-License-Identifier: BSD-3-Clause-LBNL
// SPA routing: navigateTo, handleRouteChange, popstate

import { state } from './state.js';
import { switchView, updateActiveSidebarItem } from './ui.js';
import { stopChartPolling } from './charts.js';
import { showDashboardView } from './views/dashboard.js';
import { showReservationView, handleReservationSubmit } from './views/reservation.js';
import { showTokenManagementView } from './views/tokens.js';
import { showSystemInfoView } from './views/system.js';
import { showAuthModal } from './auth.js';

// --- Navigation ---

export const navigateTo = (path, replace = false) => {
    if (!state.authToken) return showAuthModal('Please authenticate first.');

    // Prevent pushing the same path multiple times consecutively
    if (path === state.currentPath && !replace) return;

    console.log(`Navigating to: ${path}`);
    state.currentPath = path;

    const historyState = { path: path };
    if (replace) {
        history.replaceState(historyState, '', path);
    } else {
        history.pushState(historyState, '', path);
    }

    handleRouteChange(path);
};

// --- Route Change Handler ---

export const handleRouteChange = (path) => {
    if (!state.authToken) {
        // Lazy import to avoid issues - checkAuth is in auth.js
        import('./auth.js').then(({ checkAuth }) => checkAuth());
        return;
    }

    updateActiveSidebarItem(path);

    const segments = path.split('/').filter(Boolean);

    if (segments.length === 0) {
        // Root path "/"
        switchView('placeholder-view');
        state.currentSelectedLbId = null;
    } else if (segments[0] === 'lb' && segments[1]) {
        if (segments[1] === 'reserve') {
            showReservationView();
        } else {
            const lbId = segments[1];
            showDashboardView(lbId);
        }
    } else if (segments[0] === 'tools') {
        if (segments[1] === 'tokens') {
            showTokenManagementView();
        } else if (segments[1] === 'system') {
            showSystemInfoView();
        } else {
            switchView('placeholder-view');
            state.currentSelectedLbId = null;
        }
    } else {
        switchView('placeholder-view');
        state.currentSelectedLbId = null;
    }
};

// --- Router Initialization ---

export const initRouter = () => {
    // Popstate listener for browser back/forward
    window.addEventListener('popstate', (event) => {
        const path = event.state?.path || window.location.pathname;
        console.log(`Handling popstate to: ${path}`);
        state.currentPath = path;
        handleRouteChange(path);
    });
};
