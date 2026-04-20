// SPDX-License-Identifier: BSD-3-Clause-LBNL
// UI utilities: toast, alerts, view switching, sidebar highlighting

import { state } from './state.js';

// --- View Switching ---

export const switchView = (viewId) => {
    document.getElementById(state.activeView)?.classList.remove('active');
    document.getElementById(viewId)?.classList.add('active');
    state.activeView = viewId;
    // Clear right sidebar if not showing dashboard
    if (viewId !== 'dashboard-view') {
        const receiverList = document.getElementById('receiver-list');
        if (receiverList) {
            receiverList.innerHTML = '<li class="no-receivers">Select an LB to see receivers.</li>';
        }
    }
};

// --- Sidebar Highlighting ---

export const updateActiveSidebarItem = (targetPath) => {
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

// --- Toast Notifications ---

export const showToast = (message, type = 'info', duration = 4000) => {
    const container = document.getElementById('toast-container');
    if (!container) {
        console.error('Toast container element not found in DOM.');
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

// --- Load Balancer Alert ---

export const showLbAlert = (message) => {
    const lbAlertArea = document.getElementById('lb-alert-area');
    if (!lbAlertArea) {
        console.error('Load balancer alert area element not found in DOM.');
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
