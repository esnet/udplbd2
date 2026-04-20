// SPDX-License-Identifier: BSD-3-Clause-LBNL
// System information view

import { state } from '../state.js';
import { apiFetch } from '../api.js';
import { switchView } from '../ui.js';

// --- Version Info Rendering ---

export const renderVersionInfo = (data) => {
    const versionDetailsDiv = document.getElementById('version-details');
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

// --- System Info View ---

export const showSystemInfoView = async () => {
    state.currentSelectedLbId = null;
    switchView('system-info-view');

    const systemViewLoading = document.getElementById('system-view-loading');
    const systemViewContent = document.getElementById('system-view-content');
    const versionDetailsDiv = document.getElementById('version-details');

    systemViewLoading.classList.remove('hidden');
    systemViewContent.classList.add('hidden');
    versionDetailsDiv.innerHTML = '';

    try {
        const versionData = await apiFetch('/version');
        renderVersionInfo(versionData);
    } catch (error) {
        console.error('Failed to load system info:', error);
        renderVersionInfo(null);
    } finally {
        systemViewLoading.classList.add('hidden');
        systemViewContent.classList.remove('hidden');
    }
};
