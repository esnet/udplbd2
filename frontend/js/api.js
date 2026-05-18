// SPDX-License-Identifier: BSD-3-Clause-LBNL
// API fetch wrapper and cookie helpers

import { state, API_BASE_URL, AUTH_COOKIE_NAME } from './state.js';

// --- Cookie Functions ---

export const setCookie = (name, value, days) => {
    let expires = '';
    if (days) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        expires = '; expires=' + date.toUTCString();
    }
    document.cookie = `${name}=${value || ''}${expires}; path=/; SameSite=Lax; Secure`;
};

export const getCookie = (name) => {
    const nameEQ = name + '=';
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i].trimStart();
        if (c.startsWith(nameEQ)) return c.substring(nameEQ.length, c.length);
    }
    return null;
};

export const eraseCookie = (name) => {
    document.cookie = `${name}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT; SameSite=Lax; Secure`;
};

// --- Late-bound auth modal callback ---
// Set by auth.js during initialization to avoid circular dependency
let _showAuthModalFn = null;

export const setAuthModalCallback = (fn) => {
    _showAuthModalFn = fn;
};

// --- API Call Function ---

export const apiFetch = async (endpoint, options = {}) => {
    if (!state.authToken) {
        console.error('API call attempted without authToken.');
        if (_showAuthModalFn) _showAuthModalFn('Authentication token is missing. Please authenticate.');
        throw new Error('Authentication required');
    }
    const url = `${API_BASE_URL}${endpoint}`;
    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.authToken}`,
        ...options.headers
    };
    try {
        const response = await fetch(url, { ...options, headers });
        if (response.status === 401 || response.status === 403) {
            console.error(`Authentication/Authorization Error (${response.status})`);
            eraseCookie(AUTH_COOKIE_NAME);
            state.authToken = null;
            if (_showAuthModalFn) _showAuthModalFn('Authentication failed or token expired. Please re-authenticate.');
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Failed to parse error response' }));
            console.error(`API Error (${response.status}) ${options.method || 'GET'} ${endpoint}:`, errorData);
            // Lazy import to avoid circular dependency at module load time
            const { showToast } = await import('./ui.js');
            showToast(`Error: ${errorData.error || `HTTP status ${response.status}`}`);
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.status === 204 ? null : await response.json();
    } catch (error) {
        console.error(`Workspace Error ${options.method || 'GET'} ${endpoint}:`, error);
        if (!error.message.startsWith('HTTP error!') && error.message !== 'Authentication required') {
            const { showToast } = await import('./ui.js');
            showToast(`Network or fetch error: ${error.message}`);
        }
        throw error;
    }
};
