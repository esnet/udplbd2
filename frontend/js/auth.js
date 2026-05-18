// SPDX-License-Identifier: BSD-3-Clause-LBNL
// Authentication: modal, token extraction, login/logout

import { state, AUTH_COOKIE_NAME, COOKIE_EXPIRY_DAYS } from './state.js';
import { apiFetch, setCookie, getCookie, eraseCookie, setAuthModalCallback } from './api.js';

// --- Auth Modal ---

export const showAuthModal = (errorMessage = null) => {
    console.log('Authentication required. Showing modal.');
    const authInput = document.getElementById('auth-input');
    const authError = document.getElementById('auth-error');
    const authModal = document.getElementById('auth-modal');
    authInput.value = '';
    authError.textContent = errorMessage || '';
    authError.style.display = errorMessage ? 'block' : 'none';
    authModal.style.display = 'block';
    authInput.focus();
};

export const hideAuthModal = () => {
    const authModal = document.getElementById('auth-modal');
    const authError = document.getElementById('auth-error');
    authModal.style.display = 'none';
    authError.style.display = 'none';
};

// Register the auth modal callback with api.js to avoid circular dependency
setAuthModalCallback(showAuthModal);

// --- Token Extraction ---

export const extractTokenFromInput = (inputValue) => {
    const trimmedValue = inputValue.trim();
    try {
        // Check for EJFAT URI specifically
        if (trimmedValue.toLowerCase().startsWith('ejfats://')) {
            const url = new URL(trimmedValue);
            // Token is in the 'username' part for ejfats://token@host...
            if (url.username) {
                console.log('Extracted token from EJFAT URI username.');
                return url.username;
            } else {
                console.warn('EJFAT URI detected but no token found in username part.');
                return null;
            }
        }

        // If not EJFAT, check if it's a regular URL with ?token= param
        const url = new URL(trimmedValue);
        const tokenParam = url.searchParams.get('token');
        if (tokenParam) {
            console.log('Extracted token from URL parameter.');
            return tokenParam.trim();
        }
    } catch (_) {
        // If not a valid URL, treat as raw token
        if (trimmedValue.length > 10) {
            console.log('Treating input as raw token.');
            return trimmedValue.startsWith('Bearer ') ? trimmedValue.substring(7) : trimmedValue;
        }
    }
    return null;
};

// --- Auth Form Handler ---

export const handleAuthSubmit = async (event, initializeAppCallback) => {
    event.preventDefault();
    const authError = document.getElementById('auth-error');
    const authSubmitBtn = document.getElementById('auth-submit-btn');
    const authInput = document.getElementById('auth-input');
    const authModal = document.getElementById('auth-modal');

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

    state.authToken = extractedToken; // Tentatively set token
    console.log('Attempting authentication with extracted token...');

    try {
        await apiFetch('/version');
        console.log('Authentication successful.');
        setCookie(AUTH_COOKIE_NAME, state.authToken, COOKIE_EXPIRY_DAYS);
        hideAuthModal();
        initializeAppCallback();
    } catch (error) {
        console.error('Authentication test failed:', error.message);
        // apiFetch handles showing modal again on auth error
    } finally {
        if (authModal.style.display === 'block') {
            authSubmitBtn.disabled = false;
            authSubmitBtn.textContent = 'Authenticate';
        }
    }
};

// --- Auth Check ---

export const checkAuth = (initializeAppCallback) => {
    console.log('Checking authentication...');
    const tokenFromCookie = getCookie(AUTH_COOKIE_NAME);
    if (tokenFromCookie) {
        console.log('Found auth token cookie.');
        state.authToken = tokenFromCookie;
        apiFetch('/version').then(() => {
            console.log('Token validated successfully.');
            initializeAppCallback();
        }).catch(error => {
            console.error('Token validation failed on load:', error.message);
            const authModal = document.getElementById('auth-modal');
            if (!authModal.style.display || authModal.style.display === 'none') {
                showAuthModal('Your session may have expired. Please re-authenticate.');
            }
        });
    } else {
        console.log('No auth token cookie found.');
        showAuthModal();
    }
};

// --- Logout ---

export const setupLogout = () => {
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            eraseCookie(AUTH_COOKIE_NAME);
            window.location.reload();
        });
    }
};
