// SPDX-License-Identifier: BSD-3-Clause-LBNL
// Token management: create token form, permission rows, child tokens

import {
    state,
    ResourceTypeMap,
    PermissionTypeMap,
    ResourceTypeOptions,
    PermissionTypeOptions
} from '../state.js';
import { apiFetch } from '../api.js';
import { switchView } from '../ui.js';

// --- Token Permissions Rendering ---

export const renderTokenPermissions = (data) => {
    const currentTokenDetailsDiv = document.getElementById('current-token-details');
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
        <p><strong>Name:</strong> <span class="token-name-display"></span></p>
        <p><strong>Created:</strong> ${createdAtDate}</p>
        <h4>Permissions:</h4>
        ${permissionsHtml}
    `;
    // Set token name safely using textContent to prevent XSS
    currentTokenDetailsDiv.querySelector('.token-name-display').textContent = name || 'Unnamed';
};

// --- Child Tokens Rendering ---

export const renderChildTokens = (data) => {
    const childTokensListUl = document.getElementById('child-tokens-list');
    childTokensListUl.innerHTML = '';
    if (!data?.tokens?.length) {
        childTokensListUl.innerHTML = '<li>No child tokens found.</li>';
        return;
    }

    data.tokens.forEach(token => {
        const { name, permissions, created_at, id, token: tokenValue } = token;
        const createdAtDate = created_at ? new Date(created_at).toLocaleString() : 'N/A';
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
            <h4 class="child-token-name"></h4>
            <button class="revoke-child-btn danger-button" data-token-id="${revokeTarget}" ${revokeTarget === 'unknown' ? 'disabled title="Cannot revoke unknown token"' : 'title="Revoke this token"'}>Revoke</button>
            <p><small>Created: ${createdAtDate}</small></p>
            <div class="permissions-list">
                ${permissionsHtml}
            </div>
        `;
        // Set child token name safely using textContent to prevent XSS
        li.querySelector('.child-token-name').textContent = name || 'Unnamed Token';
        const revokeBtn = li.querySelector('.revoke-child-btn[data-token-id]');
        if (revokeBtn && revokeTarget !== 'unknown') {
            revokeBtn.addEventListener('click', () => {
                handleRevokeToken(revokeTarget);
            });
        }
        childTokensListUl.appendChild(li);
    });
};

// --- Token Management View ---

export const showTokenManagementView = async () => {
    state.currentSelectedLbId = null;
    switchView('token-management-view');

    const tokenViewLoading = document.getElementById('token-view-loading');
    const tokenViewContent = document.getElementById('token-view-content');
    const currentTokenDetailsDiv = document.getElementById('current-token-details');
    const childTokensListUl = document.getElementById('child-tokens-list');

    tokenViewLoading.classList.remove('hidden');
    tokenViewContent.classList.add('hidden');
    currentTokenDetailsDiv.innerHTML = '';
    childTokensListUl.innerHTML = '';

    try {
        const [permissionsData, childrenData] = await Promise.all([
            apiFetch('/tokens/self/permissions'),
            apiFetch('/tokens/self/children')
        ]);
        renderTokenPermissions(permissionsData);
        renderChildTokens(childrenData);
    } catch (error) {
        console.error('Failed to load token management data:', error);
        currentTokenDetailsDiv.innerHTML = '<p>Error loading token details.</p>';
        childTokensListUl.innerHTML = '<li>Error loading child tokens.</li>';
    } finally {
        tokenViewLoading.classList.add('hidden');
        tokenViewContent.classList.remove('hidden');
    }
};

// --- Permission Row ---

export const createPermissionRow = (initial = {}) => {
    const permissionsListDiv = document.getElementById('permissions-list');
    const row = document.createElement('div');
    row.className = 'permission-row';

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
        if (permissionsListDiv.childElementCount === 1) {
            permissionsListDiv.querySelector('.remove-permission-btn').style.display = 'none';
        }
    });

    row.appendChild(resourceTypeSelect);
    row.appendChild(resourceIdInput);
    row.appendChild(permissionTypeSelect);
    row.appendChild(removeBtn);

    return row;
};

export const ensureAtLeastOnePermissionRow = () => {
    const permissionsListDiv = document.getElementById('permissions-list');
    if (!permissionsListDiv.querySelector('.permission-row')) {
        permissionsListDiv.appendChild(createPermissionRow());
    }
    const removeBtns = permissionsListDiv.querySelectorAll('.remove-permission-btn');
    removeBtns.forEach(btn => btn.style.display = removeBtns.length > 1 ? 'inline-block' : 'none');
};

// --- Token Creation Form ---

export const setupTokenCreationForm = () => {
    const addPermissionBtn = document.getElementById('add-permission-btn');
    const createTokenForm = document.getElementById('create-token-form');
    const permissionsListDiv = document.getElementById('permissions-list');

    if (addPermissionBtn) {
        addPermissionBtn.addEventListener('click', () => {
            permissionsListDiv.appendChild(createPermissionRow());
            const removeBtns = permissionsListDiv.querySelectorAll('.remove-permission-btn');
            removeBtns.forEach(btn => btn.style.display = removeBtns.length > 1 ? 'inline-block' : 'none');
        });
    }

    if (permissionsListDiv) {
        ensureAtLeastOnePermissionRow();
    }

    if (createTokenForm) {
        createTokenForm.addEventListener('submit', handleCreateTokenSubmit);
    }
};

const handleCreateTokenSubmit = async (e) => {
    e.preventDefault();
    const createTokenResultDiv = document.getElementById('create-token-result');
    const newTokenNameInput = document.getElementById('new-token-name');
    const permissionsListDiv = document.getElementById('permissions-list');

    createTokenResultDiv.textContent = '';
    createTokenResultDiv.className = 'create-token-result';

    const name = newTokenNameInput.value.trim();
    if (!name) {
        createTokenResultDiv.textContent = 'Token name is required.';
        createTokenResultDiv.classList.add('error-message');
        return;
    }

    const permissionRows = permissionsListDiv.querySelectorAll('.permission-row');
    const permissions = [];
    let hasError = false;
    permissionRows.forEach(row => {
        const resourceType = parseInt(row.querySelector('.perm-resource-type').value);
        const resourceId = row.querySelector('.perm-resource-id').value.trim();
        const permission = parseInt(row.querySelector('.perm-permission-type').value);

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

    try {
        createTokenResultDiv.textContent = 'Creating token...';
        createTokenResultDiv.classList.remove('error-message');
        const reply = await apiFetch('/tokens', {
            method: 'POST',
            body: JSON.stringify({ name, permissions })
        });
        const ejfatUriHtml = reply.ejfat_uri ? `<br><span class="token-result-label">EJFAT URI:</span><br><code>${reply.ejfat_uri}</code>` : '';
        createTokenResultDiv.innerHTML = `<span class="token-result-label">Token created:</span><br><code>${reply.token}</code>${ejfatUriHtml}<br><small>Store this token securely. It will not be shown again.</small>`;
        createTokenResultDiv.classList.remove('error-message');
        createTokenResultDiv.classList.add('success-message');

        const createTokenForm = document.getElementById('create-token-form');
        createTokenForm.reset();
        permissionsListDiv.innerHTML = '';
        ensureAtLeastOnePermissionRow();

        if (state.activeView === 'token-management-view') {
            const childrenData = await apiFetch('/tokens/self/children');
            renderChildTokens(childrenData);
        }
    } catch (error) {
        createTokenResultDiv.textContent = 'Failed to create token: ' + (error?.message || 'Unknown error');
        createTokenResultDiv.classList.add('error-message');
    }
};

// --- Revoke Token ---

export const handleRevokeToken = async (tokenIdOrToken) => {
    if (!tokenIdOrToken || tokenIdOrToken === 'unknown') return alert('Error: Token identifier missing or invalid.');
    if (!confirm(`Revoke token "${tokenIdOrToken}" and its children? This is irreversible.`)) return;
    console.log('Revoking token:', tokenIdOrToken);
    try {
        await apiFetch(`/tokens/${tokenIdOrToken}`, { method: 'DELETE' });
        alert(`Token ${tokenIdOrToken} revoked successfully.`);
        if (state.activeView === 'token-management-view') {
            const [permissionsData, childrenData] = await Promise.all([
                apiFetch('/tokens/self/permissions'),
                apiFetch('/tokens/self/children')
            ]);
            renderTokenPermissions(permissionsData);
            renderChildTokens(childrenData);
        }
    } catch (error) { /* Handled by apiFetch */ }
};
