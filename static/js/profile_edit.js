(function () {
    'use strict';

    /** 首页个人信息弹窗：资料编辑、头像、改密 */
    let currentUser = null;
    let initialized = false;

    // -------------------------------------------------------------------------
    // 头像展示与表单填充
    // -------------------------------------------------------------------------

    function profileDisplayInitial(name) {
        const text = String(name || '').trim();
        if (!text) return '?';
        return text.slice(0, 1).toUpperCase();
    }

    function applyProfileAvatarToElements(avatarUrl, displayName, extraImgIds, extraFallbackIds) {
        const imgIds = ['profileModalAvatar'].concat(extraImgIds || []);
        const fallbackIds = ['profileModalAvatarFallback'].concat(extraFallbackIds || []);
        const initial = profileDisplayInitial(displayName);
        imgIds.forEach(id => {
            const img = document.getElementById(id);
            if (!img) return;
            if (avatarUrl) {
                img.src = `${avatarUrl}&_=${Date.now()}`;
                img.alt = displayName || '头像';
                img.hidden = false;
            } else {
                img.removeAttribute('src');
                img.hidden = true;
            }
        });
        fallbackIds.forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.textContent = initial;
            el.style.display = avatarUrl ? 'none' : 'flex';
        });
    }

    function formatProfileSystemPermission(profile) {
        if (!profile) return '';
        if (profile.system_permission_label) return profile.system_permission_label;
        if (!profile.is_admin) return '';
        if (profile.can_grant_admin) return '管理员（可授权管理员）';
        return '管理员';
    }

    function fillProfileSupervisorSelect(candidates, selectedId) {
        const el = document.getElementById('profileDirectSupervisor');
        if (!el) return;
        const selected = selectedId ? String(selectedId) : '';
        let label = '无';
        (candidates || []).some(item => {
            const id = String(item.id || '');
            if (!id || id !== selected) return false;
            label = item.label || id;
            return true;
        });
        el.textContent = label;
    }

    function fillProfileModalForm(profile, supervisorCandidates) {
        if (!profile) return;
        const nameEl = document.getElementById('profileName');
        if (nameEl) nameEl.textContent = (profile.name || profile.display_name || '').trim() || '—';
        const phoneEl = document.getElementById('profilePhone');
        if (phoneEl) phoneEl.value = profile.phone || '';
        const birthdayEl = document.getElementById('profileBirthday');
        if (birthdayEl) birthdayEl.value = (profile.birthday || '').toString().slice(0, 10);
        const jobEl = document.getElementById('profileJobTitle');
        if (jobEl) jobEl.textContent = (profile.job_title || '').trim() || '—';
        const supervisorEl = document.getElementById('profileDirectSupervisor');
        if (supervisorEl) {
            const supervisorLabel = (profile.direct_supervisor_label || '').trim();
            if (supervisorLabel) {
                supervisorEl.textContent = supervisorLabel;
            } else if (profile.direct_supervisor_id) {
                fillProfileSupervisorSelect(supervisorCandidates, profile.direct_supervisor_id);
            } else {
                supervisorEl.textContent = '无';
            }
        }
        const hireEl = document.getElementById('profileHireDate');
        if (hireEl) {
            const hire = profile.hire_date ? String(profile.hire_date).slice(0, 10) : '';
            hireEl.textContent = hire || '—';
        }
        const usernameEl = document.getElementById('profileUsername');
        if (usernameEl) usernameEl.value = profile.username || '';
        const permGroup = document.getElementById('profileSystemPermissionGroup');
        const permEl = document.getElementById('profileSystemPermission');
        const permLabel = formatProfileSystemPermission(profile);
        if (permGroup) permGroup.hidden = !permLabel;
        if (permEl) permEl.textContent = permLabel || '—';
        const createdEl = document.getElementById('profileCreatedAt');
        if (createdEl) createdEl.textContent = profile.created_at || '—';
        const displayName = profile.display_name || profile.name || profile.username || '用户';
        applyProfileAvatarToElements(profile.avatar_url || null, displayName);
    }

    function clearProfilePasswordFields() {
        const a = document.getElementById('profileNewPassword');
        const b = document.getElementById('profileNewPasswordConfirm');
        if (a) a.value = '';
        if (b) b.value = '';
    }

    function showProfileHint(message, isError) {
        const hint = document.getElementById('profileModalHint');
        if (!hint) return;
        hint.textContent = message || '';
        hint.style.display = message ? 'block' : 'none';
        hint.classList.toggle('error', !!isError);
        hint.classList.toggle('success', !isError && !!message);
    }

    function dispatchProfileUpdated(profile) {
        document.dispatchEvent(new CustomEvent('sitjoy:profile-updated', { detail: profile || null }));
    }

    function mergeCurrentUserProfile(profile) {
        if (!profile) return;
        if (!currentUser) currentUser = {};
        Object.assign(currentUser, profile);
        currentUser.display_name = profile.display_name || profile.name || currentUser.username;
        currentUser.name = profile.name || currentUser.name;
        const displayName = currentUser.display_name || currentUser.name || currentUser.username || '用户';
        applyProfileAvatarToElements(currentUser.avatar_url || null, displayName);
        dispatchProfileUpdated(currentUser);
    }

    function closeProfileModal() {
        const modal = document.getElementById('profileModal');
        if (modal) modal.classList.remove('active');
        const input = document.getElementById('profileAvatarInput');
        if (input) input.value = '';
        clearProfilePasswordFields();
    }

    // -------------------------------------------------------------------------
    // 弹窗打开 / 保存 / 头像与密码
    // -------------------------------------------------------------------------

    async function openProfileModal() {
        if (!currentUser) {
            try {
                const resp = await fetch('/api/auth?action=current', { credentials: 'include' });
                const data = await resp.json();
                if (data.status === 'success') {
                    currentUser = data;
                } else {
                    return;
                }
            } catch (_err) {
                return;
            }
        }
        const modal = document.getElementById('profileModal');
        if (!modal) return;
        const hint = document.getElementById('profileModalHint');
        if (hint) {
            hint.style.display = 'none';
            hint.textContent = '';
        }
        clearProfilePasswordFields();
        fillProfileModalForm(currentUser, []);
        modal.classList.add('active');
        try {
            const resp = await fetch('/api/profile', { credentials: 'include' });
            const data = await resp.json();
            if (data.status === 'success' && data.profile) {
                mergeCurrentUserProfile(data.profile);
                fillProfileModalForm(data.profile, data.supervisor_candidates || []);
            }
        } catch (_err) {
            /* 使用 currentUser 已填写的表单 */
        }
    }

    async function saveProfile() {
        const payload = {
            username: (document.getElementById('profileUsername').value || '').trim(),
            phone: (document.getElementById('profilePhone').value || '').trim(),
            birthday: (document.getElementById('profileBirthday').value || '').trim()
        };
        if (!payload.username) {
            showProfileHint('登录账号不能为空', true);
            return;
        }
        const btn = document.getElementById('profileSaveBtn');
        if (btn) btn.disabled = true;
        try {
            const resp = await fetch('/api/profile', {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await resp.json();
            if (data.status === 'success' && data.profile) {
                mergeCurrentUserProfile(data.profile);
                window.__sitjoyAuthStatePromise = null;
                showProfileHint(data.message || '已保存', false);
                setTimeout(() => closeProfileModal(), 500);
            } else {
                showProfileHint(data.message || '保存失败', true);
            }
        } catch (_err) {
            showProfileHint('保存失败，请稍后重试', true);
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function uploadProfileAvatar(file) {
        if (!file) return;
        const formData = new FormData();
        formData.append('avatar', file);
        showProfileHint('正在上传头像…', false);
        try {
            const resp = await fetch('/api/profile?action=upload_avatar', {
                method: 'POST',
                credentials: 'include',
                body: formData
            });
            const data = await resp.json();
            if (data.status === 'success' && data.profile) {
                mergeCurrentUserProfile(data.profile);
                window.__sitjoyAuthStatePromise = null;
                showProfileHint(data.message || '头像已更新', false);
            } else {
                showProfileHint(data.message || '上传失败', true);
            }
        } catch (_err) {
            showProfileHint('上传失败，请稍后重试', true);
        }
    }

    async function changeProfilePassword() {
        const password = (document.getElementById('profileNewPassword') || {}).value || '';
        const passwordConfirm = (document.getElementById('profileNewPasswordConfirm') || {}).value || '';
        if (password.length < 6) {
            showProfileHint('新密码至少 6 位', true);
            return;
        }
        if (password !== passwordConfirm) {
            showProfileHint('两次输入的密码不一致', true);
            return;
        }
        const btn = document.getElementById('profileChangePasswordBtn');
        if (btn) btn.disabled = true;
        try {
            const resp = await fetch('/api/profile?action=change_password', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password, password_confirm: passwordConfirm })
            });
            const data = await resp.json();
            if (data.status === 'success') {
                clearProfilePasswordFields();
                showProfileHint(data.message || '密码已修改', false);
            } else {
                showProfileHint(data.message || '修改失败', true);
            }
        } catch (_err) {
            showProfileHint('修改失败，请稍后重试', true);
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function removeProfileAvatar() {
        if (!currentUser || !currentUser.avatar_url) return;
        if (!window.confirm('确定移除当前头像？')) return;
        try {
            const resp = await fetch('/api/profile', {
                method: 'DELETE',
                credentials: 'include'
            });
            const data = await resp.json();
            if (data.status === 'success' && data.profile) {
                mergeCurrentUserProfile(data.profile);
                window.__sitjoyAuthStatePromise = null;
                showProfileHint(data.message || '头像已移除', false);
            } else {
                showProfileHint(data.message || '操作失败', true);
            }
        } catch (_err) {
            showProfileHint('操作失败，请稍后重试', true);
        }
    }

    // -------------------------------------------------------------------------
    // 事件绑定与启动
    // -------------------------------------------------------------------------

    function bindEvents() {
        if (initialized) return;
        initialized = true;

        const saveBtn = document.getElementById('profileSaveBtn');
        if (saveBtn) saveBtn.addEventListener('click', saveProfile);

        ['profileModalCloseBtn', 'profileModalCancelBtn'].forEach(id => {
            const btn = document.getElementById(id);
            if (btn) btn.addEventListener('click', closeProfileModal);
        });

        const modal = document.getElementById('profileModal');
        if (modal && typeof window.bindBackdrop === 'function') {
            window.bindBackdrop(modal, closeProfileModal);
        } else if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) closeProfileModal();
            });
        }

        const profileAvatarInput = document.getElementById('profileAvatarInput');
        if (profileAvatarInput) {
            profileAvatarInput.addEventListener('change', e => {
                const file = e.target.files && e.target.files[0];
                if (file) uploadProfileAvatar(file);
                e.target.value = '';
            });
        }

        const profileAvatarRemoveBtn = document.getElementById('profileAvatarRemoveBtn');
        if (profileAvatarRemoveBtn) profileAvatarRemoveBtn.addEventListener('click', removeProfileAvatar);

        const profileChangePasswordBtn = document.getElementById('profileChangePasswordBtn');
        if (profileChangePasswordBtn) profileChangePasswordBtn.addEventListener('click', changeProfilePassword);
    }

    window.SitjoyProfile = {
        init(user) {
            if (user && user.status === 'success') currentUser = user;
            bindEvents();
        },
        setUser(user) {
            if (user) currentUser = user;
        },
        getUser() {
            return currentUser;
        },
        openModal: openProfileModal,
        closeModal: closeProfileModal,
        applyAvatar(avatarUrl, displayName, extraImgIds, extraFallbackIds) {
            applyProfileAvatarToElements(avatarUrl, displayName, extraImgIds, extraFallbackIds);
        }
    };

    window.openProfileModal = openProfileModal;
    window.closeProfileModal = closeProfileModal;
})();
