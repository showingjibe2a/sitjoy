/**
 * Amazon 广告信息新增/编辑弹窗（广告信息页、广告调整页共用）
 */
(function (global) {
    const MODAL_ID = 'ad-modal';
    const STYLE_ID = 'amazon-ad-form-modal-styles';

    let hooks = {};
    let readyPromise = null;
    let adEditId = null;
    let adItemsCache = [];
    let skuOptions = [];
    let categoryMap = new Map();
    let portfolioOptions = [];
    let campaignOptions = [];
    let subtypeOptions = [];
    let eventsBound = false;

    function $(id) { return document.getElementById(id); }

    function ensureModalStyles() {
        if (document.getElementById(STYLE_ID)) return;
        const style = document.createElement('style');
        style.id = STYLE_ID;
        style.textContent = [
            '.switch-field {',
            '  display: inline-flex; align-items: center; gap: 0.55rem;',
            '  min-height: 40px;',
            '  border: 1px solid rgba(207, 199, 189, 0.75);',
            '  border-radius: 10px; padding: 0.44rem 0.6rem;',
            '  background: rgba(236, 231, 223, 0.4);',
            '}',
            '.ad-subtype-segment { max-width: 100%; }',
            '.ad-subtype-segment .status-pill { white-space: nowrap; }',
            '#modalAdLevelSegment[data-locked="1"] {',
            '  opacity: 0.65; pointer-events: none;',
            '}',
        ].join('\n');
        document.head.appendChild(style);
    }

    function ensureModalDom() {
        if ($(MODAL_ID)) return;
        ensureModalStyles();
        const wrap = document.createElement('div');
        wrap.innerHTML = [
            '<div class="pm-modal" id="ad-modal">',
            '  <div class="pm-modal-content">',
            '    <h3 id="ad-modal-title" style="margin-top:0;">新增广告信息</h3>',
            '    <div class="pm-form">',
            '      <div class="form-group pm-form-full">',
            '        <label>广告类型<span class="required-asterisk">*</span></label>',
            '        <input type="hidden" id="modalAdLevel" value="portfolio">',
            '        <div id="modalAdLevelSegment" class="status-segment status-segment--inline">',
            '          <button type="button" class="status-pill" data-target="modalAdLevel" data-value="portfolio" onclick="setSegmentValue(\'modalAdLevel\',\'portfolio\', true)">广告组合（Portfolio）</button>',
            '          <button type="button" class="status-pill" data-target="modalAdLevel" data-value="campaign" onclick="setSegmentValue(\'modalAdLevel\',\'campaign\', true)">广告活动（Campaign）</button>',
            '          <button type="button" class="status-pill" data-target="modalAdLevel" data-value="group" onclick="setSegmentValue(\'modalAdLevel\',\'group\', true)">广告组（Group）</button>',
            '        </div>',
            '      </div>',
            '      <div class="form-group level-portfolio">',
            '        <label>状态<span class="required-asterisk">*</span></label>',
            '        <input type="hidden" id="modalStatusPortfolio" value="启动">',
            '        <div class="status-segment status-segment--inline">',
            '          <button type="button" class="status-pill status-pill--enabled" data-target="modalStatusPortfolio" data-value="启动" onclick="setSegmentValue(\'modalStatusPortfolio\',\'启动\')">启动</button>',
            '          <button type="button" class="status-pill status-pill--paused" data-target="modalStatusPortfolio" data-value="暂停" onclick="setSegmentValue(\'modalStatusPortfolio\',\'暂停\')">暂停</button>',
            '          <button type="button" class="status-pill status-pill--archived" data-target="modalStatusPortfolio" data-value="存档" onclick="setSegmentValue(\'modalStatusPortfolio\',\'存档\')">存档</button>',
            '        </div>',
            '      </div>',
            '      <div class="form-group level-portfolio">',
            '        <label for="modalSkuFamily">关联货号（选填）</label>',
            '        <select id="modalSkuFamily" onchange="onPortfolioSkuChanged()" data-search-placeholder="搜索货号"></select>',
            '      </div>',
            '      <div class="form-group level-portfolio">',
            '        <label for="modalPortfolioName">广告组合名称<span class="required-asterisk">*</span></label>',
            '        <input type="text" id="modalPortfolioName" placeholder="可手动输入或通过货号自动生成">',
            '      </div>',
            '      <div class="form-group level-portfolio">',
            '        <label>是否共享预算<span class="required-asterisk">*</span></label>',
            '        <input type="hidden" id="modalSharedBudget" value="是">',
            '        <div class="switch-field">',
            '          <label class="switch-wrap"><input type="checkbox" id="modalSharedBudgetSwitch" checked onchange="onSharedBudgetSwitchChange()"><span class="switch-slider"></span></label>',
            '          <span id="modalSharedBudgetLabel">是</span>',
            '        </div>',
            '      </div>',
            '      <div class="form-group level-campaign">',
            '        <label>状态<span class="required-asterisk">*</span></label>',
            '        <input type="hidden" id="modalStatusCampaign" value="启动">',
            '        <div class="status-segment status-segment--inline">',
            '          <button type="button" class="status-pill status-pill--enabled" data-target="modalStatusCampaign" data-value="启动" onclick="setSegmentValue(\'modalStatusCampaign\',\'启动\')">启动</button>',
            '          <button type="button" class="status-pill status-pill--paused" data-target="modalStatusCampaign" data-value="暂停" onclick="setSegmentValue(\'modalStatusCampaign\',\'暂停\')">暂停</button>',
            '          <button type="button" class="status-pill status-pill--archived" data-target="modalStatusCampaign" data-value="存档" onclick="setSegmentValue(\'modalStatusCampaign\',\'存档\')">存档</button>',
            '        </div>',
            '      </div>',
            '      <div class="form-group level-campaign">',
            '        <label for="modalCampaignPortfolio">归属广告组合<span class="required-asterisk">*</span></label>',
            '        <select id="modalCampaignPortfolio" onchange="refreshCampaignName()" data-search-placeholder="搜索广告组合"></select>',
            '      </div>',
            '      <div class="form-group level-campaign">',
            '        <label>策略<span class="required-asterisk">*</span></label>',
            '        <input type="hidden" id="modalStrategy" value="BE">',
            '        <div class="status-segment status-segment--inline">',
            '          <button type="button" class="status-pill" data-target="modalStrategy" data-value="BE" onclick="setSegmentValue(\'modalStrategy\',\'BE\', true)">BE - 品牌扩张</button>',
            '          <button type="button" class="status-pill" data-target="modalStrategy" data-value="BD" onclick="setSegmentValue(\'modalStrategy\',\'BD\', true)">BD - 品牌防御</button>',
            '          <button type="button" class="status-pill" data-target="modalStrategy" data-value="PC" onclick="setSegmentValue(\'modalStrategy\',\'PC\', true)">PC - 竞品进攻</button>',
            '        </div>',
            '      </div>',
            '      <div class="form-group level-campaign">',
            '        <label>细分类<span class="required-asterisk">*</span></label>',
            '        <input type="hidden" id="modalSubtype" value="">',
            '        <div id="modalSubtypeSegment" class="status-segment status-segment--inline ad-subtype-segment"></div>',
            '      </div>',
            '      <div class="form-group level-campaign">',
            '        <label for="modalCampaignName">广告活动名称<span class="required-asterisk">*</span></label>',
            '        <input type="text" id="modalCampaignName" placeholder="自动生成，可修改">',
            '      </div>',
            '      <div class="form-group level-campaign">',
            '        <label for="modalBudget">预算</label>',
            '        <input type="number" id="modalBudget" step="0.01" placeholder="例如：50.00">',
            '      </div>',
            '      <div class="form-group level-group">',
            '        <label>状态<span class="required-asterisk">*</span></label>',
            '        <input type="hidden" id="modalStatusGroup" value="启动">',
            '        <div class="status-segment status-segment--inline">',
            '          <button type="button" class="status-pill status-pill--enabled" data-target="modalStatusGroup" data-value="启动" onclick="setSegmentValue(\'modalStatusGroup\',\'启动\')">启动</button>',
            '          <button type="button" class="status-pill status-pill--paused" data-target="modalStatusGroup" data-value="暂停" onclick="setSegmentValue(\'modalStatusGroup\',\'暂停\')">暂停</button>',
            '          <button type="button" class="status-pill status-pill--archived" data-target="modalStatusGroup" data-value="存档" onclick="setSegmentValue(\'modalStatusGroup\',\'存档\')">存档</button>',
            '        </div>',
            '      </div>',
            '      <div class="form-group level-group">',
            '        <label for="modalGroupPortfolio">归属广告组合</label>',
            '        <select id="modalGroupPortfolio" onchange="onGroupPortfolioChanged()" data-search-placeholder="搜索广告组合（可选）"></select>',
            '      </div>',
            '      <div class="form-group level-group">',
            '        <label for="modalGroupCampaign">归属广告活动<span class="required-asterisk">*</span></label>',
            '        <select id="modalGroupCampaign" onchange="onGroupCampaignChanged()" data-search-placeholder="搜索广告活动"></select>',
            '      </div>',
            '      <div class="form-group level-group">',
            '        <label for="modalGroupName">广告组名称<span class="required-asterisk">*</span></label>',
            '        <input type="text" id="modalGroupName" placeholder="例如：核心词-精准">',
            '      </div>',
            '    </div>',
            '    <div id="adModalStatus" class="response" style="display:none; margin-top:0.75rem;"></div>',
            '    <div class="pm-modal-actions">',
            '      <button class="btn-secondary" onclick="closeAdModal()">取消</button>',
            '      <button class="btn-primary" onclick="saveAdFromModal()">保存</button>',
            '    </div>',
            '  </div>',
            '</div>',
        ].join('');
        document.body.appendChild(wrap.firstElementChild);
    }

    function showAdStatus(message, isError) {
        const el = $('adModalStatus');
        if (!el) return;
        el.style.display = 'block';
        el.style.background = isError ? '#ffecec' : '#f0fff0';
        el.style.color = isError ? '#a33' : '#2f6f2f';
        el.innerText = message;
    }

    function resetAdStatus() {
        const el = $('adModalStatus');
        if (!el) return;
        el.style.display = 'none';
        el.innerText = '';
    }

    function loadAdItemsCache() {
        return fetch('/api/amazon-ad')
            .then(r => r.json())
            .then(data => {
                adItemsCache = data.status === 'success' ? (data.items || []) : [];
            })
            .catch(() => { adItemsCache = []; });
    }

    function loadCategoryMap() {
        return fetch('/api/category')
            .then(r => r.json())
            .then(data => {
                categoryMap = new Map();
                if (data.status !== 'success') return;
                (data.items || []).forEach(item => {
                    categoryMap.set(item.category_cn, item.category_en || item.category_cn || '');
                });
            })
            .catch(() => { categoryMap = new Map(); });
    }

    function loadSkuOptions() {
        return fetch('/api/sku')
            .then(r => r.json())
            .then(data => {
                skuOptions = data.status === 'success' ? (data.items || []) : [];
                renderSkuFamilySelect();
            })
            .catch(() => { skuOptions = []; });
    }

    function renderSkuFamilySelect(selectedValue) {
        const select = $('modalSkuFamily');
        const current = String(selectedValue !== undefined ? selectedValue : (select?.value || ''));
        if (!select) return;
        select.innerHTML = '<option value="">请选择货号</option>';
        let hasCurrent = false;
        (skuOptions || []).forEach(item => {
            const option = document.createElement('option');
            option.value = item.id;
            option.textContent = `${item.sku_family}（${item.category || ''}）`;
            if (current && String(item.id) === current) {
                option.selected = true;
                hasCurrent = true;
            }
            select.appendChild(option);
        });
        if (current && !hasCurrent) select.value = '';
        if (global.refreshUniversalSingleSelect) global.refreshUniversalSingleSelect(select);
    }

    function loadSubtypeOptions() {
        return fetch('/api/amazon-ad-subtype')
            .then(r => r.json())
            .then(data => {
                subtypeOptions = data.status === 'success' ? (data.items || []) : [];
                renderSubtypeSegment();
            })
            .catch(() => {
                subtypeOptions = [];
                renderSubtypeSegment();
            });
    }

    function syncSegmentButtons(targetId) {
        const input = $(targetId);
        const value = input ? String(input.value || '') : '';
        document.querySelectorAll(`[data-target="${targetId}"]`).forEach(btn => {
            btn.classList.toggle('is-active', String(btn.getAttribute('data-value') || '') === value);
        });
    }

    function setSegmentValue(targetId, value, triggerRefresh) {
        if (targetId === 'modalAdLevel') {
            const levelSeg = $('modalAdLevelSegment');
            if (levelSeg && levelSeg.getAttribute('data-locked') === '1') return;
        }
        const input = $(targetId);
        if (!input) return;
        input.value = value;
        syncSegmentButtons(targetId);
        if (targetId === 'modalAdLevel') onAdLevelChanged();
        if (triggerRefresh) refreshCampaignName();
    }

    function onSharedBudgetSwitchChange() {
        const checked = !!$('modalSharedBudgetSwitch').checked;
        $('modalSharedBudget').value = checked ? '是' : '否';
        $('modalSharedBudgetLabel').innerText = checked ? '是' : '否';
    }

    function renderSubtypeSegment() {
        const container = $('modalSubtypeSegment');
        const input = $('modalSubtype');
        if (!container || !input) return;
        if (!subtypeOptions.length) {
            container.innerHTML = '<span style="color:var(--morandi-slate);font-size:0.88rem;padding:0.22rem 0.3rem;">暂无细分类</span>';
            input.value = '';
            return;
        }
        const current = String(input.value || '');
        const hasCurrent = subtypeOptions.some(item => String(item.id) === current);
        if (!hasCurrent) input.value = String(subtypeOptions[0].id);
        container.innerHTML = subtypeOptions.map(item => {
            const value = String(item.id);
            const active = String(input.value) === value ? 'is-active' : '';
            const text = `${item.ad_class}-${item.subtype_code}`;
            return `<button type="button" class="status-pill ${active}" data-target="modalSubtype" data-value="${value}" onclick="setSegmentValue('modalSubtype','${value}', true)">${text}</button>`;
        }).join('');
    }

    function loadPortfolioOptions() {
        return fetch('/api/amazon-ad?level=portfolio')
            .then(r => r.json())
            .then(data => {
                portfolioOptions = data.status === 'success' ? (data.items || []) : [];
                renderCampaignPortfolioSelect();
                renderGroupPortfolioSelect();
            })
            .catch(() => { portfolioOptions = []; });
    }

    function renderCampaignPortfolioSelect(selectedValue) {
        const select = $('modalCampaignPortfolio');
        const current = String(selectedValue !== undefined ? selectedValue : (select?.value || ''));
        if (!select) return;
        select.innerHTML = '<option value="">请选择广告组合</option>';
        let hasCurrent = false;
        (portfolioOptions || []).forEach(item => {
            const option = document.createElement('option');
            option.value = item.id;
            option.textContent = item.name || '';
            if (current && String(item.id) === current) {
                option.selected = true;
                hasCurrent = true;
            }
            select.appendChild(option);
        });
        if (current && !hasCurrent) select.value = '';
        if (global.refreshUniversalSingleSelect) global.refreshUniversalSingleSelect(select);
    }

    function renderGroupPortfolioSelect(selectedValue) {
        const select = $('modalGroupPortfolio');
        const current = String(selectedValue !== undefined ? selectedValue : (select?.value || ''));
        if (!select) return;
        select.innerHTML = '<option value="">请选择广告组合</option>';
        let hasCurrent = false;
        (portfolioOptions || []).forEach(item => {
            const option = document.createElement('option');
            option.value = item.id;
            option.textContent = item.name || '';
            if (current && String(item.id) === current) {
                option.selected = true;
                hasCurrent = true;
            }
            select.appendChild(option);
        });
        if (current && !hasCurrent) select.value = '';
        if (global.refreshUniversalSingleSelect) global.refreshUniversalSingleSelect(select);
    }

    function loadCampaignOptions() {
        return fetch('/api/amazon-ad?level=campaign')
            .then(r => r.json())
            .then(data => {
                campaignOptions = data.status === 'success' ? (data.items || []) : [];
                renderGroupCampaignSelect();
            })
            .catch(() => { campaignOptions = []; });
    }

    function renderGroupCampaignSelect(selectedValue) {
        const select = $('modalGroupCampaign');
        const portfolioId = $('modalGroupPortfolio')?.value || '';
        const current = String(selectedValue !== undefined ? selectedValue : (select?.value || ''));
        if (!select) return;
        select.innerHTML = '<option value="">请选择广告活动</option>';
        let hasCurrent = false;
        (campaignOptions || []).forEach(item => {
            if (portfolioId && String(item.portfolio_id || '') !== String(portfolioId)) return;
            const option = document.createElement('option');
            option.value = item.id;
            option.textContent = item.name || '';
            if (current && String(item.id) === current) {
                option.selected = true;
                hasCurrent = true;
            }
            select.appendChild(option);
        });
        if (current && !hasCurrent) select.value = '';
        if (global.refreshUniversalSingleSelect) global.refreshUniversalSingleSelect(select);
    }

    function onGroupPortfolioChanged() {
        const selectedCampaign = $('modalGroupCampaign')?.value || '';
        const valid = (campaignOptions || []).some(item => {
            return String(item.id) === String(selectedCampaign)
                && String(item.portfolio_id || '') === String($('modalGroupPortfolio')?.value || '');
        });
        if (!valid) {
            renderGroupCampaignSelect('');
            onGroupCampaignChanged();
            return;
        }
        renderGroupCampaignSelect(selectedCampaign);
        onGroupCampaignChanged();
    }

    function onGroupCampaignChanged() {
        const campaignId = $('modalGroupCampaign')?.value || '';
        const groupNameInput = $('modalGroupName');
        if (!groupNameInput) return;
        const selectedCampaign = (campaignOptions || []).find(x => String(x.id) === String(campaignId));
        const campaignName = selectedCampaign?.name || '';
        if (!campaignId || !campaignName) {
            if (groupNameInput.dataset.auto === '1') groupNameInput.value = '';
            return;
        }
        if (!groupNameInput.value.trim() || groupNameInput.dataset.auto === '1') {
            groupNameInput.value = campaignName;
            groupNameInput.dataset.auto = '1';
        }
    }

    function buildPortfolioNameBySkuId(skuId) {
        const sku = skuOptions.find(x => String(x.id) === String(skuId));
        if (!sku) return '';
        const short = categoryMap.get(sku.category) || sku.category || '';
        return short && sku.sku_family ? `${short}-${sku.sku_family}` : '';
    }

    function onPortfolioSkuChanged() {
        const skuId = $('modalSkuFamily').value;
        const input = $('modalPortfolioName');
        const built = buildPortfolioNameBySkuId(skuId);
        if (!input) return;
        if (!input.value.trim() || input.dataset.auto === '1') {
            input.value = built;
            input.dataset.auto = built ? '1' : '0';
        }
    }

    function buildCampaignName() {
        const strategy = $('modalStrategy').value;
        const portfolioId = $('modalCampaignPortfolio').value;
        const subtypeId = $('modalSubtype').value;
        const portfolio = portfolioOptions.find(x => String(x.id) === String(portfolioId));
        const subtype = subtypeOptions.find(x => String(x.id) === String(subtypeId));
        if (!strategy || !portfolio || !subtype) return '';
        return `${strategy}-${portfolio.name}-${subtype.ad_class}-${subtype.subtype_code}`;
    }

    function refreshCampaignName() {
        const input = $('modalCampaignName');
        const autoName = buildCampaignName();
        if (!input.value || input.dataset.auto === '1') {
            input.value = autoName;
            input.dataset.auto = autoName ? '1' : '0';
        }
    }

    function onAdLevelChanged() {
        const level = $('modalAdLevel').value;
        ['portfolio', 'campaign', 'group'].forEach(item => {
            document.querySelectorAll(`.level-${item}`).forEach(el => {
                el.style.display = item === level ? '' : 'none';
            });
        });
        if (level === 'group') onGroupPortfolioChanged();
        syncSegmentButtons('modalAdLevel');
    }

    function resetCreateForm() {
        adEditId = null;
        $('ad-modal-title').innerText = '新增广告信息';
        $('modalAdLevelSegment').setAttribute('data-locked', '0');
        $('modalAdLevel').value = 'portfolio';
        $('modalSkuFamily').value = '';
        renderSkuFamilySelect('');
        $('modalPortfolioName').value = '';
        $('modalPortfolioName').dataset.auto = '1';
        $('modalSharedBudgetSwitch').checked = true;
        onSharedBudgetSwitchChange();
        $('modalStatusPortfolio').value = '启动';
        $('modalStatusCampaign').value = '启动';
        $('modalCampaignPortfolio').value = '';
        renderCampaignPortfolioSelect('');
        $('modalStrategy').value = 'BE';
        $('modalSubtype').value = '';
        $('modalCampaignName').value = '';
        $('modalCampaignName').dataset.auto = '1';
        $('modalBudget').value = '';
        $('modalGroupPortfolio').value = '';
        renderGroupPortfolioSelect('');
        $('modalGroupCampaign').value = '';
        renderGroupCampaignSelect('');
        $('modalGroupName').value = '';
        $('modalGroupName').dataset.auto = '1';
        $('modalStatusGroup').value = '启动';
        renderSubtypeSegment();
        syncSegmentButtons('modalStrategy');
        syncSegmentButtons('modalStatusPortfolio');
        syncSegmentButtons('modalStatusCampaign');
        syncSegmentButtons('modalStatusGroup');
        resetAdStatus();
        onAdLevelChanged();
    }

    function openCreateModal() {
        const run = () => {
            resetCreateForm();
            $(MODAL_ID).classList.add('active');
            if (global.initUniversalSingleSelects) global.initUniversalSingleSelects($(MODAL_ID));
            if (global.syncModalScrollLock) global.syncModalScrollLock();
        };
        return (readyPromise || Promise.resolve()).then(run);
    }

    function openEditModal(id) {
        const run = () => {
            const item = typeof hooks.getEditItem === 'function'
                ? hooks.getEditItem(id)
                : (adItemsCache || []).find(x => String(x.id) === String(id));
            if (!item) return;
            adEditId = item.id;
            $('ad-modal-title').innerText = '编辑广告信息';
            $('modalAdLevelSegment').setAttribute('data-locked', '1');
            $('modalAdLevel').value = item.ad_level;
            if (item.ad_level === 'portfolio') {
                $('modalSkuFamily').value = item.sku_family_id || '';
                renderSkuFamilySelect(item.sku_family_id || '');
                $('modalSharedBudget').value = item.is_shared_budget === 1 ? '是' : '否';
                $('modalSharedBudgetSwitch').checked = (item.is_shared_budget === 1);
                onSharedBudgetSwitchChange();
                $('modalStatusPortfolio').value = item.status || '启动';
                const nameInput = $('modalPortfolioName');
                const autoName = buildPortfolioNameBySkuId(item.sku_family_id || '');
                nameInput.value = item.name || '';
                nameInput.dataset.auto = (autoName && (item.name || '') === autoName) ? '1' : '0';
            } else if (item.ad_level === 'campaign') {
                $('modalCampaignPortfolio').value = item.portfolio_id || '';
                renderCampaignPortfolioSelect(item.portfolio_id || '');
                $('modalStrategy').value = item.strategy_code || 'BE';
                $('modalSubtype').value = item.subtype_id || '';
                $('modalStatusCampaign').value = item.status || '启动';
                $('modalCampaignName').value = item.name || '';
                $('modalCampaignName').dataset.auto = '0';
                $('modalBudget').value = item.budget === null || item.budget === undefined ? '' : item.budget;
            } else {
                $('modalGroupPortfolio').value = item.portfolio_id || '';
                renderGroupPortfolioSelect(item.portfolio_id || '');
                onGroupPortfolioChanged();
                $('modalGroupCampaign').value = item.campaign_id || '';
                renderGroupCampaignSelect(item.campaign_id || '');
                $('modalGroupName').value = item.name || '';
                const autoByCampaign = !!item.campaign_name && (item.name || '') === (item.campaign_name || '');
                $('modalGroupName').dataset.auto = autoByCampaign ? '1' : '0';
                $('modalStatusGroup').value = item.status || '启动';
            }
            renderSubtypeSegment();
            syncSegmentButtons('modalStrategy');
            syncSegmentButtons('modalStatusPortfolio');
            syncSegmentButtons('modalStatusCampaign');
            syncSegmentButtons('modalStatusGroup');
            resetAdStatus();
            onAdLevelChanged();
            $(MODAL_ID).classList.add('active');
            if (global.initUniversalSingleSelects) global.initUniversalSingleSelects($(MODAL_ID));
            if (global.syncModalScrollLock) global.syncModalScrollLock();
        };
        return (readyPromise || Promise.resolve()).then(run);
    }

    function closeAdModal() {
        $(MODAL_ID)?.classList.remove('active');
        adEditId = null;
        if (global.syncModalScrollLock) global.syncModalScrollLock();
    }

    function validateAdNameUnique(level, name, portfolioId, campaignId) {
        const nm = String(name || '').trim();
        if (!nm) return null;
        const excludeId = adEditId ? Number(adEditId) : null;
        const list = adItemsCache || [];
        const sameName = (item) => String(item.name || '').trim() === nm;
        const notSelf = (item) => !excludeId || Number(item.id) !== excludeId;
        if (level === 'portfolio') {
            const hit = list.find(item => item.ad_level === 'portfolio' && sameName(item) && notSelf(item));
            if (hit) return '广告组合名称已存在，请勿重复';
        } else if (level === 'campaign') {
            const pid = String(portfolioId || '');
            const hit = list.find(item =>
                item.ad_level === 'campaign'
                && String(item.portfolio_id || '') === pid
                && sameName(item)
                && notSelf(item)
            );
            if (hit) return '该广告组合下已存在同名广告活动';
        } else {
            const cid = String(campaignId || '');
            const hit = list.find(item =>
                item.ad_level === 'group'
                && String(item.campaign_id || '') === cid
                && sameName(item)
                && notSelf(item)
            );
            if (hit) return '该广告活动下已存在同名广告组';
        }
        return null;
    }

    function saveAdFromModal() {
        const level = $('modalAdLevel').value;
        const payload = { ad_level: level };

        if (level === 'portfolio') {
            payload.sku_family_id = $('modalSkuFamily').value;
            payload.is_shared_budget = $('modalSharedBudget').value;
            payload.status = $('modalStatusPortfolio').value;
            const portfolioName = ($('modalPortfolioName').value || '').trim();
            payload.name = portfolioName;
            if (!payload.is_shared_budget || !payload.status || !portfolioName) {
                showAdStatus('请完整填写广告组合信息', true);
                return;
            }
        } else if (level === 'campaign') {
            payload.portfolio_id = $('modalCampaignPortfolio').value;
            payload.strategy_code = $('modalStrategy').value;
            payload.subtype_id = $('modalSubtype').value;
            payload.status = $('modalStatusCampaign').value;
            payload.name = $('modalCampaignName').value.trim();
            payload.budget = $('modalBudget').value;
            if (!payload.name) {
                refreshCampaignName();
                payload.name = $('modalCampaignName').value.trim();
            }
            if (!payload.portfolio_id || !payload.strategy_code || !payload.subtype_id || !payload.status || !payload.name) {
                showAdStatus('请完整填写广告活动信息', true);
                return;
            }
        } else {
            payload.portfolio_id = $('modalGroupPortfolio').value;
            payload.campaign_id = $('modalGroupCampaign').value;
            payload.name = $('modalGroupName').value.trim();
            payload.status = $('modalStatusGroup').value;
            if (!payload.campaign_id || !payload.name || !payload.status) {
                showAdStatus('请完整填写广告组信息', true);
                return;
            }
            const selectedCampaign = (campaignOptions || []).find(x => String(x.id) === String(payload.campaign_id));
            if (!selectedCampaign) {
                showAdStatus('请选择有效的广告活动', true);
                return;
            }
            if (payload.portfolio_id && String(selectedCampaign.portfolio_id || '') !== String(payload.portfolio_id || '')) {
                showAdStatus('请选择该广告组合下的广告活动', true);
                return;
            }
            if (!payload.portfolio_id && selectedCampaign.portfolio_id) {
                payload.portfolio_id = String(selectedCampaign.portfolio_id);
            }
            if (selectedCampaign.strategy_code) payload.strategy_code = selectedCampaign.strategy_code;
            if (selectedCampaign.subtype_id) payload.subtype_id = selectedCampaign.subtype_id;
        }

        const dupMsg = validateAdNameUnique(level, payload.name, payload.portfolio_id, payload.campaign_id);
        if (dupMsg) {
            showAdStatus(dupMsg, true);
            return;
        }

        let method = 'POST';
        if (adEditId) {
            payload.id = adEditId;
            method = 'PUT';
        }

        fetch('/api/amazon-ad', {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        })
            .then(r => r.json())
            .then(data => {
                if (data.status === 'success') {
                    closeAdModal();
                    const afterSave = Promise.all([
                        loadAdItemsCache(),
                        loadPortfolioOptions(),
                        loadCampaignOptions(),
                    ]);
                    const hookResult = typeof hooks.onSaveSuccess === 'function'
                        ? hooks.onSaveSuccess(data)
                        : null;
                    const chained = hookResult && typeof hookResult.then === 'function'
                        ? Promise.all([afterSave, hookResult])
                        : afterSave;
                    chained.then(() => {
                        if (typeof hooks.showSuccessToast === 'function') {
                            hooks.showSuccessToast('保存成功');
                        }
                    });
                } else {
                    showAdStatus(data.message || '操作失败', true);
                }
            })
            .catch(err => showAdStatus('请求失败: ' + err, true));
    }

    function bindEvents() {
        if (eventsBound) return;
        eventsBound = true;
        const campaignNameInput = $('modalCampaignName');
        const groupNameInput = $('modalGroupName');
        const portfolioNameInput = $('modalPortfolioName');
        if (campaignNameInput) {
            campaignNameInput.addEventListener('input', function () {
                this.dataset.auto = this.value.trim() ? '0' : '1';
            });
        }
        if (groupNameInput) {
            groupNameInput.addEventListener('input', function () {
                const campaignId = $('modalGroupCampaign')?.value || '';
                const selectedCampaign = (campaignOptions || []).find(x => String(x.id) === String(campaignId));
                const campaignName = selectedCampaign?.name || '';
                this.dataset.auto = campaignName && this.value.trim() === campaignName ? '1' : (this.value.trim() ? '0' : '1');
            });
        }
        if (portfolioNameInput) {
            portfolioNameInput.addEventListener('input', function () {
                this.dataset.auto = this.value.trim() ? '0' : '1';
            });
        }
        global.setTimeout(() => {
            const el = $(MODAL_ID);
            if (el && typeof global.bindPmModalBackdropClose === 'function') {
                global.bindPmModalBackdropClose(el, closeAdModal);
            }
        }, 0);
    }

    function init(options) {
        hooks = options && typeof options === 'object' ? options : {};
        ensureModalDom();
        bindEvents();
        readyPromise = Promise.all([
            loadCategoryMap(),
            loadSkuOptions(),
            loadSubtypeOptions(),
            loadPortfolioOptions(),
            loadCampaignOptions(),
            loadAdItemsCache(),
        ]);
        return readyPromise;
    }

    function refreshReferenceOptions() {
        return Promise.all([loadPortfolioOptions(), loadCampaignOptions(), loadAdItemsCache()]);
    }

    global.setSegmentValue = setSegmentValue;
    global.onPortfolioSkuChanged = onPortfolioSkuChanged;
    global.onGroupPortfolioChanged = onGroupPortfolioChanged;
    global.onGroupCampaignChanged = onGroupCampaignChanged;
    global.onSharedBudgetSwitchChange = onSharedBudgetSwitchChange;
    global.refreshCampaignName = refreshCampaignName;
    global.closeAdModal = closeAdModal;
    global.saveAdFromModal = saveAdFromModal;
    global.openCreateModal = openCreateModal;
    global.openEditModal = openEditModal;

    global.AmazonAdFormModal = {
        init,
        openCreateModal,
        openEditModal,
        closeAdModal,
        refreshReferenceOptions,
    };
}(window));
