/**
 * Amazon 广告信息新增/编辑弹窗（广告信息页、广告调整页共用）
 */
(function (global) {
    const MODAL_ID = 'ad-modal';
    const STYLE_ID = 'amazon-ad-form-modal-styles';

    let hooks = {};
    let readyPromise = null;
    let adEditId = null;
    let skuOptions = [];
    let categoryMap = new Map();
    let portfolioOptions = [];
    let campaignOptions = [];
    let subtypeOptions = [];
    let shopOptions = [];
    let operationTypeOptions = [];
    let eventsBound = false;
    let modalDefaultTargets = [];
    let defaultTargetsSourceKey = '';
    let operationTypeOptionsPromise = null;

    function escapeHtml(text) {
        return String(text ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

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
            '#adDefaultTargetsWrap .default-target-toolbar {',
            '  display: grid; grid-template-columns: 1fr 120px auto; gap: 0.5rem; align-items: center;',
            '}',
            '#adDefaultTargetsWrap .default-target-list { display: grid; gap: 0.5rem; }',
            '#adDefaultTargetsWrap .default-target-item {',
            '  display: grid; grid-template-columns: 1fr 100px 132px auto; gap: 0.55rem; align-items: center;',
            '  border: 2px solid var(--morandi-sand); border-radius: 8px; padding: 0.45rem 0.55rem; background: #fff;',
            '}',
            '#adDefaultTargetsWrap .default-target-item-name {',
            '  color: var(--morandi-ink); font-size: 0.92rem; word-break: break-word;',
            '}',
            '#adDefaultTargetsWrap .default-target-empty {',
            '  color: var(--morandi-slate); font-size: 0.9rem;',
            '}',
            '#adInitialProductSkusInput {',
            '  width: 100%; min-height: 5.5rem; resize: vertical;',
            '  border: 2px solid var(--morandi-sand); border-radius: 8px;',
            '  padding: 0.5rem 0.6rem; font-size: 0.92rem; line-height: 1.45;',
            '  font-family: inherit; box-sizing: border-box;',
            '}',
            '#adInitialProductSkusInput.is-invalid { border-color: #c45c5c; }',
            '#adInitialProductSkusValidation {',
            '  margin-top: 0.4rem; font-size: 0.86rem; line-height: 1.4;',
            '}',
            '#adInitialProductSkusValidation.is-error { color: #a33; }',
            '#adInitialProductSkusValidation.is-ok { color: #2f6f2f; }',
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
            '      <div class="form-group level-portfolio">',
            '        <label for="modalPortfolioShop">关联店铺<span class="required-asterisk">*</span></label>',
            '        <select id="modalPortfolioShop" data-search-placeholder="搜索店铺"></select>',
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
            '      <div class="form-group level-campaign">',
            '        <label>竞价策略</label>',
            '        <input type="hidden" id="modalBidStrategy" value="">',
            '        <div class="status-segment status-segment--inline">',
            '          <button type="button" class="status-pill" data-target="modalBidStrategy" data-value="" onclick="setSegmentValue(\'modalBidStrategy\',\'\')">无</button>',
            '          <button type="button" class="status-pill" data-target="modalBidStrategy" data-value="动态竞价-仅降低" onclick="setSegmentValue(\'modalBidStrategy\',\'动态竞价-仅降低\')">动态竞价-仅降低</button>',
            '          <button type="button" class="status-pill" data-target="modalBidStrategy" data-value="动态竞价-提高和降低" onclick="setSegmentValue(\'modalBidStrategy\',\'动态竞价-提高和降低\')">动态竞价-提高和降低</button>',
            '          <button type="button" class="status-pill" data-target="modalBidStrategy" data-value="固定竞价" onclick="setSegmentValue(\'modalBidStrategy\',\'固定竞价\')">固定竞价</button>',
            '        </div>',
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
            '      <div class="form-group pm-form-full level-campaign level-group" id="adDefaultTargetsWrap" style="display:none;">',
            '        <div class="pm-section">',
            '          <h4 style="margin-top:0;" class="label-help">默认投放<span class="help-dot" data-tip="细分类关联「修改投放」或「修改广告位」时显示。保存广告时将一并创建以下投放，可修改竞价、启动/暂停状态或增删。"></span></h4>',
            '          <div class="default-target-toolbar">',
            '            <input type="text" id="adDefaultTargetNameInput" placeholder="投放描述">',
            '            <input type="text" id="adDefaultTargetValueInput" placeholder="竞价">',
            '            <button type="button" class="btn-secondary" id="adDefaultTargetAddBtn">添加</button>',
            '          </div>',
            '          <div id="adDefaultTargetList" class="default-target-list"></div>',
            '          <div id="adDefaultTargetEmpty" class="default-target-empty" style="display:none;">暂无投放项，保存时不会自动创建投放</div>',
            '        </div>',
            '      </div>',
            '      <div class="form-group pm-form-full level-group" id="adInitialProductSkusWrap" style="display:none;">',
            '        <label for="adInitialProductSkusInput" class="label-help">销售平台SKU<span class="help-dot" data-tip="每行一个销售平台SKU，保存广告组时将一并创建商品（状态：启动）。失焦时校验是否为当前店铺的销售平台SKU。"></span></label>',
            '        <textarea id="adInitialProductSkusInput" placeholder="例如：&#10;ABC-123&#10;DEF-456"></textarea>',
            '        <div id="adInitialProductSkusValidation" style="display:none;"></div>',
            '      </div>',
            '      <div class="form-group pm-form-full">',
            '        <label for="modalAmazonId">亚马逊 ID（选填）</label>',
            '        <input type="text" id="modalAmazonId" placeholder="亚马逊后台对应层级的实体 ID">',
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
        const modalEl = wrap.firstElementChild;
        document.body.appendChild(modalEl);
        if (global.bindFloatingHelpDots) global.bindFloatingHelpDots(modalEl);
    }

    function showAdStatus(message, isError) {
        const text = String(message || '').trim();
        if (!text) return;
        resetAdStatus();
        if (global.showPageStatus) global.showPageStatus(text, !!isError);
        else if (global.showAppToast) global.showAppToast(text, !!isError);
    }

    function resetAdStatus() {
        const el = $('adModalStatus');
        if (!el) return;
        el.style.display = 'none';
        el.innerText = '';
    }

    function getReferenceItemsForDupCheck() {
        if (typeof hooks.getReferenceItems === 'function') {
            return hooks.getReferenceItems() || [];
        }
        return [];
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

    function loadOperationTypeOptions() {
        return fetch('/api/amazon-ad-operation-type')
            .then(r => r.json())
            .then(data => {
                operationTypeOptions = data.status === 'success' ? (data.items || []) : [];
            })
            .catch(() => { operationTypeOptions = []; });
    }

    function ensureOperationTypeOptions() {
        if (operationTypeOptions.length) return Promise.resolve();
        if (!operationTypeOptionsPromise) {
            operationTypeOptionsPromise = loadOperationTypeOptions();
        }
        return operationTypeOptionsPromise;
    }

    function normalizeOperationTypeName(name) {
        return String(name || '').replace(/[『』【】「」]/g, '').trim();
    }

    function isModifyProductOperationName(name) {
        const n = normalizeOperationTypeName(name);
        return n.includes('修改') && n.includes('商品');
    }

    function isModifyDeliveryTargetOperationName(name) {
        const n = normalizeOperationTypeName(name);
        return n.includes('修改') && n.includes('投放') && !n.includes('广告位');
    }

    function isModifyPlacementOperationName(name) {
        const n = normalizeOperationTypeName(name);
        return n.includes('修改') && n.includes('广告位');
    }

    function subtypeHasModifyTargetOp(subtype) {
        if (!subtype || !Array.isArray(subtype.operation_type_ids)) return false;
        const idSet = new Set(subtype.operation_type_ids.map(String));
        return (operationTypeOptions || []).some((op) => {
            if (!idSet.has(String(op.id))) return false;
            const opName = op.name || '';
            return isModifyDeliveryTargetOperationName(opName)
                || isModifyPlacementOperationName(opName);
        });
    }

    function normalizeDefaultTargetStatus(status) {
        const s = String(status || '').trim();
        return s === '暂停' ? '暂停' : '启动';
    }

    function shouldShowDefaultTargetsSection() {
        if (adEditId) return false;
        const level = $('modalAdLevel')?.value;
        if (level !== 'campaign' && level !== 'group') return false;
        if (level === 'group' && !($('modalGroupCampaign')?.value || '')) return false;
        if (level === 'campaign' && !($('modalSubtype')?.value || '')) return false;
        const subtype = getActiveSubtypeForDefaultTargets();
        return subtypeHasModifyTargetOp(subtype);
    }

    function subtypeHasModifyProductOp(subtype) {
        if (!subtype || !Array.isArray(subtype.operation_type_ids)) return false;
        const idSet = new Set(subtype.operation_type_ids.map(String));
        return (operationTypeOptions || []).some(
            op => idSet.has(String(op.id)) && isModifyProductOperationName(op.name),
        );
    }

    function shouldShowInitialProductSkusSection() {
        if (adEditId) return false;
        if (($('modalAdLevel')?.value || '') !== 'group') return false;
        if (!($('modalGroupCampaign')?.value || '')) return false;
        const subtype = getActiveSubtypeForDefaultTargets();
        return subtypeHasModifyProductOp(subtype);
    }

    function parseInitialProductSkusFromTextarea() {
        const raw = $('adInitialProductSkusInput')?.value || '';
        const seen = new Set();
        const lines = [];
        raw.split(/\r?\n/).forEach((line) => {
            const text = String(line || '').trim();
            if (!text) return;
            const key = text.toLowerCase();
            if (seen.has(key)) return;
            seen.add(key);
            lines.push(text);
        });
        return lines;
    }

    function renderInitialProductSkusValidation(message, mode) {
        const el = $('adInitialProductSkusValidation');
        const input = $('adInitialProductSkusInput');
        if (!el) return;
        if (!message) {
            el.style.display = 'none';
            el.className = '';
            el.innerText = '';
            input?.classList.remove('is-invalid');
            return;
        }
        el.style.display = '';
        el.className = mode === 'ok' ? 'is-ok' : 'is-error';
        el.innerText = message;
        input?.classList.toggle('is-invalid', mode !== 'ok');
    }

    function validateInitialProductSkus(showEmptyAsValid) {
        const skus = parseInitialProductSkusFromTextarea();
        if (!skus.length) {
            renderInitialProductSkusValidation('', null);
            return Promise.resolve(true);
        }
        const campaignId = $('modalGroupCampaign')?.value || '';
        if (!campaignId) {
            renderInitialProductSkusValidation('请先选择广告活动', 'error');
            return Promise.resolve(false);
        }
        const qs = skus.map(sku => `sku=${encodeURIComponent(sku)}`).join('&');
        return fetch(
            `/api/amazon-ad?action=validate-platform-skus&campaign_id=${encodeURIComponent(campaignId)}&${qs}`,
        )
            .then(r => r.json())
            .then((data) => {
                if (data.status !== 'success') {
                    renderInitialProductSkusValidation(data.message || 'SKU 校验失败', 'error');
                    return false;
                }
                const invalid = Array.isArray(data.invalid_skus) ? data.invalid_skus : [];
                if (invalid.length) {
                    renderInitialProductSkusValidation(
                        `以下SKU不是当前广告归属店铺的销售平台SKU：${invalid.join('、')}`,
                        'error',
                    );
                    return false;
                }
                if (!showEmptyAsValid) {
                    renderInitialProductSkusValidation(`已校验 ${skus.length} 个销售平台SKU`, 'ok');
                } else {
                    renderInitialProductSkusValidation('', null);
                }
                return true;
            })
            .catch(() => {
                renderInitialProductSkusValidation('SKU 校验请求失败', 'error');
                return false;
            });
    }

    function refreshInitialProductSkusSection() {
        const wrap = $('adInitialProductSkusWrap');
        if (!wrap) return;
        ensureOperationTypeOptions().then(() => {
            if (!shouldShowInitialProductSkusSection()) {
                wrap.style.display = 'none';
                renderInitialProductSkusValidation('', null);
                return;
            }
            wrap.style.display = '';
            const skus = parseInitialProductSkusFromTextarea();
            if (skus.length) {
                validateInitialProductSkus(true);
            } else {
                renderInitialProductSkusValidation('', null);
            }
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
        if (targetId === 'modalSubtype') refreshDefaultTargetsSection();
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
            refreshDefaultTargetsSection();
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
        refreshDefaultTargetsSection();
    }

    function loadShopOptions() {
        return fetch('/api/shop')
            .then(r => r.json())
            .then(data => {
                shopOptions = data.status === 'success' ? (data.items || []) : [];
                renderPortfolioShopSelect();
            })
            .catch(() => { shopOptions = []; });
    }

    function renderPortfolioShopSelect(selectedValue) {
        const select = $('modalPortfolioShop');
        const current = String(
            selectedValue !== undefined ? selectedValue : (select?.value || '1')
        );
        if (!select) return;
        select.innerHTML = '<option value="">请选择店铺</option>';
        let hasCurrent = false;
        (shopOptions || []).forEach(item => {
            const option = document.createElement('option');
            option.value = item.id;
            option.textContent = item.shop_name || '';
            if (current && String(item.id) === current) {
                option.selected = true;
                hasCurrent = true;
            }
            select.appendChild(option);
        });
        if (current && !hasCurrent) {
            select.value = shopOptions.length ? String(shopOptions[0].id) : '1';
        } else if (!current) {
            select.value = '1';
        }
        if (global.refreshUniversalSingleSelect) global.refreshUniversalSingleSelect(select);
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
        refreshDefaultTargetsSection();
        refreshInitialProductSkusSection();
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
        refreshDefaultTargetsSection();
        refreshInitialProductSkusSection();
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
        refreshDefaultTargetsSection();
        refreshInitialProductSkusSection();
    }

    function normalizeDefaultTargetItems(items) {
        const seen = new Set();
        return (Array.isArray(items) ? items : [])
            .map(item => ({
                name: item && item.name ? String(item.name).trim() : '',
                value: item && item.value ? String(item.value).trim() : '',
                status: normalizeDefaultTargetStatus(item && item.status),
            }))
            .filter(item => item.name && item.value)
            .filter(item => {
                const key = item.name.toLowerCase();
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
            });
    }

    function getActiveSubtypeForDefaultTargets() {
        const level = $('modalAdLevel')?.value;
        if (level === 'campaign') {
            const subtypeId = $('modalSubtype')?.value;
            return (subtypeOptions || []).find(x => String(x.id) === String(subtypeId)) || null;
        }
        if (level === 'group') {
            const campaignId = $('modalGroupCampaign')?.value;
            const campaign = (campaignOptions || []).find(x => String(x.id) === String(campaignId));
            if (!campaign?.subtype_id) return null;
            return (subtypeOptions || []).find(x => String(x.id) === String(campaign.subtype_id)) || null;
        }
        return null;
    }

    function defaultTargetsSourceKeyForState() {
        const level = $('modalAdLevel')?.value;
        if (level === 'campaign') return `campaign:${$('modalSubtype')?.value || ''}`;
        if (level === 'group') return `group:${$('modalGroupCampaign')?.value || ''}`;
        return '';
    }

    function getSubtypeDefaultTargetsForLevel() {
        const level = $('modalAdLevel')?.value;
        const subtype = getActiveSubtypeForDefaultTargets();
        if (!subtype) return [];
        if (level === 'campaign') {
            return normalizeDefaultTargetItems(subtype.campaign_default_targets || []);
        }
        if (level === 'group') {
            return normalizeDefaultTargetItems(subtype.group_default_targets || []);
        }
        return [];
    }

    function setDefaultTargetRowStatus(idx, status) {
        if (!modalDefaultTargets[idx]) return;
        modalDefaultTargets[idx].status = normalizeDefaultTargetStatus(status);
        renderAdDefaultTargetList();
    }

    function renderAdDefaultTargetList() {
        const list = $('adDefaultTargetList');
        const empty = $('adDefaultTargetEmpty');
        if (!list || !empty) return;
        list.innerHTML = '';
        modalDefaultTargets.forEach((item, idx) => {
            const rowStatus = normalizeDefaultTargetStatus(item.status);
            const row = document.createElement('div');
            row.className = 'default-target-item';
            row.innerHTML = `
                <span class="default-target-item-name">${escapeHtml(item.name)}</span>
                <input type="text" class="inline-input default-target-value-input" value="${escapeHtml(item.value)}" aria-label="竞价">
                <div class="default-target-status-segment status-segment status-segment--inline">
                    <button type="button" class="status-pill status-pill--enabled ${rowStatus === '启动' ? 'is-active' : ''}" data-status="启动">启动</button>
                    <button type="button" class="status-pill status-pill--paused ${rowStatus === '暂停' ? 'is-active' : ''}" data-status="暂停">暂停</button>
                </div>
                <button type="button" class="btn-danger btn-small">删除</button>
            `;
            const valueInput = row.querySelector('.default-target-value-input');
            valueInput.addEventListener('input', () => {
                modalDefaultTargets[idx].value = valueInput.value;
            });
            row.querySelectorAll('.default-target-status-segment [data-status]').forEach((btn) => {
                btn.addEventListener('click', () => {
                    setDefaultTargetRowStatus(idx, btn.getAttribute('data-status'));
                });
            });
            row.querySelector('button.btn-danger').addEventListener('click', () => {
                modalDefaultTargets.splice(idx, 1);
                renderAdDefaultTargetList();
            });
            list.appendChild(row);
        });
        empty.style.display = modalDefaultTargets.length ? 'none' : '';
    }

    function refreshDefaultTargetsSection() {
        const wrap = $('adDefaultTargetsWrap');
        if (!wrap) return;
        ensureOperationTypeOptions().then(() => {
            if (!shouldShowDefaultTargetsSection()) {
                wrap.style.display = 'none';
                return;
            }
            wrap.style.display = '';
            const key = defaultTargetsSourceKeyForState();
            if (key !== defaultTargetsSourceKey) {
                defaultTargetsSourceKey = key;
                modalDefaultTargets = getSubtypeDefaultTargetsForLevel().map((item) => ({
                    name: item.name,
                    value: item.value,
                    status: normalizeDefaultTargetStatus(item.status),
                }));
            }
            renderAdDefaultTargetList();
        });
    }

    function addAdDefaultTargetFromInput() {
        const nameInput = $('adDefaultTargetNameInput');
        const valueInput = $('adDefaultTargetValueInput');
        const name = (nameInput?.value || '').trim();
        const value = (valueInput?.value || '').trim();
        if (!name || !value) {
            if (!name) nameInput?.focus();
            else valueInput?.focus();
            return;
        }
        const exists = modalDefaultTargets.some(
            item => String(item.name).toLowerCase() === name.toLowerCase(),
        );
        if (exists) {
            nameInput.value = '';
            valueInput.value = '';
            valueInput.focus();
            return;
        }
        modalDefaultTargets.push({ name, value, status: '启动' });
        nameInput.value = '';
        valueInput.value = '';
        renderAdDefaultTargetList();
    }

    function collectDefaultTargetsPayload() {
        if (adEditId) return undefined;
        const wrap = $('adDefaultTargetsWrap');
        if (!wrap || wrap.style.display === 'none') return undefined;
        return normalizeDefaultTargetItems(
            modalDefaultTargets.map(item => ({
                name: item.name,
                value: String(item.value || '').trim(),
                status: normalizeDefaultTargetStatus(item.status),
            })).filter(item => item.name && item.value),
        );
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
        renderPortfolioShopSelect('1');
        $('modalStatusPortfolio').value = '启动';
        $('modalStatusCampaign').value = '启动';
        $('modalCampaignPortfolio').value = '';
        renderCampaignPortfolioSelect('');
        $('modalStrategy').value = 'BE';
        $('modalSubtype').value = '';
        $('modalCampaignName').value = '';
        $('modalCampaignName').dataset.auto = '1';
        $('modalBudget').value = '';
        $('modalBidStrategy').value = '';
        $('modalGroupPortfolio').value = '';
        renderGroupPortfolioSelect('');
        $('modalGroupCampaign').value = '';
        renderGroupCampaignSelect('');
        $('modalGroupName').value = '';
        $('modalGroupName').dataset.auto = '1';
        $('modalStatusGroup').value = '启动';
        $('modalAmazonId').value = '';
        modalDefaultTargets = [];
        defaultTargetsSourceKey = '';
        const skuInput = $('adInitialProductSkusInput');
        if (skuInput) skuInput.value = '';
        renderInitialProductSkusValidation('', null);
        renderSubtypeSegment();
        syncSegmentButtons('modalStrategy');
        syncSegmentButtons('modalBidStrategy');
        syncSegmentButtons('modalStatusPortfolio');
        syncSegmentButtons('modalStatusCampaign');
        syncSegmentButtons('modalStatusGroup');
        resetAdStatus();
        onAdLevelChanged();
        refreshDefaultTargetsSection();
        refreshInitialProductSkusSection();
    }

    function openCreateModal() {
        const run = () => {
            resetCreateForm();
            $(MODAL_ID).classList.add('active');
            if (global.initUniversalSingleSelects) global.initUniversalSingleSelects($(MODAL_ID));
            if (global.syncModalScrollLock) global.syncModalScrollLock();
        };
        return ensureModalDataLoaded().then(run);
    }

    function openEditModal(id) {
        const run = () => {
            const item = typeof hooks.getEditItem === 'function'
                ? hooks.getEditItem(id)
                : getReferenceItemsForDupCheck().find(x => String(x.id) === String(id));
            if (!item) return;
            adEditId = item.id;
            $('ad-modal-title').innerText = '编辑广告信息';
            $('modalAmazonId').value = item.amazon_id || '';
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
                renderPortfolioShopSelect(item.shop_id || '1');
            } else if (item.ad_level === 'campaign') {
                $('modalCampaignPortfolio').value = item.portfolio_id || '';
                renderCampaignPortfolioSelect(item.portfolio_id || '');
                $('modalStrategy').value = item.strategy_code || 'BE';
                $('modalSubtype').value = item.subtype_id || '';
                $('modalStatusCampaign').value = item.status || '启动';
                $('modalCampaignName').value = item.name || '';
                $('modalCampaignName').dataset.auto = '0';
                $('modalBudget').value = item.budget === null || item.budget === undefined ? '' : item.budget;
                $('modalBidStrategy').value = item.bid_strategy || '';
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
            syncSegmentButtons('modalBidStrategy');
            syncSegmentButtons('modalStatusPortfolio');
            syncSegmentButtons('modalStatusCampaign');
            syncSegmentButtons('modalStatusGroup');
            resetAdStatus();
            onAdLevelChanged();
            $('adDefaultTargetsWrap').style.display = 'none';
            $('adInitialProductSkusWrap').style.display = 'none';
            renderInitialProductSkusValidation('', null);
            $(MODAL_ID).classList.add('active');
            if (global.initUniversalSingleSelects) global.initUniversalSingleSelects($(MODAL_ID));
            if (global.syncModalScrollLock) global.syncModalScrollLock();
        };
        return ensureModalDataLoaded().then(run);
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
        const list = getReferenceItemsForDupCheck();
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
            payload.shop_id = $('modalPortfolioShop').value;
            if (!payload.is_shared_budget || !payload.status || !portfolioName || !payload.shop_id) {
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
            payload.bid_strategy = ($('modalBidStrategy').value || '').trim() || null;
            if (!payload.name) {
                refreshCampaignName();
                payload.name = $('modalCampaignName').value.trim();
            }
            if (!payload.portfolio_id || !payload.strategy_code || !payload.subtype_id
                || !payload.status || !payload.name) {
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

        const amazonId = ($('modalAmazonId')?.value || '').trim();
        payload.amazon_id = amazonId || null;

        if (!adEditId && (level === 'campaign' || level === 'group')) {
            const defaultTargets = collectDefaultTargetsPayload();
            if (defaultTargets !== undefined) {
                payload.default_targets = defaultTargets;
            }
        }

        let method = 'POST';
        if (adEditId) {
            payload.id = adEditId;
            method = 'PUT';
        }

        const submitPayload = () => {
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
        };

        if (!adEditId && level === 'group' && shouldShowInitialProductSkusSection()) {
            const skus = parseInitialProductSkusFromTextarea();
            if (skus.length) {
                validateInitialProductSkus(false).then((ok) => {
                    if (!ok) {
                        showAdStatus('请修正不合法的销售平台SKU', true);
                        return;
                    }
                    payload.initial_product_skus = skus;
                    submitPayload();
                });
                return;
            }
        }

        submitPayload();
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
        $('adDefaultTargetAddBtn')?.addEventListener('click', addAdDefaultTargetFromInput);
        $('adInitialProductSkusInput')?.addEventListener('blur', () => {
            if (shouldShowInitialProductSkusSection()) {
                validateInitialProductSkus(false);
            }
        });
        ['adDefaultTargetNameInput', 'adDefaultTargetValueInput'].forEach((id) => {
            const el = $(id);
            if (!el) return;
            el.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    addAdDefaultTargetFromInput();
                }
            });
        });
        global.setTimeout(() => {
            const el = $(MODAL_ID);
            if (el && typeof global.bindPmModalBackdropClose === 'function') {
                global.bindPmModalBackdropClose(el, closeAdModal);
            }
        }, 0);
    }

    function buildModalDataPromise() {
        return Promise.all([
            loadCategoryMap(),
            loadSkuOptions(),
            loadSubtypeOptions(),
            loadShopOptions(),
            loadPortfolioOptions(),
            loadCampaignOptions(),
        ]);
    }

    function ensureModalDataLoaded() {
        if (!readyPromise) {
            readyPromise = buildModalDataPromise();
        }
        return readyPromise;
    }

    function init(options) {
        hooks = options && typeof options === 'object' ? options : {};
        ensureModalDom();
        bindEvents();
        return Promise.resolve();
    }

    function refreshReferenceOptions() {
        readyPromise = buildModalDataPromise();
        return readyPromise;
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
