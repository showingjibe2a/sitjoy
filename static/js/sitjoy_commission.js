/**
 * 销售佣金：平台 × 货号 commission_group → 计算规则（与后端 CommissionCalcMixin 一致）。
 * 未配置规则时返回 commission_status=unavailable。
 */
(function (global) {
    'use strict';

    const UNAVAILABLE_LABEL = '无法计算';
    let cache = { ready: false, rules: {}, commission_groups: [] };
    let loadPromise = null;

    // -------------------------------------------------------------------------
    // 规则缓存加载
    // -------------------------------------------------------------------------

    function parseIntId(v) {
        const n = Number(v);
        return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
    }

    function buildCacheFromApi(payload) {
        const rules = {};
        const commissionGroups = [];
        if (!payload || payload.ready !== true) {
            return { ready: false, rules, commission_groups: commissionGroups };
        }
        (payload.commission_groups || []).forEach((grp) => {
            const g = String(grp || '').trim();
            if (g && !commissionGroups.includes(g)) commissionGroups.push(g);
        });
        (payload.rules || []).forEach((row) => {
            const pt = parseIntId(row.platform_type_id);
            const grp = String(row.commission_group || '').trim();
            if (!pt || !grp) return;
            if (!commissionGroups.includes(grp)) commissionGroups.push(grp);
            rules[`${pt}:${grp}`] = {
                calc_method: String(row.calc_method || '').trim().toLowerCase(),
                params_json: row.params_json && typeof row.params_json === 'object' ? row.params_json : {},
                commission_group: grp,
            };
        });
        commissionGroups.sort((a, b) => a.localeCompare(b, 'zh-CN'));
        return { ready: true, rules, commission_groups: commissionGroups };
    }

    function loadCommissionRules(force) {
        if (!force && cache.ready) return Promise.resolve(cache);
        if (!force && loadPromise) return loadPromise;
        loadPromise = fetch('/api/commission-rules')
            .then((r) => r.json())
            .then((data) => {
                cache = buildCacheFromApi(data);
                return cache;
            })
            .catch(() => {
                cache = { ready: false, rules: {}, commission_groups: [] };
                return cache;
            })
            .finally(() => {
                loadPromise = null;
            });
        return loadPromise;
    }

    // -------------------------------------------------------------------------
    // 分段 / 固定费率计算
    // -------------------------------------------------------------------------

    function parseTiers(params) {
        const tiers = [];
        ((params && params.tiers) || []).forEach((item) => {
            if (!item || typeof item !== 'object') return;
            const rate = Number(item.rate);
            if (!Number.isFinite(rate)) return;
            const upTo = item.up_to;
            if (upTo == null || String(upTo).trim() === '') {
                tiers.push({ up_to: null, rate });
            } else {
                const cap = Number(upTo);
                if (Number.isFinite(cap)) tiers.push({ up_to: cap, rate });
            }
        });
        return tiers;
    }

    function applyTiered(amount, params) {
        const tiers = parseTiers(params);
        if (!tiers.length) return null;
        const s = Math.max(0, Number(amount) || 0);
        if (s <= 1e-12) return 0;
        let total = 0;
        let prevCap = 0;
        for (let i = 0; i < tiers.length; i += 1) {
            const tier = tiers[i];
            const rate = Number(tier.rate) || 0;
            const cap = tier.up_to;
            let seg;
            if (cap == null) {
                seg = Math.max(0, s - prevCap);
            } else {
                const capF = Number(cap);
                seg = Math.max(0, Math.min(s, capF) - prevCap);
                prevCap = capF;
            }
            total += seg * rate;
            if (cap == null) break;
            if (s <= Number(cap)) break;
        }
        return Math.round(total * 100) / 100;
    }

    function applyFlat(amount, params) {
        const rate = Number((params || {}).rate);
        if (!Number.isFinite(rate)) return null;
        const s = Math.max(0, Number(amount) || 0);
        if (s <= 1e-12) return 0;
        return Math.round(s * rate * 100) / 100;
    }

    function applyRuleAmount(amount, rule) {
        if (!rule) return null;
        const method = String(rule.calc_method || '').trim().toLowerCase();
        const params = rule.params_json || {};
        if (method === 'flat') return applyFlat(amount, params);
        if (method === 'tiered') return applyTiered(amount, params);
        return null;
    }

    // -------------------------------------------------------------------------
    // 对外 API
    // -------------------------------------------------------------------------

    function computeForContext(platformTypeId, commissionGroup, amount, mode) {
        const grp = String(commissionGroup || '').trim();
        if (!grp) {
            return {
                commission_status: 'unavailable',
                commission_message: '缺少货号佣金大类',
                commission_group: null,
                est_referral_commission_usd: null,
                commission_rate: null,
            };
        }
        const pt = parseIntId(platformTypeId);
        if (!pt) {
            return {
                commission_status: 'unavailable',
                commission_message: '缺少平台类型',
                commission_group: grp,
                est_referral_commission_usd: null,
                commission_rate: null,
            };
        }
        if (!cache.ready) {
            return {
                commission_status: 'unavailable',
                commission_message: '佣金规则表未就绪',
                commission_group: grp,
                est_referral_commission_usd: null,
                commission_rate: null,
            };
        }
        const rule = cache.rules[`${pt}:${grp}`];
        if (!rule) {
            return {
                commission_status: 'unavailable',
                commission_message: `未维护佣金规则（${grp}）`,
                commission_group: grp,
                est_referral_commission_usd: null,
                commission_rate: null,
            };
        }
        const comm = applyRuleAmount(amount, rule);
        if (comm == null) {
            return {
                commission_status: 'unavailable',
                commission_message: UNAVAILABLE_LABEL,
                commission_group: grp,
                est_referral_commission_usd: null,
                commission_rate: null,
            };
        }
        const net = Math.max(0, Number(amount) || 0);
        const rate = net > 1e-12 ? Math.round((comm / net) * 1e6) / 1e6 : 0;
        return {
            commission_status: 'ok',
            commission_message: null,
            commission_group: grp,
            est_referral_commission_usd: comm,
            commission_rate: rate,
        };
    }

    function isCommissionOk(result) {
        return !!(result && result.commission_status === 'ok');
    }

    global.SitjoyCommission = {
        UNAVAILABLE_LABEL,
        loadCommissionRules,
        getCache: () => cache,
        getCommissionGroups: () => (cache.commission_groups || []).slice(),
        computeForContext,
        isCommissionOk,
    };
})(typeof window !== 'undefined' ? window : globalThis);
