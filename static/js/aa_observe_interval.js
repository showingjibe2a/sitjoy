(function (global) {
    const LS_KEY = 'sj.amazonAdAdjustment.observeInterval.v1';

    // -------------------------------------------------------------------------
    // 观察间隔 localStorage 与日期推算
    // -------------------------------------------------------------------------
    const DEFAULTS = {
        product: { days: 14, hours: 0, minutes: 0 },
        delivery: { days: 1, hours: 0, minutes: 0 },
    };

    function normalizePart(value) {
        const n = parseInt(String(value ?? '').trim(), 10);
        if (!Number.isFinite(n) || n < 0) return 0;
        return n;
    }

    function normalizeInterval(raw) {
        const src = raw && typeof raw === 'object' ? raw : {};
        return {
            days: normalizePart(src.days),
            hours: normalizePart(src.hours),
            minutes: normalizePart(src.minutes),
        };
    }

    function readObserveIntervalSettings() {
        try {
            const parsed = JSON.parse(global.localStorage.getItem(LS_KEY) || '{}');
            return {
                product: normalizeInterval(parsed.product || DEFAULTS.product),
                delivery: normalizeInterval(parsed.delivery || DEFAULTS.delivery),
            };
        } catch (_e) {
            return {
                product: { ...DEFAULTS.product },
                delivery: { ...DEFAULTS.delivery },
            };
        }
    }

    function writeObserveIntervalSettings(next) {
        const settings = {
            product: normalizeInterval(next && next.product),
            delivery: normalizeInterval(next && next.delivery),
        };
        try {
            global.localStorage.setItem(LS_KEY, JSON.stringify(settings));
        } catch (_e) { }
        return settings;
    }

    function intervalToMinutes(interval) {
        const iv = normalizeInterval(interval);
        return iv.days * 24 * 60 + iv.hours * 60 + iv.minutes;
    }

    function addIntervalToDate(baseDate, interval) {
        const d = baseDate instanceof Date ? new Date(baseDate.getTime()) : new Date(baseDate);
        if (Number.isNaN(d.getTime())) return null;
        const iv = normalizeInterval(interval);
        d.setDate(d.getDate() + iv.days);
        d.setHours(d.getHours() + iv.hours);
        d.setMinutes(d.getMinutes() + iv.minutes);
        return d;
    }

    // -------------------------------------------------------------------------
    // 操作类型 → 商品/投放观察周期
    // -------------------------------------------------------------------------
    /** @returns {'product'|'delivery'} */
    function observeKindFromOperationName(name) {
        const n = String(name || '').replace(/[『』【】「」]/g, '').trim();
        if (n.includes('修改') && n.includes('商品')) return 'product';
        return 'delivery';
    }

    function getObserveIntervalForKind(kind) {
        const settings = readObserveIntervalSettings();
        return kind === 'product' ? settings.product : settings.delivery;
    }

    function getObserveIntervalForOperationName(opName) {
        return getObserveIntervalForKind(observeKindFromOperationName(opName));
    }

    function computeNextObserveFromBase(baseDate, opNameOrKind) {
        const kind = opNameOrKind === 'product' || opNameOrKind === 'delivery'
            ? opNameOrKind
            : observeKindFromOperationName(opNameOrKind);
        const interval = getObserveIntervalForKind(kind);
        return addIntervalToDate(baseDate, interval);
    }

    global.AaObserveInterval = {
        LS_KEY,
        DEFAULTS,
        readObserveIntervalSettings,
        writeObserveIntervalSettings,
        intervalToMinutes,
        addIntervalToDate,
        observeKindFromOperationName,
        getObserveIntervalForKind,
        getObserveIntervalForOperationName,
        computeNextObserveFromBase,
    };
}(typeof window !== 'undefined' ? window : globalThis));
