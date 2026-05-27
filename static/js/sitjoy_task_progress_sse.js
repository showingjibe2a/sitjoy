/**
 * 任务进度 SSE（Server-Sent Events）客户端。
 * 服务端在进度变化时推送事件；不支持 EventSource 时回退到 mode=wait 长轮询。
 */
(function (global) {
    'use strict';

    function isTerminalDone(data) {
        const payload = data && typeof data === 'object' ? data : {};
        const state = String(payload.state || '').toLowerCase();
        const agg = String(payload.agg_refresh_status || '').toLowerCase();
        if (state === 'error') return true;
        if (state === 'success' && agg !== 'running') return true;
        return false;
    }

    function buildUrl(baseUrl, mode, taskId, sinceSeq) {
        const raw = String(baseUrl || '/');
        const u = raw.indexOf('http') === 0 ? new URL(raw) : new URL(raw, global.location.href);
        u.searchParams.set('mode', mode);
        u.searchParams.set('task_id', String(taskId || ''));
        u.searchParams.set('since_seq', String(Number(sinceSeq || 0)));
        return u.toString();
    }

    /**
     * @param {object} opts
     * @param {string} opts.url - 进度 API 基址（如 /api/sales-product-performance-import）
     * @param {string} opts.taskId
     * @param {number} [opts.sinceSeq]
     * @param {number} [opts.timeoutMs] - 总超时，默认 30 分钟
     * @param {function} [opts.onProgress] - (data) => void
     * @param {function} [opts.onDone] - (data) => void
     * @param {function} [opts.onError] - (err, data?) => void
     * @param {function} [opts.fetchJson] - 可选，回退长轮询用的 fetch 封装
     * @returns {{ cancel: function }}
     */
    function watch(opts) {
        const baseUrl = opts.url || '';
        const taskId = String(opts.taskId || '').trim();
        let sinceSeq = Number(opts.sinceSeq || 0);
        const onProgress = typeof opts.onProgress === 'function' ? opts.onProgress : function () {};
        const onDone = typeof opts.onDone === 'function' ? opts.onDone : function () {};
        const onError = typeof opts.onError === 'function' ? opts.onError : function () {};
        const deadline = Date.now() + (Number(opts.timeoutMs) || 30 * 60 * 1000);
        const waitTimeoutMs = Number(opts.waitTimeoutMs) || 28000;
        const fetchImpl = opts.fetchJson || defaultFetchJson;

        let closed = false;
        let es = null;
        let waitChain = false;

        function finish(err, data) {
            if (closed) return;
            closed = true;
            if (es) {
                try { es.close(); } catch (_) {}
                es = null;
            }
            if (err) onError(err, data);
            else onDone(data || {});
        }

        function timedOut() {
            return Date.now() > deadline;
        }

        function ingest(data, forceDone) {
            if (closed || timedOut()) return;
            const seq = Number((data && data.seq) || 0);
            if (seq > sinceSeq) sinceSeq = seq;
            onProgress(data || {});
            if (forceDone || isTerminalDone(data)) {
                finish(null, data);
            }
        }

        function waitPollLoop() {
            if (closed) return;
            if (timedOut()) {
                finish(new Error('任务超时，请稍后重试'));
                return;
            }
            waitChain = true;
            const waitUrl = buildUrl(baseUrl, 'wait', taskId, sinceSeq);
            fetchImpl(waitUrl, { method: 'GET', credentials: 'include', headers: { Accept: 'application/json' } }, waitTimeoutMs)
                .then((data) => {
                    waitChain = false;
                    if (closed) return;
                    ingest(data, isTerminalDone(data));
                    if (!closed) {
                        global.setTimeout(waitPollLoop, data && data.unchanged ? 80 : 0);
                    }
                })
                .catch(() => {
                    waitChain = false;
                    if (!closed) global.setTimeout(waitPollLoop, 1500);
                });
        }

        function connectSse() {
            if (closed) return;
            if (timedOut()) {
                finish(new Error('任务超时，请稍后重试'));
                return;
            }
            if (typeof EventSource === 'undefined') {
                waitPollLoop();
                return;
            }
            let url;
            try {
                url = buildUrl(baseUrl, 'stream', taskId, sinceSeq);
                es = new EventSource(url);
            } catch (_) {
                waitPollLoop();
                return;
            }
            es.addEventListener('progress', (ev) => {
                if (closed || !ev.data) return;
                try { ingest(JSON.parse(ev.data), false); } catch (_) {}
            });
            es.addEventListener('done', (ev) => {
                if (closed || !ev.data) return;
                try { ingest(JSON.parse(ev.data), true); } catch (_) {}
            });
            es.addEventListener('error', (ev) => {
                if (closed) return;
                if (ev && ev.data) {
                    try {
                        const data = JSON.parse(ev.data);
                        onProgress(data);
                        const err = new Error(data.message || '任务失败');
                        err.taskData = data;
                        finish(err, data);
                        return;
                    } catch (_) {}
                }
            });
            es.onerror = () => {
                if (closed) return;
                try { es.close(); } catch (_) {}
                es = null;
                global.setTimeout(() => {
                    if (!closed && !waitChain) connectSse();
                }, 600);
            };
        }

        connectSse();

        return {
            cancel() {
                closed = true;
                if (es) {
                    try { es.close(); } catch (_) {}
                    es = null;
                }
            },
        };
    }

    function defaultFetchJson(url, options, timeoutMs) {
        const controller = new AbortController();
        const ms = Math.max(500, Number(timeoutMs || 0) || 28000);
        const timer = global.setTimeout(() => controller.abort(), ms);
        return fetch(url, Object.assign({}, options || {}, { signal: controller.signal }))
            .then((r) => r.text().then((text) => {
                global.clearTimeout(timer);
                try {
                    return JSON.parse(text);
                } catch (e) {
                    throw new Error('接口未返回 JSON');
                }
            }))
            .catch((e) => {
                global.clearTimeout(timer);
                if (e && (e.name === 'AbortError' || String(e).includes('AbortError'))) {
                    throw new Error('请求超时（已中止）');
                }
                throw e;
            });
    }

    global.SitjoyTaskProgress = {
        watch,
        isTerminalDone,
    };
})(typeof window !== 'undefined' ? window : globalThis);
