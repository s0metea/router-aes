class HookPayload {
    static final String HOOK_JS =
            "(() => {\n" +
                    "    const root = document.getElementById('app')?.__vue__?.$root;\n" +
                    "    if (!root) return console.warn('No Vue root found');\n" +
                    "\n" +
                    "    const store  = root.$store;\n" +
                    "    const router = root.$router;\n" +
                    "    const VueProto = root.__proto__.constructor.prototype;\n" +
                    "    const originalReq = VueProto.httpReqSendAndRecv;\n" +
                    "\n" +
                    "    // Kill validators\n" +
                    "    for (const k of Object.keys(window))\n" +
                    "        if (/valid|check|verify/i.test(k) && typeof window[k] === 'function')\n" +
                    "            window[k] = () => true;\n" +
                    "    document.addEventListener('submit', e => e.stopImmediatePropagation(), true);\n" +
                    "\n" +
                    "    // Force all visible\n" +
                    "    const forceAllVisible = g => {\n" +
                    "        for (const k in g) {\n" +
                    "            if (typeof g[k] === 'boolean') g[k] = true;\n" +
                    "            if (typeof g[k] === 'number' && /VisibilityLevel/i.test(k)) g[k] = 3;\n" +
                    "            if (typeof g[k] === 'string' && g[k] === '') g[k] = '*';\n" +
                    "        }\n" +
                    "    };\n" +
                    "\n" +
                    "    // Spoof responses for privilege endpoints\n" +
                    "    const spoof = {\n" +
                    "        \"/cgi-bin/loginAccountLevel\": [{ level: \"high\" }],\n" +
                    "        \"/cgi-bin/MULTI_USER_LIST_Get\": {\n" +
                    "            Object: [{\n" +
                    "                TTNETMultiUser: 0,\n" +
                    "                curloginLevel: 3,\n" +
                    "                MGMTVisibilityLevel: 3,\n" +
                    "                BackupVisibilityLevel: 3,\n" +
                    "                TimeVisibilityLevel: 3,\n" +
                    "                BackupLock: 0,\n" +
                    "                BackupLimitation: 0,\n" +
                    "                enblMGMTcancelsubmit: true,\n" +
                    "                enblBackup: true,\n" +
                    "                enblBackupfilename: true,\n" +
                    "                enblBackupupload: true,\n" +
                    "                enblresetbtn: true,\n" +
                    "                enblLanid: true,\n" +
                    "                enblwlanid: true,\n" +
                    "                enblwanid: true,\n" +
                    "                enblport: true,\n" +
                    "                enbllocallan: true,\n" +
                    "                enbltelnetLanid: true,\n" +
                    "                enbltelnetwlanid: true,\n" +
                    "                enbltelnetwanid: true,\n" +
                    "                enbltelnetport: true\n" +
                    "            }]\n" +
                    "        },\n" +
                    "        \"/cgi-bin/CheckFsecureLicense\": {\n" +
                    "            status: true,\n" +
                    "            licenseStatus: \"active\",\n" +
                    "            daysLeft: 9999,\n" +
                    "            Cyber_Security_FSC: true,\n" +
                    "            FSC_License_Apply: true\n" +
                    "        }\n" +
                    "    };\n" +
                    "\n" +
                    "    function enableDebug() {\n" +
                    "        forceAllVisible(store.state.guiFlag);\n" +
                    "        store.state.loginLevel = \"high\";\n" +
                    "        if (Array.isArray(store.state.menu)) {\n" +
                    "            store.state.menu.forEach(m => {\n" +
                    "                m.hidden = false;\n" +
                    "                if (Array.isArray(m.submenu)) {\n" +
                    "                    m.submenu.forEach(s => s.hidden = false);\n" +
                    "                }\n" +
                    "            });\n" +
                    "        }\n" +
                    "        VueProto.httpReqSendAndRecv = function (opts = {}) {\n" +
                    "            if (opts.url && spoof[opts.url]) {\n" +
                    "                const hit = spoof[opts.url];\n" +
                    "                if (typeof opts.fnSuccess === 'function') setTimeout(() => opts.fnSuccess(hit), 0);\n" +
                    "                if (typeof opts.fnComplete === 'function') setTimeout(() => opts.fnComplete(hit), 0);\n" +
                    "                return Promise.resolve(hit);\n" +
                    "            }\n" +
                    "            return originalReq.call(this, opts);\n" +
                    "        };\n" +
                    "        root.$forceUpdate();\n" +
                    "    }\n" +
                    "\n" +
                    "    function disableDebug() {\n" +
                    "        VueProto.httpReqSendAndRecv = originalReq;\n" +
                    "        root.$forceUpdate();\n" +
                    "    }\n" +
                    "\n" +
                    "    // Nuking guards\n" +
                    "    router.beforeHooks.length = 0;\n" +
                    "    //router.resolveHooks.length = 0;\n" +
                    "    router.afterHooks.length = 0;\n" +
                    "\n" +
                    "    window.hack = { router, store, enableDebug, disableDebug, spoof, forceAllVisible };\n" +
                    "    console.log('hack ready — full unlock applied', { router, store });\n" +
                    "    console.log(\"Store and router are available by window.hack.store and window.hack.router\"); \n" +
                    "    console.log(\"Use window.hack.router.push({ path: '/GPON', query: { debug: 1 } }) to change path. Guards are disabled.\");\n" +
                    "})();\n" +
                    "hack.enableDebug();\n";
}