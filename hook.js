(() => {
  function sendToBurp(payload) {
    const json = JSON.stringify(payload);
    const blob = new Blob([json], { type: 'application/json' });

    if (navigator.sendBeacon && navigator.sendBeacon('/__capture__', blob)) return;

    try {
      fetch('/__capture__', {
        method: 'POST',
        mode: 'no-cors',
        headers: { 'Content-Type': 'application/json' },
        body: json
      }).catch(() => {});
      return;
    } catch (_) {}

    try {
      const img = new Image();
      img.src = '/__capture__?d=' + encodeURIComponent(btoa(unescape(encodeURIComponent(json))));
    } catch (_) {}
  }

  function hookComponent(comp) {
    if (!comp || typeof comp.AesRsaEncrypt !== 'function' || comp.__aesHooked__) return false;
    comp.__aesHooked__ = true;

    const _orig = comp.AesRsaEncrypt;
    comp.AesRsaEncrypt = function(outObj, plainText, aesKeyB64, ivB64, wrapKey) {
      const t0 = (self.performance && performance.now()) || Date.now();
      const ret = _orig.apply(this, arguments);

      const report = {
        ts: new Date().toISOString(),
        url: location.href,
        wrapKey: !!wrapKey,
        ivB64,
        aesKeyB64,
        plaintextLen: (typeof plainText === 'string' ? plainText.length : 0),
        out: {
          contentLen: (outObj && outObj.content && outObj.content.length) || 0,
          contentPreview: outObj && outObj.content ? outObj.content.slice(0, 64) : null,
          keyB64: outObj && outObj.key || null,
          ivB64: outObj && outObj.iv || ivB64
        },
        stack: (new Error()).stack,
        dt_ms: (((self.performance && performance.now()) || Date.now()) - t0)
      };

      try { sendToBurp(report); } catch (_) {}
      return ret;
    };

    console.log('[hook] AesRsaEncrypt hooked on', comp);
    return true;
  }

  function scanAndHook() {
    // Vue 2 scan
    for (const el of document.querySelectorAll('*')) {
      const vm = el.__vue__;
      if (vm && typeof vm.AesRsaEncrypt === 'function') {
        if (hookComponent(vm)) return true;
      }
    }
    // Vue 3 scan
    for (const el of document.querySelectorAll('*')) {
      const inst = el.__vueParentComponent;
      const ctx = inst && inst.ctx;
      if (ctx && typeof ctx.AesRsaEncrypt === 'function') {
        if (hookComponent(ctx)) return true;
      }
    }
    return false;
  }

  // try now, then poll until mounted
  if (!scanAndHook()) {
    const timer = setInterval(() => {
      if (scanAndHook()) clearInterval(timer);
    }, 500);
  }
})();
