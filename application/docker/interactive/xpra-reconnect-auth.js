/* Keep Xpra's per-session secret only in client memory for authenticated reconnects. */
(() => {
  'use strict';
  let reconnectURL = '';
  try {
    const candidate = new URL(sessionStorage.getItem('odysafe-reconnect-url') || '');
    if (['http:', 'https:'].includes(candidate.protocol) && ['localhost', '127.0.0.1'].includes(candidate.hostname) &&
        /^\/sessions\/[0-9a-f-]{36}\/connect$/.test(candidate.pathname) && !candidate.username && !candidate.password) {
      reconnectURL = candidate.href;
    }
  } catch (_) { /* No session to resume. */ }
  let deadline = 0;
  try { deadline = Number(sessionStorage.getItem('odysafe-session-deadline')); } catch (_) {}
  if (reconnectURL && Number.isFinite(deadline) && deadline > 0) {
    const finish = () => {
      try { Utilities.clearSessionStorage(); sessionStorage.removeItem('odysafe-session-deadline'); } catch (_) {}
      window.location.replace(new URL('/sessions', reconnectURL).href);
    };
    if (deadline <= Date.now()) { finish(); return; }
    window.setTimeout(finish, deadline - Date.now());
  }
  if (reconnectURL && performance.getEntriesByType('navigation')[0]?.type === 'reload') {
    window.location.replace(reconnectURL);
    return;
  }
  // Lossless local sessions do not need periodic quality-refresh frames.
  const originalCapabilities = XpraClient.prototype._update_capabilities;
  if (typeof originalCapabilities === 'function') {
    XpraClient.prototype._update_capabilities = function (capabilities) {
      if (Object.prototype.hasOwnProperty.call(capabilities, 'auto_refresh_delay')) {
        capabilities.auto_refresh_delay = 0;
      }
      return originalCapabilities.call(this, capabilities);
    };
  }
  const originalChallenge = XpraClient.prototype._process_challenge;
  XpraClient.prototype._process_challenge = function (packet) {
    if (this.passwords.length > 0) {
      this._odysafeReconnectPassword = this.passwords[0];
      try { Utilities.clearSessionStorage(); if (reconnectURL) sessionStorage.setItem('odysafe-reconnect-url', reconnectURL); if (deadline > 0) sessionStorage.setItem('odysafe-session-deadline', String(deadline)); } catch (_) { /* unavailable storage */ }
    } else if (this._odysafeReconnectPassword) {
      this.passwords = [this._odysafeReconnectPassword];
    } else if (reconnectURL) {
      window.location.replace(reconnectURL);
      return;
    }
    return originalChallenge.call(this, packet);
  };

})();
