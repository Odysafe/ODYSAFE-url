(() => {
  "use strict";
  const send = (type, details) => {
    try {
      Promise.resolve(globalThis.__odysafeRecordEvent({
        type, details, timestamp: new Date().toISOString(), url: location.href
      })).catch(() => {});
    } catch (_) {}
  };
  const preview = value => typeof value === "string" ? value.slice(0, 256) : null;
  const length = value => typeof value === "string" ? value.length : null;
  const installed = [];
  const failed = hook => send("__odysafe.hook_error", {hook});

  try {
    const originalEval = globalThis.eval;
    globalThis.eval = function (...args) {
      if (typeof args[0] === "string" &&
          args[0].includes("__playwright__binding__controller__"))
        return Reflect.apply(originalEval, this, args);
      send("eval", {argument_is_string: typeof args[0] === "string",
        argument_length: length(args[0]), argument_preview: preview(args[0])});
      return Reflect.apply(originalEval, this, args);
    };
    installed.push("eval");
  } catch (_) { failed("eval"); }

  for (const method of ["write", "writeln"]) {
    try {
      const original = Document.prototype[method];
      Document.prototype[method] = function (...args) {
        const strings = args.filter(value => typeof value === "string");
        send(`document.${method}`, {argument_count: args.length,
          content_length: strings.reduce((total, value) => total + value.length, 0),
          content_preview: strings.join("").slice(0, 256)});
        return Reflect.apply(original, this, args);
      };
      installed.push(`document.${method}`);
    } catch (_) { failed(`document.${method}`); }
  }

  try {
    const object = globalThis.Storage && Storage.prototype;
    if (!object) throw new Error("Storage unavailable");
    for (const method of ["setItem", "removeItem", "clear"]) {
      const original = object[method];
      object[method] = function (...args) {
        let name = "storage";
        try { name = this === globalThis.localStorage ? "localStorage" :
          (this === globalThis.sessionStorage ? "sessionStorage" : "storage"); } catch (_) {}
        send(`${name}.${method}`, {operation: method,
          key: preview(args[0]), value_length: length(args[1])});
        return Reflect.apply(original, this, args);
      };
    }
    for (const name of ["localStorage", "sessionStorage"])
      for (const method of ["setItem", "removeItem", "clear"])
        installed.push(`${name}.${method}`);
  } catch (_) {
    for (const name of ["localStorage", "sessionStorage"])
      for (const method of ["setItem", "removeItem", "clear"])
        failed(`${name}.${method}`);
  }

  try {
    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function")
      throw new Error("Clipboard unavailable");
    const original = navigator.clipboard.writeText;
    navigator.clipboard.writeText = function (...args) {
        const details = {text_length: length(args[0]), text_preview: preview(args[0]),
          sensitive_content: true, outcome: "attempted"};
        send("clipboard.writeText", details);
        let result;
        try { result = Reflect.apply(original, this, args); }
        catch (error) { send("clipboard.writeText", {...details, outcome: "failed"}); throw error; }
        Promise.resolve(result).then(
          () => send("clipboard.writeText", {...details, outcome: "succeeded"}),
          () => send("clipboard.writeText", {...details, outcome: "failed"})
        );
        return result;
      };
    installed.push("clipboard.writeText");
  } catch (_) { failed("clipboard.writeText"); }

  send("__odysafe.ready", {hooks: installed});
})();
