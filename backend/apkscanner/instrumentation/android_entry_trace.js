"use strict";

function emit(event, fields) {
  const payload = Object.assign({ marker: "APKSCANNER_TRACE", event: event }, fields || {});
  send(payload);
}

function safeUri(value) {
  if (value === null || value === undefined) return null;
  const text = String(value);
  const boundary = text.search(/[?#]/);
  return boundary >= 0 ? text.slice(0, boundary) + "?<redacted>" : text;
}

setImmediate(function () {
  Java.perform(function () {
    send({ marker: "APKSCANNER_READY", event: "script_loaded" });

    try {
      const Intent = Java.use("android.content.Intent");
      const getData = Intent.getData.overload();
      getData.implementation = function () {
        const result = getData.call(this);
        emit("intent.getData", { uri: safeUri(result) });
        return result;
      };

      const getStringExtra = Intent.getStringExtra.overload("java.lang.String");
      getStringExtra.implementation = function (name) {
        const result = getStringExtra.call(this, name);
        emit("intent.getStringExtra", {
          key: String(name),
          present: result !== null,
          value_length: result === null ? 0 : String(result).length,
        });
        return result;
      };
    } catch (error) {
      emit("hook_error", { hook: "Intent", error: String(error) });
    }

    try {
      const WebView = Java.use("android.webkit.WebView");
      const loadUrl = WebView.loadUrl.overload("java.lang.String");
      loadUrl.implementation = function (url) {
        emit("webview.loadUrl", { uri: safeUri(url) });
        return loadUrl.call(this, url);
      };

      const addJavascriptInterface = WebView.addJavascriptInterface.overload(
        "java.lang.Object",
        "java.lang.String"
      );
      addJavascriptInterface.implementation = function (object, name) {
        emit("webview.addJavascriptInterface", { name: String(name) });
        return addJavascriptInterface.call(this, object, name);
      };
    } catch (error) {
      emit("hook_error", { hook: "WebView", error: String(error) });
    }

    try {
      const ContextWrapper = Java.use("android.content.ContextWrapper");
      const startActivity = ContextWrapper.startActivity.overload("android.content.Intent");
      startActivity.implementation = function (intent) {
        emit("context.startActivity", { component: String(intent.getComponent()) });
        return startActivity.call(this, intent);
      };
    } catch (error) {
      emit("hook_error", { hook: "ContextWrapper", error: String(error) });
    }
  });
});
