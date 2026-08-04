package io.apkscanner.adaptivecases;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public final class BridgeActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String attackerUrl = null;
        if (getIntent().getData() != null) {
            attackerUrl = getIntent().getData().getQueryParameter("url");
        }
        if (attackerUrl == null) {
            attackerUrl = "data:text/html,<h1>Adaptive bridge ready</h1>";
        }
        WebView webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowFileAccessFromFileURLs(true);
        settings.setAllowUniversalAccessFromFileURLs(true);
        webView.setWebViewClient(new WebViewClient());
        webView.addJavascriptInterface(new AccountBridge(), "AccountBridge");
        webView.loadUrl(attackerUrl);
        setContentView(webView);
    }

    public static final class AccountBridge {
        @JavascriptInterface
        public String getAccountId() {
            return Secrets.ACCOUNT_ID;
        }

        @JavascriptInterface
        public String getSessionToken() {
            return Secrets.SESSION_TOKEN;
        }

        @JavascriptInterface
        public long getTokenExpiry() {
            return Secrets.TOKEN_EXPIRY;
        }
    }
}
