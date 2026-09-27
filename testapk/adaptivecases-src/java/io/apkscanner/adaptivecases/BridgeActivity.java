package io.apkscanner.adaptivecases;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class BridgeActivity extends Activity {
    private TextView transferStatus;
    private volatile String loadedUrl;

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
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                Log.i("APKScannerWebView", "onPageFinished " + url);
            }
        });
        webView.addJavascriptInterface(new AccountBridge(), "AccountBridge");
        transferStatus = new TextView(this);
        transferStatus.setText("transfer:" +
                (getPreferences(MODE_PRIVATE).getBoolean("transfer_enabled", false) ? "on" : "off"));
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.addView(transferStatus);
        layout.addView(webView, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(layout);
        loadedUrl = attackerUrl;
        webView.loadUrl(attackerUrl);
    }

    public final class AccountBridge {
        @JavascriptInterface
        public String getAccountId() {
            return Secrets.ACCOUNT_ID;
        }

        @JavascriptInterface
        public String getSessionToken() {
            WebCanaryState.noteBridgeCall(BridgeActivity.this, loadedUrl);
            return WebCanaryState.token(BridgeActivity.this);
        }

        @JavascriptInterface
        public long getTokenExpiry() {
            return Secrets.TOKEN_EXPIRY;
        }

        @JavascriptInterface
        public void setTransferEnabled(boolean enabled) {
            getPreferences(MODE_PRIVATE).edit().putBoolean("transfer_enabled", enabled).apply();
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    transferStatus.setText("transfer:" + (enabled ? "on" : "off"));
                }
            });
        }
    }
}
