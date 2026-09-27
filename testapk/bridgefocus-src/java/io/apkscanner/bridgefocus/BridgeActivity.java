package io.apkscanner.bridgefocus;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.TextView;

/** One-route fixture: an external page may change target-owned state via JSBridge. */
public final class BridgeActivity extends Activity {
    private static final String DEFAULT_PAGE = "data:text/html,<h1>Bridge focus ready</h1>";

    private TextView stateView;
    private volatile boolean enabled;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        enabled = getPreferences(MODE_PRIVATE).getBoolean("enabled", false);

        stateView = new TextView(this);
        stateView.setId(android.R.id.text1);
        stateView.setText("state:" + (enabled ? "on" : "off"));

        WebView webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        webView.setWebViewClient(new WebViewClient());
        webView.addJavascriptInterface(new StateBridge(), "StateBridge");

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.addView(stateView);
        layout.addView(webView, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(layout);

        String pageUrl = getIntent().getData() == null
                ? null : getIntent().getData().getQueryParameter("url");
        webView.loadUrl(pageUrl == null || pageUrl.isEmpty() ? DEFAULT_PAGE : pageUrl);
    }

    public final class StateBridge {
        @JavascriptInterface
        public void setEnabled(boolean value) {
            enabled = value;
            getPreferences(MODE_PRIVATE).edit().putBoolean("enabled", value).apply();
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    stateView.setText("state:" + (enabled ? "on" : "off"));
                }
            });
        }
    }
}
