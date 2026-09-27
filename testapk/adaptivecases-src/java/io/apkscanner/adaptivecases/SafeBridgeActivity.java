package io.apkscanner.adaptivecases;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/** A page-loading control: external content is rendered without an account bridge. */
public final class SafeBridgeActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String pageUrl = getIntent().getData() == null
                ? null : getIntent().getData().getQueryParameter("url");
        WebView webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                Log.i("APKScannerSafeWebView", "onPageFinished " + url);
            }
        });
        setContentView(webView);
        if (pageUrl != null) {
            webView.loadUrl(pageUrl);
        }
    }
}
