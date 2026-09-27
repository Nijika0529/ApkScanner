package io.apkscanner.poc.webobserverattacker;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

/** Ordinary-UID launcher used to distinguish app-origin Deep Links from adb_shell. */
public final class LaunchActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String uri = getIntent().getStringExtra("target_uri");
        String requestId = getIntent().getStringExtra("apkscanner_request_id");
        String encodedPayload = getIntent().getStringExtra("apkscanner_payload_base64");
        if (encodedPayload != null) {
            try {
                String json = new String(Base64.decode(encodedPayload, Base64.URL_SAFE),
                        StandardCharsets.UTF_8);
                JSONObject payload = new JSONObject(json);
                requestId = payload.optString("request_id", requestId);
                uri = payload.getJSONObject("extras").optString("target_uri", uri);
            } catch (IllegalArgumentException | JSONException error) {
                Log.e("APKSCANNER_POC", "request=" + requestId + " invalid payload", error);
            }
        }
        TextView status = new TextView(this);
        setContentView(status);
        if (uri == null || !uri.startsWith("adaptivecases://")) {
            status.setText("invalid target_uri");
            return;
        }
        try {
            Intent target = new Intent(Intent.ACTION_VIEW, Uri.parse(uri));
            target.addCategory(Intent.CATEGORY_BROWSABLE);
            startActivity(target);
            status.setText("deep link dispatched: " + requestId);
            Log.i("APKSCANNER_POC", "request=" + requestId + " dispatch=" + uri);
        } catch (ActivityNotFoundException error) {
            status.setText("target activity not found");
            Log.e("APKSCANNER_POC", "request=" + requestId + " failed", error);
        }
    }
}
