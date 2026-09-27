package io.apkscanner.poc.webobserverattacker;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/** Ordinary-UID negative control for the platform-only canary oracle. */
public final class FixturePermissionProbeActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String result;
        try (Cursor cursor = getContentResolver().query(
                Uri.parse("content://io.apkscanner.adaptivecases.fixture/web-canary"),
                null, null, null, null)) {
            result = cursor == null ? "oracle_unavailable" : "oracle_accessible";
        } catch (SecurityException expected) {
            result = "oracle_permission_denied";
        }
        TextView status = new TextView(this);
        status.setText(result);
        setContentView(status);
        Log.i("APKSCANNER_POC", "fixture_permission_probe=" + result);
    }
}
