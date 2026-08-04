package io.apkscanner.adaptivecases;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Bundle;
import android.widget.TextView;

public final class SafeCapabilityActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Intent explicitIntent = new Intent(this, SafeCapabilityActivity.class);
        PendingIntent safePendingIntent = PendingIntent.getActivity(
                this, 99, explicitIntent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_ONE_SHOT);
        TextView status = new TextView(this);
        status.setText(safePendingIntent != null
                ? "Signature-only immutable capability"
                : "Unavailable");
        setContentView(status);
    }
}
