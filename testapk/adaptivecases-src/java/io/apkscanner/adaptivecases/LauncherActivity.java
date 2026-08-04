package io.apkscanner.adaptivecases;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Bundle;
import android.widget.TextView;

public final class LauncherActivity extends Activity {
    public static final String DYNAMIC_ACTION =
            "io.apkscanner.adaptivecases.DYNAMIC_ACCOUNT_REQUEST";

    private TextView status;
    private final BroadcastReceiver accountReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent request) {
            PendingIntent reply = null;
            if (Build.VERSION.SDK_INT >= 33) {
                reply = request.getParcelableExtra("reply", PendingIntent.class);
            } else {
                reply = request.getParcelableExtra("reply");
            }
            if (reply == null) {
                status.setText("Dynamic request had no callback");
                return;
            }
            Intent result = new Intent();
            result.putExtra("account_id", Secrets.ACCOUNT_ID);
            result.putExtra("session_token", Secrets.SESSION_TOKEN);
            try {
                reply.send(context, 0, result);
                status.setText("Dynamic callback delivered");
            } catch (PendingIntent.CanceledException exception) {
                status.setText("Dynamic callback was canceled");
            }
        }
    };

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        status = new TextView(this);
        status.setText("Adaptive fixture ready");
        status.setTextSize(20.0f);
        setContentView(status);
        getSharedPreferences("session", MODE_PRIVATE)
                .edit()
                .putString("account_id", Secrets.ACCOUNT_ID)
                .putString("session_token", Secrets.SESSION_TOKEN)
                .apply();
        startService(new Intent(this, LocalTokenService.class));
        IntentFilter filter = new IntentFilter(DYNAMIC_ACTION);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(accountReceiver, filter, Context.RECEIVER_EXPORTED);
        } else {
            registerReceiver(accountReceiver, filter);
        }
    }

    @Override
    protected void onDestroy() {
        try {
            unregisterReceiver(accountReceiver);
        } catch (IllegalArgumentException ignored) {
            // Test fixture cleanup only.
        }
        super.onDestroy();
    }
}
