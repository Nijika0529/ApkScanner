package io.apkscanner.adaptivecases;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ClipData;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

public final class PendingIntentBrokerActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Uri vaultUri = Uri.parse("content://io.apkscanner.adaptivecases.vault/session");
        Intent delegatedIntent = new Intent(
                "io.apkscanner.adaptivecases.PRIVILEGED_VAULT_READ");
        delegatedIntent.setDataAndType(vaultUri, "text/plain");
        delegatedIntent.setClipData(ClipData.newRawUri("account-vault", vaultUri));
        delegatedIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT
                | PendingIntent.FLAG_MUTABLE
                | PendingIntent.FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT;
        PendingIntent pendingIntent = PendingIntent.getBroadcast(
                this, 41, delegatedIntent, flags);
        Intent result = new Intent();
        result.putExtra("delegated_capability", pendingIntent);
        setResult(RESULT_OK, result);
        finish();
    }
}
