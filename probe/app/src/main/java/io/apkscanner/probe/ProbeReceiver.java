package io.apkscanner.probe;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Process;
import android.util.Base64;
import android.util.Log;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Iterator;

/** Executes one bounded cross-application call from an ordinary application UID. */
public final class ProbeReceiver extends BroadcastReceiver {
    private static final String TAG = "APKSCANNER_PROBE";

    @Override
    public void onReceive(Context context, Intent outerIntent) {
        JSONObject result = new JSONObject();
        try {
            int senderUid = getSentFromUid();
            if (senderUid != Process.SHELL_UID && senderUid != Process.ROOT_UID) {
                throw new SecurityException("only adb shell/root may dispatch probe requests");
            }
            String encoded = outerIntent.getStringExtra("request_base64");
            if (encoded == null || encoded.length() > 64 * 1024) {
                throw new IllegalArgumentException("missing or oversized request_base64");
            }
            byte[] decoded = Base64.decode(encoded, Base64.URL_SAFE | Base64.NO_WRAP);
            JSONObject request = new JSONObject(new String(decoded, StandardCharsets.UTF_8));
            String kind = request.getString("kind");
            String packageName = request.getString("package");
            String component = request.optString("component", "");
            String requestId = request.optString("request_id", "missing");
            result.put("requestId", requestId);
            result.put("kind", kind);
            result.put("targetPackage", packageName);

            switch (kind) {
                case "activity":
                case "activity_alias": {
                    Intent target = new Intent();
                    target.setComponent(new ComponentName(packageName, component));
                    applyExtras(target, request.optJSONObject("extras"));
                    target.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    context.startActivity(target);
                    result.put("delivered", true);
                    break;
                }
                case "deep_link": {
                    Uri uri = Uri.parse(request.getString("uri"));
                    Intent implicit = new Intent(Intent.ACTION_VIEW, uri);
                    ComponentName resolved = implicit.resolveActivity(context.getPackageManager());
                    result.put(
                        "implicitResolvedComponent",
                        resolved == null ? JSONObject.NULL : resolved.flattenToShortString()
                    );
                    Intent target = new Intent(Intent.ACTION_VIEW, uri);
                    target.setPackage(packageName);
                    ComponentName packageResolved =
                        target.resolveActivity(context.getPackageManager());
                    result.put(
                        "packageResolvedComponent",
                        packageResolved == null
                            ? JSONObject.NULL
                            : packageResolved.flattenToShortString()
                    );
                    if (!component.isEmpty()) {
                        String expectedClass = component.startsWith(".")
                            ? packageName + component
                            : component;
                        ComponentName expected = new ComponentName(packageName, expectedClass);
                        result.put("expectedComponent", expected.flattenToShortString());
                        boolean targetMatched = expected.equals(packageResolved);
                        result.put("targetMatched", targetMatched);
                        if (!targetMatched) {
                            throw new SecurityException(
                                "deep link did not resolve to the expected component"
                            );
                        }
                    }
                    applyExtras(target, request.optJSONObject("extras"));
                    target.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    context.startActivity(target);
                    result.put("delivered", true);
                    break;
                }
                case "service": {
                    Intent target = new Intent();
                    target.setComponent(new ComponentName(packageName, component));
                    applyExtras(target, request.optJSONObject("extras"));
                    ComponentName started = context.startService(target);
                    result.put("delivered", started != null);
                    break;
                }
                case "receiver": {
                    Intent target = new Intent();
                    target.setComponent(new ComponentName(packageName, component));
                    applyExtras(target, request.optJSONObject("extras"));
                    context.sendBroadcast(target);
                    result.put("delivered", true);
                    break;
                }
                case "provider": {
                    Uri uri = Uri.parse(request.getString("uri"));
                    try (Cursor cursor = context.getContentResolver().query(uri, null, null, null, null)) {
                        result.put("delivered", true);
                        result.put("rowCount", cursor == null ? -1 : cursor.getCount());
                        if (cursor != null) {
                            result.put("columns", String.join(",", cursor.getColumnNames()));
                        }
                    }
                    break;
                }
                default:
                    throw new IllegalArgumentException("unsupported probe kind: " + kind);
            }
            result.put("success", true);
        } catch (Throwable error) {
            try {
                result.put("success", false);
                result.put("errorType", error.getClass().getName());
                result.put("error", String.valueOf(error.getMessage()));
            } catch (Exception ignored) {
                // JSONObject writes above use primitive strings only.
            }
        }
        String payload = result.toString();
        Log.i(TAG, payload);
        setResultData(payload);
    }

    private static void applyExtras(Intent intent, JSONObject extras) throws Exception {
        if (extras == null) {
            return;
        }
        Iterator<String> keys = extras.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            Object value = extras.get(key);
            if (value instanceof Boolean) {
                intent.putExtra(key, (Boolean) value);
            } else if (value instanceof Integer) {
                intent.putExtra(key, (Integer) value);
            } else if (value instanceof Long) {
                intent.putExtra(key, (Long) value);
            } else if (value instanceof String) {
                intent.putExtra(key, (String) value);
            } else {
                throw new IllegalArgumentException("unsupported extra value for " + key);
            }
        }
    }
}
