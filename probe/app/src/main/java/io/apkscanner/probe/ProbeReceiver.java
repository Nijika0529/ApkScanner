package io.apkscanner.probe;

import android.content.BroadcastReceiver;
import android.content.ContentValues;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Process;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import org.json.JSONObject;
import org.json.JSONArray;

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
                    Intent target = newIntent(request);
                    target.setComponent(new ComponentName(packageName, component));
                    applyExtras(target, request.optJSONObject("extras"));
                    applyCategories(target, request.optJSONArray("categories"));
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
                    Intent target = newIntent(request);
                    target.setComponent(new ComponentName(packageName, component));
                    applyExtras(target, request.optJSONObject("extras"));
                    applyCategories(target, request.optJSONArray("categories"));
                    ComponentName started = context.startService(target);
                    result.put("delivered", started != null);
                    break;
                }
                case "receiver": {
                    Intent target = newIntent(request);
                    target.setComponent(new ComponentName(packageName, component));
                    applyExtras(target, request.optJSONObject("extras"));
                    applyCategories(target, request.optJSONArray("categories"));
                    context.sendBroadcast(target);
                    result.put("delivered", true);
                    break;
                }
                case "provider": {
                    Uri uri = Uri.parse(request.getString("uri"));
                    String operation = request.optString("operation", "query");
                    switch (operation) {
                        case "auto":
                        case "query":
                            try (Cursor cursor = context.getContentResolver().query(
                                uri, null, null, null, null
                            )) {
                                result.put("delivered", true);
                                result.put("rowCount", cursor == null ? -1 : cursor.getCount());
                                if (cursor != null) {
                                    result.put("columns", String.join(",", cursor.getColumnNames()));
                                }
                            }
                            break;
                        case "call": {
                            Bundle returned = context.getContentResolver().call(
                                uri,
                                request.getString("method"),
                                request.optString("argument", null),
                                toBundle(request.optJSONObject("extras"))
                            );
                            result.put("delivered", true);
                            result.put("bundleKeyCount", returned == null ? -1 : returned.keySet().size());
                            result.put(
                                "bundleKeys",
                                returned == null ? "" : String.join(",", returned.keySet())
                            );
                            break;
                        }
                        case "insert": {
                            Uri inserted = context.getContentResolver().insert(
                                uri, toContentValues(request.optJSONObject("extras"))
                            );
                            result.put("delivered", true);
                            result.put("returnedUri", inserted == null ? JSONObject.NULL : inserted.toString());
                            break;
                        }
                        case "update":
                            result.put(
                                "affectedRows",
                                context.getContentResolver().update(
                                    uri,
                                    toContentValues(request.optJSONObject("extras")),
                                    null,
                                    null
                                )
                            );
                            result.put("delivered", true);
                            break;
                        case "delete":
                            result.put(
                                "affectedRows",
                                context.getContentResolver().delete(uri, null, null)
                            );
                            result.put("delivered", true);
                            break;
                        default:
                            throw new IllegalArgumentException(
                                "unsupported provider operation: " + operation
                            );
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

    private static Intent newIntent(JSONObject request) {
        Intent intent = new Intent();
        String action = request.optString("intent_action", "");
        if (!action.isEmpty()) {
            intent.setAction(action);
        }
        return intent;
    }

    private static void applyCategories(Intent intent, JSONArray categories) throws Exception {
        if (categories == null) {
            return;
        }
        for (int index = 0; index < categories.length(); index++) {
            intent.addCategory(categories.getString(index));
        }
    }

    private static ContentValues toContentValues(JSONObject extras) throws Exception {
        ContentValues values = new ContentValues();
        if (extras == null) {
            return values;
        }
        Iterator<String> keys = extras.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            Object value = extras.get(key);
            if (value instanceof Boolean) {
                values.put(key, (Boolean) value);
            } else if (value instanceof Integer) {
                values.put(key, (Integer) value);
            } else if (value instanceof Long) {
                values.put(key, (Long) value);
            } else if (value instanceof String) {
                values.put(key, (String) value);
            } else {
                throw new IllegalArgumentException("unsupported provider value for " + key);
            }
        }
        return values;
    }

    private static Bundle toBundle(JSONObject extras) throws Exception {
        Bundle values = new Bundle();
        if (extras == null) {
            return values;
        }
        Iterator<String> keys = extras.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            Object value = extras.get(key);
            if (value instanceof Boolean) {
                values.putBoolean(key, (Boolean) value);
            } else if (value instanceof Integer) {
                values.putInt(key, (Integer) value);
            } else if (value instanceof Long) {
                values.putLong(key, (Long) value);
            } else if (value instanceof String) {
                values.putString(key, (String) value);
            } else {
                throw new IllegalArgumentException("unsupported bundle value for " + key);
            }
        }
        return values;
    }
}
