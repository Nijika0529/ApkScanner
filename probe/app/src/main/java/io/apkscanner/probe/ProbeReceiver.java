package io.apkscanner.probe;

import android.content.BroadcastReceiver;
import android.content.ContentValues;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.database.Cursor;
import android.net.Uri;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import org.json.JSONObject;
import org.json.JSONArray;

import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;

/** Executes one bounded cross-application call from an ordinary application UID. */
public final class ProbeReceiver extends BroadcastReceiver {
    private static final String TAG = "APKSCANNER_PROBE";

    @Override
    public void onReceive(Context context, Intent outerIntent) {
        JSONObject result = new JSONObject();
        try {
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
                    if ("binder_transact".equals(request.optString("operation", "auto"))) {
                        PendingResult pending = goAsync();
                        startBinderTransaction(context, target, request, result, pending);
                        return;
                    }
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

    private static void startBinderTransaction(
        Context context,
        Intent target,
        JSONObject request,
        JSONObject result,
        PendingResult pending
    ) {
        // BroadcastReceiver receives a ReceiverRestrictedContext which rejects
        // bindService even after goAsync(); the process application context is
        // still the same ordinary app UID and supports the bounded async bind.
        Context applicationContext = context.getApplicationContext();
        BinderProbeConnection connection = new BinderProbeConnection(
            applicationContext,
            request,
            result,
            pending
        );
        try {
            boolean bound = applicationContext.bindService(
                target,
                connection,
                Context.BIND_AUTO_CREATE
            );
            result.put("bound", bound);
            if (!bound) {
                connection.fail(new SecurityException("bindService returned false"));
                return;
            }
            connection.markBoundAndArmTimeout();
        } catch (Throwable error) {
            connection.fail(error);
        }
    }

    private static final class BinderProbeConnection implements ServiceConnection {
        private static final long TIMEOUT_MILLIS = 8_000L;

        private final Context context;
        private final JSONObject request;
        private final JSONObject result;
        private final PendingResult pending;
        private final Handler handler = new Handler(Looper.getMainLooper());
        private final AtomicBoolean finished = new AtomicBoolean(false);
        private final Runnable timeout = new Runnable() {
            @Override
            public void run() {
                fail(new IllegalStateException("Binder probe timed out"));
            }
        };
        private volatile boolean bound;

        BinderProbeConnection(
            Context context,
            JSONObject request,
            JSONObject result,
            PendingResult pending
        ) {
            this.context = context;
            this.request = request;
            this.result = result;
            this.pending = pending;
        }

        void markBoundAndArmTimeout() {
            bound = true;
            handler.postDelayed(timeout, TIMEOUT_MILLIS);
        }

        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                result.put("boundComponent", name.flattenToShortString());
                String descriptor = request.optString("binder_interface_descriptor", "");
                if (!descriptor.isEmpty()) {
                    data.writeInterfaceToken(descriptor);
                    result.put("binderInterfaceDescriptor", descriptor);
                }
                int transactionCode = request.getInt("binder_transaction_code");
                String replyType = request.getString("binder_reply_type");
                boolean returned = service.transact(transactionCode, data, reply, 0);
                result.put("binderTransactionCode", transactionCode);
                result.put("binderTransactReturned", returned);
                result.put("binderReplyType", replyType);
                if (!returned) {
                    throw new IllegalStateException("Binder transact returned false");
                }
                reply.setDataPosition(0);
                if (request.optBoolean("binder_read_exception", true)) {
                    reply.readException();
                }
                switch (replyType) {
                    case "string":
                        result.put("binderReply", reply.readString());
                        break;
                    case "integer":
                        result.put("binderReply", reply.readInt());
                        break;
                    case "long":
                        result.put("binderReply", reply.readLong());
                        break;
                    case "boolean":
                        result.put("binderReply", reply.readInt() != 0);
                        break;
                    default:
                        throw new IllegalArgumentException(
                            "unsupported binder_reply_type: " + replyType
                        );
                }
                result.put("delivered", true);
                result.put("success", true);
                finish();
            } catch (Throwable error) {
                fail(error);
            } finally {
                reply.recycle();
                data.recycle();
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            // A disconnect after a completed transaction is expected and is not a new result.
        }

        @Override
        public void onBindingDied(ComponentName name) {
            fail(new IllegalStateException("Service binding died: " + name));
        }

        @Override
        public void onNullBinding(ComponentName name) {
            fail(new IllegalStateException("Service returned a null binding: " + name));
        }

        void fail(Throwable error) {
            try {
                result.put("success", false);
                result.put("errorType", error.getClass().getName());
                result.put("error", String.valueOf(error.getMessage()));
            } catch (Exception ignored) {
                // JSONObject writes above use primitive strings only.
            }
            finish();
        }

        private void finish() {
            if (!finished.compareAndSet(false, true)) {
                return;
            }
            handler.removeCallbacks(timeout);
            if (bound) {
                try {
                    context.unbindService(this);
                } catch (Throwable ignored) {
                    // The structured result is more important than an unbind race.
                }
            }
            String payload = result.toString();
            Log.i(TAG, payload);
            pending.setResultData(payload);
            pending.finish();
        }
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
