package io.apkscanner.adaptivecases;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

final class WebCanaryState {
    private static final String NAME = "web_canary_fixture";
    private static final String TOKEN = "token";
    private static final String EXPERIMENT_ID = "experiment_id";
    private static final String BRIDGE_CALLS = "bridge_calls";
    private static final String BRIDGE_URL_SHA256 = "bridge_url_sha256";

    private WebCanaryState() {}

    static String token(Context context) {
        String value = preferences(context).getString(TOKEN, null);
        return value == null ? Secrets.SESSION_TOKEN : value;
    }

    static String seededToken(Context context) {
        return preferences(context).getString(TOKEN, null);
    }

    static String tokenSha256(Context context) {
        String token = seededToken(context);
        return token == null ? null : sha256(token);
    }

    static int bridgeCalls(Context context) {
        return preferences(context).getInt(BRIDGE_CALLS, 0);
    }

    static String bridgeUrlSha256(Context context) {
        return preferences(context).getString(BRIDGE_URL_SHA256, null);
    }

    static String experimentId(Context context) {
        return preferences(context).getString(EXPERIMENT_ID, null);
    }

    static boolean seed(Context context, String experimentId) {
        if (seededToken(context) != null) {
            return false;
        }
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        String token = Base64.encodeToString(random,
                Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        return preferences(context).edit()
                .putString(EXPERIMENT_ID, experimentId)
                .putString(TOKEN, token)
                .putInt(BRIDGE_CALLS, 0)
                .remove(BRIDGE_URL_SHA256)
                .commit();
    }

    static void noteBridgeCall(Context context, String loadedUrl) {
        String experimentId = experimentId(context);
        if (seededToken(context) == null || experimentId == null
                || loadedUrl == null || !loadedUrl.contains(experimentId)) {
            return;
        }
        SharedPreferences state = preferences(context);
        state.edit()
                .putInt(BRIDGE_CALLS, state.getInt(BRIDGE_CALLS, 0) + 1)
                .putString(BRIDGE_URL_SHA256, sha256(loadedUrl))
                .commit();
    }

    static boolean clear(Context context, String experimentId) {
        if (!experimentId.equals(experimentId(context))) {
            return false;
        }
        return preferences(context).edit().clear().commit();
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(NAME, Context.MODE_PRIVATE);
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(
                    value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte part : digest) {
                hex.append(Character.forDigit((part >> 4) & 0xf, 16));
                hex.append(Character.forDigit(part & 0xf, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }
}
