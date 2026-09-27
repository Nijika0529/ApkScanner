package io.apkscanner.adaptivecases;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Process;

/** Shell-only digest oracle for a target-owned synthetic Web canary. */
public final class FixtureCanaryProvider extends ContentProvider {
    private static final String AUTHORITY = "io.apkscanner.adaptivecases.fixture";

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
            String[] selectionArgs, String sortOrder) {
        requireShellCaller();
        requireCanaryPath(uri);
        MatrixCursor cursor = new MatrixCursor(new String[] {
                "experiment_id", "token_sha256", "bridge_calls", "bridge_url_sha256"});
        String tokenSha256 = WebCanaryState.tokenSha256(getContext());
        String experimentId = WebCanaryState.experimentId(getContext());
        if (tokenSha256 != null && experimentId != null) {
            cursor.addRow(new Object[] {
                    experimentId,
                    tokenSha256,
                    WebCanaryState.bridgeCalls(getContext()),
                    WebCanaryState.bridgeUrlSha256(getContext()),
            });
        }
        return cursor;
    }

    @Override
    public String getType(Uri uri) {
        requireShellCaller();
        requireCanaryPath(uri);
        return "vnd.android.cursor.item/vnd.io.apkscanner.webcanary";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        requireShellCaller();
        requireCanaryPath(uri);
        if (values == null) {
            throw new IllegalArgumentException("missing fixture values");
        }
        String experimentId = values.getAsString("experiment_id");
        if (values.size() != 1 || experimentId == null
                || !experimentId.matches("[a-f0-9-]{36}")) {
            throw new IllegalArgumentException("invalid fixture values");
        }
        if (!WebCanaryState.seed(getContext(), experimentId)) {
            throw new IllegalStateException("could not persist fixture canary");
        }
        return uri;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        requireShellCaller();
        requireCanaryPath(uri);
        if (selection == null || !selection.matches("experiment_id=[a-f0-9-]{36}")
                || selectionArgs != null) {
            throw new IllegalArgumentException("delete must name one experiment");
        }
        String experimentId = selection.substring("experiment_id=".length());
        return WebCanaryState.clear(getContext(), experimentId) ? 1 : 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection,
            String[] selectionArgs) {
        requireShellCaller();
        throw new UnsupportedOperationException("read-only fixture oracle");
    }

    private static void requireShellCaller() {
        // DUMP has the "development" flag and can be granted to a regular
        // app by ADB. Permission alone therefore cannot protect a proof
        // canary from an attacker APK that later reports a forged callback.
        if (Binder.getCallingUid() != Process.SHELL_UID) {
            throw new SecurityException("fixture canary is reserved for the shell oracle");
        }
    }

    private static void requireCanaryPath(Uri uri) {
        if (!AUTHORITY.equals(uri.getAuthority()) || !"/web-canary".equals(uri.getPath())) {
            throw new IllegalArgumentException("unknown fixture URI");
        }
    }
}
