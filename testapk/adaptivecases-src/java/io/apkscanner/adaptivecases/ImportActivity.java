package io.apkscanner.adaptivecases;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.widget.TextView;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public final class ImportActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        TextView result = new TextView(this);
        setContentView(result);
        Uri stream = getIntent().getData();
        if (stream == null && Intent.ACTION_SEND.equals(getIntent().getAction())) {
            if (Build.VERSION.SDK_INT >= 33) {
                stream = getIntent().getParcelableExtra(Intent.EXTRA_STREAM, Uri.class);
            } else {
                stream = getIntent().getParcelableExtra(Intent.EXTRA_STREAM);
            }
        }
        if (stream == null) {
            result.setText("No archive supplied");
            return;
        }
        List<String> imported = new ArrayList<>();
        try (InputStream input = getContentResolver().openInputStream(stream);
             ZipInputStream zip = new ZipInputStream(input)) {
            ZipEntry entry;
            byte[] buffer = new byte[8192];
            while ((entry = zip.getNextEntry()) != null) {
                File destination = new File(getFilesDir(), entry.getName());
                if (entry.isDirectory()) {
                    destination.mkdirs();
                    continue;
                }
                File parent = destination.getParentFile();
                if (parent != null) {
                    parent.mkdirs();
                }
                try (FileOutputStream output = new FileOutputStream(destination)) {
                    int count;
                    while ((count = zip.read(buffer)) != -1) {
                        output.write(buffer, 0, count);
                    }
                }
                imported.add(entry.getName());
            }
            result.setText("Imported entries: " + imported);
        } catch (Exception exception) {
            result.setText("Import failed: " + exception.getClass().getSimpleName());
        }
    }
}
