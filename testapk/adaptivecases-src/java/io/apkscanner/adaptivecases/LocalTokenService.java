package io.apkscanner.adaptivecases;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public final class LocalTokenService extends Service implements Runnable {
    private volatile boolean running;
    private ServerSocket serverSocket;

    @Override
    public void onCreate() {
        super.onCreate();
        running = true;
        Thread worker = new Thread(this, "adaptive-local-token-server");
        worker.start();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void run() {
        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(
                    InetAddress.getByName("127.0.0.1"), 48765));
            Log.i("ADAPTIVE_TARGET", "localhost token endpoint ready");
            while (running) {
                try (Socket client = serverSocket.accept();
                     BufferedReader input = new BufferedReader(
                             new InputStreamReader(client.getInputStream()));
                     PrintWriter output = new PrintWriter(client.getOutputStream(), true)) {
                    String command = input.readLine();
                    if ("GET_SESSION".equals(command)) {
                        output.println("account=" + Secrets.ACCOUNT_ID);
                        output.println("token=" + Secrets.SESSION_TOKEN);
                        output.println("expires=" + Secrets.TOKEN_EXPIRY);
                    } else {
                        output.println("error=unknown_command");
                    }
                }
            }
        } catch (Exception exception) {
            Log.e("ADAPTIVE_TARGET", "localhost server stopped", exception);
        }
    }

    @Override
    public void onDestroy() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (Exception ignored) {
            // Test fixture cleanup only.
        }
        super.onDestroy();
    }
}
