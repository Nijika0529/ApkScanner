package io.apkscanner.adaptivecases;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

public final class SecretBinderService extends Service {
    private final Binder accountBinder = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                throws RemoteException {
            if (code == 7) {
                String operation = data.readString();
                if ("get_session_bundle".equals(operation)) {
                    reply.writeNoException();
                    reply.writeInt(200);
                    reply.writeString(Secrets.ACCOUNT_ID);
                    reply.writeString(Secrets.SESSION_TOKEN);
                    reply.writeLong(Secrets.TOKEN_EXPIRY);
                    return true;
                }
            }
            return super.onTransact(code, data, reply, flags);
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return accountBinder;
    }
}
