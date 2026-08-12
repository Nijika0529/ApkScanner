.class public Lio/apkscanner/nativecases/NativeSecretBinder;
.super Landroid/os/Binder;
.source "NativeSecretBinder.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/os/Binder;-><init>()V
    return-void
.end method

.method protected onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z
    .locals 3
    const/4 v0, 0x1
    if-ne p1, v0, :fallback
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V
    invoke-static {}, Lio/apkscanner/nativecases/NativeBridge;->readSecret()J
    move-result-wide v1
    invoke-virtual {p3, v1, v2}, Landroid/os/Parcel;->writeLong(J)V
    return v0

    :fallback
    invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z
    move-result v0
    return v0
.end method
