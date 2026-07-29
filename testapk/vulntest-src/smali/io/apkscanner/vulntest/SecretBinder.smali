.class public Lio/apkscanner/vulntest/SecretBinder;
.super Landroid/os/Binder;
.source "SecretBinder.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/os/Binder;-><init>()V
    return-void
.end method

.method protected onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z
    .locals 1

    const/4 v0, 0x1
    if-ne p1, v0, :fallback
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V
    const-string v0, "service-secret=hunter2"
    invoke-virtual {p3, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V
    const/4 v0, 0x1
    return v0

    :fallback
    invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z
    move-result v0
    return v0
.end method
