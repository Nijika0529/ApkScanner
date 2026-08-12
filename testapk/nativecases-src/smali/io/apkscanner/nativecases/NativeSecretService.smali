.class public Lio/apkscanner/nativecases/NativeSecretService;
.super Landroid/app/Service;
.source "NativeSecretService.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Service;-><init>()V
    return-void
.end method

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 1
    new-instance v0, Lio/apkscanner/nativecases/NativeSecretBinder;
    invoke-direct {v0}, Lio/apkscanner/nativecases/NativeSecretBinder;-><init>()V
    return-object v0
.end method
