.class public Lio/apkscanner/vulntest/CommandService;
.super Landroid/app/Service;
.source "CommandService.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Service;-><init>()V
    return-void
.end method

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 1
    new-instance v0, Lio/apkscanner/vulntest/SecretBinder;
    invoke-direct {v0}, Lio/apkscanner/vulntest/SecretBinder;-><init>()V
    return-object v0
.end method
