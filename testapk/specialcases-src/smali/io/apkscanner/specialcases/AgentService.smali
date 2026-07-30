.class public Lio/apkscanner/specialcases/AgentService;
.super Landroid/app/Service;
.source "AgentService.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Service;-><init>()V
    return-void
.end method

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 1
    new-instance v0, Lio/apkscanner/specialcases/AgentBinder;
    invoke-direct {v0}, Lio/apkscanner/specialcases/AgentBinder;-><init>()V
    return-object v0
.end method
