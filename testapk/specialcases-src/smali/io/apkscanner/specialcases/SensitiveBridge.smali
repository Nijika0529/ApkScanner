.class public Lio/apkscanner/specialcases/SensitiveBridge;
.super Ljava/lang/Object;
.source "SensitiveBridge.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public getAgentToken()Ljava/lang/String;
    .locals 1
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation
    const-string v0, "demo_system_token"
    return-object v0
.end method
