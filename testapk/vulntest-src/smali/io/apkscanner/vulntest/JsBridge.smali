.class public Lio/apkscanner/vulntest/JsBridge;
.super Ljava/lang/Object;
.source "JsBridge.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public getSecret()Ljava/lang/String;
    .locals 1
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation

    const-string v0, "demo-password=hunter2"
    return-object v0
.end method
