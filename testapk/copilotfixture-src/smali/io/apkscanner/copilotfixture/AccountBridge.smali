.class public final Lio/apkscanner/copilotfixture/AccountBridge;
.super Ljava/lang/Object;
.source "AccountBridge.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public readToken()Ljava/lang/String;
    .locals 1
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation
    const-string v0, "fixture-token"
    return-object v0
.end method
