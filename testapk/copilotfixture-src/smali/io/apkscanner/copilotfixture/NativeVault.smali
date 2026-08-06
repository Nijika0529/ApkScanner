.class public final Lio/apkscanner/copilotfixture/NativeVault;
.super Ljava/lang/Object;
.source "NativeVault.java"

.method static constructor <clinit>()V
    .locals 1
    const-string v0, "fixturevault"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method

.method public static native readCanary()J
.end method
