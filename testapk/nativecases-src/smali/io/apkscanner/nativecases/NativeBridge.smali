.class public final Lio/apkscanner/nativecases/NativeBridge;
.super Ljava/lang/Object;
.source "NativeBridge.java"

.method static constructor <clinit>()V
    .locals 1
    const-string v0, "nativecases"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method

.method public static native authorize(I)Z
.end method

.method public static native readSecret()J
.end method

.method public static native dynamicDecision(I)I
.end method
