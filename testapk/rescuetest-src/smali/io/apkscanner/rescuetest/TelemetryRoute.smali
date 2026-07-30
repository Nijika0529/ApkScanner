.class public final Lio/apkscanner/rescuetest/TelemetryRoute;
.super Ljava/lang/Object;
.source "TelemetryRoute.java"

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static dispatch(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 4

    const-string v0, "delivery_token"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;
    move-result-object v1
    check-cast v1, Landroid/app/PendingIntent;

    if-eqz v1, :done

    new-instance v2, Landroid/content/Intent;
    const-class v3, Lio/apkscanner/rescuetest/VaultRelay;
    invoke-direct {v2, p0, v3}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    invoke-virtual {v2, v0, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;
    invoke-virtual {p0, v2}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    :done
    return-void
.end method
