.class public Lio/apkscanner/rescuetest/VaultRelay;
.super Landroid/content/BroadcastReceiver;
.source "VaultRelay.java"

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V
    return-void
.end method

.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 5

    const-string v0, "delivery_token"
    invoke-virtual {p2, v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;
    move-result-object v0
    check-cast v0, Landroid/app/PendingIntent;

    if-eqz v0, :done

    new-instance v1, Landroid/content/Intent;
    invoke-direct {v1}, Landroid/content/Intent;-><init>()V
    const-string v2, "vault_secret"
    const-string v3, "rescue-chain-secret"
    invoke-virtual {v1, v2, v3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    :try_start_send
    const/4 v2, 0x0
    invoke-virtual {v0, p1, v2, v1}, Landroid/app/PendingIntent;->send(Landroid/content/Context;ILandroid/content/Intent;)V
    const-string v2, "RESCUETEST_TARGET"
    const-string v4, "vault_secret=rescue-chain-secret"
    invoke-static {v2, v4}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_send
    .catch Landroid/app/PendingIntent$CanceledException; {:try_start_send .. :try_end_send} :catch_send

    :catch_send
    nop

    :done
    return-void
.end method
