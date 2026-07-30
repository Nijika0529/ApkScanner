.class public Lio/apkscanner/rescuetest/EntryActivity;
.super Landroid/app/Activity;
.source "EntryActivity.java"

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 1

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    invoke-virtual {p0}, Lio/apkscanner/rescuetest/EntryActivity;->getIntent()Landroid/content/Intent;
    move-result-object v0

    invoke-static {p0, v0}, Lio/apkscanner/rescuetest/TelemetryRoute;->dispatch(Landroid/content/Context;Landroid/content/Intent;)V

    invoke-virtual {p0}, Lio/apkscanner/rescuetest/EntryActivity;->finish()V
    return-void
.end method
