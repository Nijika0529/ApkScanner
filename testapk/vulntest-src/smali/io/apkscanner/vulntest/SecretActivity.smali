.class public Lio/apkscanner/vulntest/SecretActivity;
.super Landroid/app/Activity;
.source "SecretActivity.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, Lio/apkscanner/vulntest/SecretActivity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "record_id"
    const-wide/16 v2, -0x1
    invoke-virtual {v0, v1, v2, v3}, Landroid/content/Intent;->getLongExtra(Ljava/lang/String;J)J
    new-instance v0, Landroid/widget/TextView;
    invoke-direct {v0, p0}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V
    const-string v1, "Sensitive record: username=admin password=hunter2"
    invoke-virtual {v0, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
    invoke-virtual {p0, v0}, Lio/apkscanner/vulntest/SecretActivity;->setContentView(Landroid/view/View;)V
    return-void
.end method
