.class public Lio/apkscanner/nativecases/NativeGateActivity;
.super Landroid/app/Activity;
.source "NativeGateActivity.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 5
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    invoke-virtual {p0}, Lio/apkscanner/nativecases/NativeGateActivity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "requested_action"
    const/4 v2, 0x0
    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I
    move-result v0

    invoke-static {v0}, Lio/apkscanner/nativecases/NativeBridge;->authorize(I)Z
    move-result v1
    if-eqz v1, :denied

    const-string v1, "NATIVE_ADMIN_ACTION=executed"
    goto :show

    :denied
    const-string v1, "NATIVE_ADMIN_ACTION=denied"

    :show
    const-string v2, "APKSCANNER_NATIVE"
    invoke-static {v2, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    new-instance v3, Landroid/widget/TextView;
    invoke-direct {v3, p0}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V
    invoke-virtual {v3, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
    const/high16 v4, 0x41c00000    # 24.0f
    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setTextSize(F)V
    const/16 v4, 0x30
    invoke-virtual {v3, v4, v4, v4, v4}, Landroid/widget/TextView;->setPadding(IIII)V
    invoke-virtual {p0, v3}, Lio/apkscanner/nativecases/NativeGateActivity;->setContentView(Landroid/view/View;)V
    return-void
.end method
