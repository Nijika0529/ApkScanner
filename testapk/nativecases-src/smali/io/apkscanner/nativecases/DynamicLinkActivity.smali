.class public Lio/apkscanner/nativecases/DynamicLinkActivity;
.super Landroid/app/Activity;
.source "DynamicLinkActivity.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 6
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    const/4 v0, 0x0
    invoke-virtual {p0}, Lio/apkscanner/nativecases/DynamicLinkActivity;->getIntent()Landroid/content/Intent;
    move-result-object v1
    invoke-virtual {v1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v1
    if-eqz v1, :decide
    const-string v2, "level"
    invoke-virtual {v1, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    if-eqz v1, :decide
    invoke-static {v1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I
    move-result v0

    :decide
    invoke-static {v0}, Lio/apkscanner/nativecases/NativeBridge;->dynamicDecision(I)I
    move-result v1
    if-lez v1, :denied
    const-string v2, "DYNAMIC_NATIVE_BYPASS=granted"
    goto :show

    :denied
    const-string v2, "DYNAMIC_NATIVE_BYPASS=denied"

    :show
    const-string v3, "APKSCANNER_NATIVE"
    invoke-static {v3, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    new-instance v4, Landroid/widget/TextView;
    invoke-direct {v4, p0}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V
    invoke-virtual {v4, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
    const/high16 v5, 0x41c00000    # 24.0f
    invoke-virtual {v4, v5}, Landroid/widget/TextView;->setTextSize(F)V
    const/16 v5, 0x30
    invoke-virtual {v4, v5, v5, v5, v5}, Landroid/widget/TextView;->setPadding(IIII)V
    invoke-virtual {p0, v4}, Lio/apkscanner/nativecases/DynamicLinkActivity;->setContentView(Landroid/view/View;)V
    return-void
.end method
