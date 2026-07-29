.class public Lio/apkscanner/vulntest/DeepLinkActivity;
.super Landroid/app/Activity;
.source "DeepLinkActivity.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 6

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, Lio/apkscanner/vulntest/DeepLinkActivity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v1
    if-eqz v1, :fallback
    const-string v2, "url"
    invoke-virtual {v1, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    if-nez v2, :load

    :fallback
    const-string v2, "http://example.invalid/"

    :load
    new-instance v3, Landroid/webkit/WebView;
    invoke-direct {v3, p0}, Landroid/webkit/WebView;-><init>(Landroid/content/Context;)V
    invoke-virtual {v3}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;
    move-result-object v4
    const/4 v5, 0x1
    invoke-virtual {v4, v5}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    new-instance v4, Lio/apkscanner/vulntest/JsBridge;
    invoke-direct {v4}, Lio/apkscanner/vulntest/JsBridge;-><init>()V
    const-string v5, "VulnBridge"
    invoke-virtual {v3, v4, v5}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    invoke-virtual {p0, v3}, Lio/apkscanner/vulntest/DeepLinkActivity;->setContentView(Landroid/view/View;)V
    return-void
.end method
