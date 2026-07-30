.class public Lio/apkscanner/specialcases/HtmlPreviewActivity;
.super Landroid/app/Activity;
.source "HtmlPreviewActivity.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 5
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    new-instance v0, Landroid/webkit/WebView;
    invoke-direct {v0, p0}, Landroid/webkit/WebView;-><init>(Landroid/content/Context;)V
    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;
    move-result-object v1
    const/4 v2, 0x1
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
    new-instance v3, Lio/apkscanner/specialcases/SensitiveBridge;
    invoke-direct {v3}, Lio/apkscanner/specialcases/SensitiveBridge;-><init>()V
    const-string v4, "AgentAction"
    invoke-virtual {v0, v3, v4}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    invoke-virtual {p0}, Lio/apkscanner/specialcases/HtmlPreviewActivity;->getIntent()Landroid/content/Intent;
    move-result-object v1
    const-string v2, "report_url"
    invoke-virtual {v1, v2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    invoke-virtual {p0, v0}, Lio/apkscanner/specialcases/HtmlPreviewActivity;->setContentView(Landroid/view/View;)V
    return-void
.end method
