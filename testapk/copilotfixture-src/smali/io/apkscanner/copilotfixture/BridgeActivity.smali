.class public Lio/apkscanner/copilotfixture/BridgeActivity;
.super Landroid/app/Activity;
.source "BridgeActivity.java"

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
    new-instance v3, Lio/apkscanner/copilotfixture/AccountBridge;
    invoke-direct {v3}, Lio/apkscanner/copilotfixture/AccountBridge;-><init>()V
    const-string v4, "AccountBridge"
    invoke-virtual {v0, v3, v4}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    const-string v1, "file:///android_asset/dist/index.html"
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    invoke-virtual {p0, v0}, Lio/apkscanner/copilotfixture/BridgeActivity;->setContentView(Landroid/view/View;)V
    const-string v1, "APKSCANNER_FIXTURE"
    const-string v2, "BRIDGE_OK"
    invoke-static {v1, v2}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method
