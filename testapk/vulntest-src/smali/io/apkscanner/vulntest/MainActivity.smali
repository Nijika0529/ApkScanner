.class public Lio/apkscanner/vulntest/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.java"

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 7

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    new-instance v0, Landroid/widget/TextView;
    invoke-direct {v0, p0}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V
    const-string v1, "APKScanner VulnTest: exported MainActivity"
    invoke-virtual {v0, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
    invoke-virtual {p0, v0}, Lio/apkscanner/vulntest/MainActivity;->setContentView(Landroid/view/View;)V

    invoke-virtual {p0}, Lio/apkscanner/vulntest/MainActivity;->getIntent()Landroid/content/Intent;
    move-result-object v0

    const-string v1, "target_activity"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1

    if-eqz v1, :check_nested

    :try_start_redirect
    invoke-static {v1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    move-result-object v2
    new-instance v3, Landroid/content/Intent;
    invoke-direct {v3, p0, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    const-string v4, "record_id"
    const-wide/16 v5, 0x1
    invoke-virtual {v3, v4, v5, v6}, Landroid/content/Intent;->putExtra(Ljava/lang/String;J)Landroid/content/Intent;
    invoke-virtual {p0, v3}, Lio/apkscanner/vulntest/MainActivity;->startActivity(Landroid/content/Intent;)V
    :try_end_redirect
    .catch Ljava/lang/Exception; {:try_start_redirect .. :try_end_redirect} :catch_redirect

    :catch_redirect
    nop

    :check_nested
    const-string v1, "inner_intent"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;
    move-result-object v1
    check-cast v1, Landroid/content/Intent;
    if-eqz v1, :check_url
    invoke-virtual {p0, v1}, Lio/apkscanner/vulntest/MainActivity;->startActivity(Landroid/content/Intent;)V

    :check_url
    const-string v1, "url"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    if-eqz v1, :done

    :try_start_web
    const-string v2, "UTF-8"
    invoke-static {v1, v2}, Ljava/net/URLDecoder;->decode(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    new-instance v2, Landroid/webkit/WebView;
    invoke-direct {v2, p0}, Landroid/webkit/WebView;-><init>(Landroid/content/Context;)V
    invoke-virtual {v2}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;
    move-result-object v3
    const/4 v4, 0x1
    invoke-virtual {v3, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    new-instance v3, Lio/apkscanner/vulntest/JsBridge;
    invoke-direct {v3}, Lio/apkscanner/vulntest/JsBridge;-><init>()V
    const-string v4, "VulnBridge"
    invoke-virtual {v2, v3, v4}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    invoke-virtual {v2, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    invoke-virtual {p0, v2}, Lio/apkscanner/vulntest/MainActivity;->setContentView(Landroid/view/View;)V
    :try_end_web
    .catch Ljava/lang/Exception; {:try_start_web .. :try_end_web} :catch_web

    :catch_web
    nop

    :done
    return-void
.end method
