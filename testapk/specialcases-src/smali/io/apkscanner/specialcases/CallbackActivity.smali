.class public Lio/apkscanner/specialcases/CallbackActivity;
.super Landroid/app/Activity;
.source "CallbackActivity.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, Lio/apkscanner/specialcases/CallbackActivity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v0
    const-string v1, "ret"
    invoke-virtual {v0, v1}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    const-string v1, "0"
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v2
    if-eqz v2, :done
    const-string v1, "authorization"
    const/4 v2, 0x0
    invoke-virtual {p0, v1, v2}, Lio/apkscanner/specialcases/CallbackActivity;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v3
    invoke-interface {v3}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;
    move-result-object v3
    const-string v1, "qqmusic_authorized"
    const/4 v2, 0x1
    invoke-interface {v3, v1, v2}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;
    move-result-object v3
    invoke-interface {v3}, Landroid/content/SharedPreferences$Editor;->apply()V
    const-string v1, "CallbackActivity"
    const-string v2, "authorization accepted without state"
    invoke-static {v1, v2}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :done
    invoke-virtual {p0}, Lio/apkscanner/specialcases/CallbackActivity;->finish()V
    return-void
.end method
