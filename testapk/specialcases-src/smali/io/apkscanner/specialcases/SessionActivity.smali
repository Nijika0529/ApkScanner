.class public Lio/apkscanner/specialcases/SessionActivity;
.super Landroid/app/Activity;
.source "SessionActivity.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 5
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, Lio/apkscanner/specialcases/SessionActivity;->getIntent()Landroid/content/Intent;
    move-result-object v0

    const-string v1, "session_id"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    if-eqz v2, :check_report
    const-string v3, "sessions"
    const/4 v4, 0x0
    invoke-virtual {p0, v3, v4}, Lio/apkscanner/specialcases/SessionActivity;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v3
    invoke-interface {v3}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;
    move-result-object v3
    const-string v4, "active_session"
    invoke-interface {v3, v4, v2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;
    move-result-object v3
    invoke-interface {v3}, Landroid/content/SharedPreferences$Editor;->apply()V

    :check_report
    const-string v1, "report_url"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    if-eqz v2, :done
    new-instance v3, Landroid/content/Intent;
    const-class v4, Lio/apkscanner/specialcases/HtmlPreviewActivity;
    invoke-direct {v3, p0, v4}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    invoke-virtual {v3, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
    invoke-virtual {p0, v3}, Lio/apkscanner/specialcases/SessionActivity;->startActivity(Landroid/content/Intent;)V

    :done
    return-void
.end method
