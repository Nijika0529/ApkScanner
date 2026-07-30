.class public Lio/apkscanner/specialcases/AgentApp;
.super Landroid/app/Application;
.source "AgentApp.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Application;-><init>()V
    return-void
.end method

.method public onCreate()V
    .locals 2
    invoke-super {p0}, Landroid/app/Application;->onCreate()V
    const-string v0, "agent.gateway"
    const-string v1, "ws://agent-gateway-pre.example.test"
    invoke-static {v0, v1}, Ljava/lang/System;->setProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    return-void
.end method
