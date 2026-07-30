.class public Lio/apkscanner/specialcases/CliExecutor;
.super Ljava/lang/Object;
.source "CliExecutor.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public execute(Ljava/lang/String;)V
    .locals 4
    invoke-static {p1}, Lio/apkscanner/specialcases/ShellRiskAssessor;->isDenied(Ljava/lang/String;)Z
    move-result v0
    if-nez v0, :done
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    move-result-object v0
    const/4 v1, 0x3
    new-array v1, v1, [Ljava/lang/String;
    const/4 v2, 0x0
    const-string v3, "/system/bin/sh"
    aput-object v3, v1, v2
    const/4 v2, 0x1
    const-string v3, "-c"
    aput-object v3, v1, v2
    const/4 v2, 0x2
    aput-object p1, v1, v2
    invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;
    move-result-object v2
    :done
    return-void
.end method
