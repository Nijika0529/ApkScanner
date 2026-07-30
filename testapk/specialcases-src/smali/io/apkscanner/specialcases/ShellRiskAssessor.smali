.class public Lio/apkscanner/specialcases/ShellRiskAssessor;
.super Ljava/lang/Object;
.source "ShellRiskAssessor.java"

.method public static isDenied(Ljava/lang/String;)Z
    .locals 2
    const-string v0, "pm clear"
    invoke-virtual {p0, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v1
    if-nez v1, :denied
    const-string v0, "am broadcast"
    invoke-virtual {p0, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v1
    if-nez v1, :denied
    const/4 v0, 0x0
    return v0
    :denied
    const/4 v0, 0x1
    return v0
.end method
