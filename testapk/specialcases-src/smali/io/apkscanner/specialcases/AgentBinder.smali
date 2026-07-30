.class public Lio/apkscanner/specialcases/AgentBinder;
.super Landroid/os/Binder;
.source "AgentBinder.java"

.method public constructor <init>()V
    .locals 2
    invoke-direct {p0}, Landroid/os/Binder;-><init>()V
    const/4 v0, 0x0
    const-string v1, "io.apkscanner.specialcases.IAgentService"
    invoke-virtual {p0, v0, v1}, Landroid/os/Binder;->attachInterface(Landroid/os/IInterface;Ljava/lang/String;)V
    return-void
.end method

.method public sendRequest(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 2
    const-string v0, "AgentBinder"
    invoke-static {v0, p1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    new-instance v0, Lio/apkscanner/specialcases/CliExecutor;
    invoke-direct {v0}, Lio/apkscanner/specialcases/CliExecutor;-><init>()V
    invoke-virtual {v0, p2}, Lio/apkscanner/specialcases/CliExecutor;->execute(Ljava/lang/String;)V
    const-string v1, "REQUEST_ACCEPTED"
    return-object v1
.end method

.method protected onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z
    .locals 4
    const/4 v0, 0x1
    if-ne p1, v0, :delegate
    const-string v0, "io.apkscanner.specialcases.IAgentService"
    invoke-virtual {p2, v0}, Landroid/os/Parcel;->enforceInterface(Ljava/lang/String;)V
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;
    move-result-object v1
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;
    move-result-object v2
    invoke-virtual {p0, v1, v2}, Lio/apkscanner/specialcases/AgentBinder;->sendRequest(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    move-result-object v3
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V
    invoke-virtual {p3, v3}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V
    const/4 v0, 0x1
    return v0
    :delegate
    invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z
    move-result v0
    return v0
.end method
