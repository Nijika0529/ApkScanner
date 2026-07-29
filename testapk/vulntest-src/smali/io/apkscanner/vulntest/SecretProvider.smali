.class public Lio/apkscanner/vulntest/SecretProvider;
.super Landroid/content/ContentProvider;
.source "SecretProvider.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/content/ContentProvider;-><init>()V
    return-void
.end method

.method public onCreate()Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method

.method public getType(Landroid/net/Uri;)Ljava/lang/String;
    .locals 1
    const-string v0, "vnd.android.cursor.dir/vnd.vulntest.secret"
    return-object v0
.end method

.method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 6

    const/4 v0, 0x2
    new-array v1, v0, [Ljava/lang/String;
    const/4 v2, 0x0
    const-string v3, "username"
    aput-object v3, v1, v2
    const/4 v2, 0x1
    const-string v3, "password"
    aput-object v3, v1, v2

    new-instance v4, Landroid/database/MatrixCursor;
    invoke-direct {v4, v1}, Landroid/database/MatrixCursor;-><init>([Ljava/lang/String;)V

    new-array v5, v0, [Ljava/lang/Object;
    const/4 v2, 0x0
    const-string v3, "admin"
    aput-object v3, v5, v2
    const/4 v2, 0x1
    const-string v3, "hunter2"
    aput-object v3, v5, v2
    invoke-virtual {v4, v5}, Landroid/database/MatrixCursor;->addRow([Ljava/lang/Object;)V
    return-object v4
.end method

.method public insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;
    .locals 0
    return-object p1
.end method

.method public delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x1
    return v0
.end method

.method public update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x1
    return v0
.end method
