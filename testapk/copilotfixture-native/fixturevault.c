typedef long long jlong;

__attribute__((visibility("default")))
jlong Java_io_apkscanner_copilotfixture_NativeVault_readCanary(void *env, void *type) {
    (void)env;
    (void)type;
    return 42;
}

__attribute__((visibility("default")))
int JNI_OnLoad(void *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    return 0x00010006;
}
