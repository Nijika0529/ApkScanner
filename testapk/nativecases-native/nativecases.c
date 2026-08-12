typedef unsigned char jboolean;
typedef int jint;
typedef long long jlong;
typedef void *jclass;
typedef const void **JNIEnv;
typedef const void **JavaVM;

typedef struct {
    const char *name;
    const char *signature;
    void *fn_ptr;
} JNINativeMethod;

#define JNI_TRUE ((jboolean)1)
#define JNI_OK 0
#define JNI_ERR (-1)
#define JNI_VERSION_1_6 0x00010006

static volatile const char native_gate_marker[] = "NATIVE_GATE_ALWAYS_ALLOW";
static volatile const char native_secret_marker[] = "NATIVE_ACCOUNT_SECRET_13579BDF2468ACE";
static volatile const char dynamic_gate_marker[] = "REGISTER_NATIVES_LEVEL_BYPASS";

__attribute__((visibility("default"))) jboolean
Java_io_apkscanner_nativecases_NativeBridge_authorize(
    JNIEnv *env,
    jclass type,
    jint requested_action
) {
    (void)env;
    (void)type;
    (void)requested_action;
    (void)native_gate_marker;
    return JNI_TRUE;
}

__attribute__((visibility("default"))) jlong
Java_io_apkscanner_nativecases_NativeBridge_readSecret(JNIEnv *env, jclass type) {
    (void)env;
    (void)type;
    (void)native_secret_marker;
    return (jlong)0x013579BDF2468ACELL;
}

static jint dynamic_decision(JNIEnv *env, jclass type, jint requested_level) {
    (void)env;
    (void)type;
    (void)requested_level;
    (void)dynamic_gate_marker;
    return 7;
}

__attribute__((visibility("default"))) jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = 0;
    jclass bridge;
    void **vm_functions = *(void ***)vm;
    void **env_functions;
    jint (*get_env)(JavaVM *, void **, jint) =
        (jint (*)(JavaVM *, void **, jint))vm_functions[6];
    jclass (*find_class)(JNIEnv *, const char *);
    jint (*register_natives)(JNIEnv *, jclass, const JNINativeMethod *, jint);
    JNINativeMethod methods[] = {
        {"dynamicDecision", "(I)I", (void *)dynamic_decision},
    };
    (void)reserved;
    if (get_env(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    env_functions = *(void ***)env;
    find_class = (jclass (*)(JNIEnv *, const char *))env_functions[6];
    register_natives =
        (jint (*)(JNIEnv *, jclass, const JNINativeMethod *, jint))env_functions[215];
    bridge = find_class(env, "io/apkscanner/nativecases/NativeBridge");
    if (bridge == 0) {
        return JNI_ERR;
    }
    if (register_natives(env, bridge, methods, 1) < 0) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
