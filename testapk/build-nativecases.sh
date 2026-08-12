#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir="$script_dir/nativecases-src"
build_dir="$script_dir/.nativecases-build"
test_keystore="$script_dir/vulntest-test-signing.jks"
output_apk="$script_dir/nativecases.apk"

if [ -x /usr/lib/jvm/java-17-openjdk-amd64/bin/java ]; then
    PATH="/usr/lib/jvm/java-17-openjdk-amd64/bin:/usr/lib/android-sdk/build-tools/36.1.0:$PATH"
    export PATH
fi

cleanup() {
    rm -rf "$build_dir"
    rm -rf "$source_dir/build"
    rm -f "$source_dir/lib/arm64-v8a/libnativecases.so"
}
trap cleanup EXIT HUP INT TERM

rm -rf "$source_dir/build"
mkdir -p "$build_dir" "$source_dir/lib/arm64-v8a"

clang --target=aarch64-linux-android26 \
    -shared -fPIC -nostdlib -fuse-ld=lld \
    -Wl,-soname,libnativecases.so \
    -Wl,-z,relro,-z,now \
    -o "$source_dir/lib/arm64-v8a/libnativecases.so" \
    "$script_dir/nativecases-native/nativecases.c"

apktool b "$source_dir" -o "$build_dir/nativecases-unsigned.apk"
zipalign -f 4 "$build_dir/nativecases-unsigned.apk" "$build_dir/nativecases-aligned.apk"
apksigner sign \
    --v4-signing-enabled false \
    --ks "$test_keystore" \
    --ks-key-alias vulntest \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$output_apk" \
    "$build_dir/nativecases-aligned.apk"
apksigner verify --verbose "$output_apk"
sha256sum "$output_apk"
