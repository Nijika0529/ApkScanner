#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
plugin_source="$script_dir/copilotfixture-plugin-src"
host_source="$script_dir/copilotfixture-src"
build_dir="$script_dir/.copilotfixture-build"
test_keystore="$script_dir/vulntest-test-signing.jks"
output_apk="$script_dir/copilotfixture.apk"

if [ -x /usr/lib/jvm/java-17-openjdk-amd64/bin/java ]; then
    PATH="/usr/lib/jvm/java-17-openjdk-amd64/bin:$PATH"
    export PATH
fi

cleanup() {
    rm -rf "$build_dir"
    rm -rf "$plugin_source/build" "$host_source/build"
    rm -f "$host_source/assets/plugin/entityplugin.apk"
    rm -f "$host_source/assets/plugin/entityplugin.apk.idsig"
    rm -f "$host_source/lib/arm64-v8a/libfixturevault.so"
}
trap cleanup EXIT HUP INT TERM

rm -rf "$plugin_source/build" "$host_source/build"
mkdir -p "$build_dir" "$host_source/assets/plugin" "$host_source/lib/arm64-v8a"

apktool b "$plugin_source" -o "$build_dir/entityplugin-unsigned.apk"
zipalign -f 4 "$build_dir/entityplugin-unsigned.apk" "$build_dir/entityplugin-aligned.apk"
apksigner sign \
    --v4-signing-enabled false \
    --ks "$test_keystore" \
    --ks-key-alias vulntest \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$host_source/assets/plugin/entityplugin.apk" \
    "$build_dir/entityplugin-aligned.apk"

clang --target=aarch64-linux-android26 \
    -shared -fPIC -nostdlib -fuse-ld=lld \
    -Wl,-soname,libfixturevault.so \
    -o "$host_source/lib/arm64-v8a/libfixturevault.so" \
    "$script_dir/copilotfixture-native/fixturevault.c"

apktool b "$host_source" -o "$build_dir/copilotfixture-unsigned.apk"
zipalign -f 4 "$build_dir/copilotfixture-unsigned.apk" "$build_dir/copilotfixture-aligned.apk"
apksigner sign \
    --v4-signing-enabled false \
    --ks "$test_keystore" \
    --ks-key-alias vulntest \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$output_apk" \
    "$build_dir/copilotfixture-aligned.apk"
apksigner verify --verbose "$output_apk"
sha256sum "$output_apk"
