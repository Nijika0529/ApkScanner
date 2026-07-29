#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir="$script_dir/vulntest-src"
unsigned_apk="$script_dir/vulntest-unsigned.apk"
aligned_apk="$script_dir/vulntest-aligned.apk"
output_apk="$script_dir/vulntest.apk"
test_keystore="$script_dir/vulntest-test-signing.jks"

cleanup() {
    rm -f "$unsigned_apk" "$aligned_apk"
}
trap cleanup EXIT HUP INT TERM

if [ -x /usr/lib/jvm/java-17-openjdk-amd64/bin/java ]; then
    PATH="/usr/lib/jvm/java-17-openjdk-amd64/bin:$PATH"
    export PATH
fi

apktool b "$source_dir" -o "$unsigned_apk"
zipalign -f 4 "$unsigned_apk" "$aligned_apk"
apksigner sign \
    --ks "$test_keystore" \
    --ks-key-alias vulntest \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$output_apk" \
    "$aligned_apk"
apksigner verify --verbose "$output_apk"
sha256sum "$output_apk"
