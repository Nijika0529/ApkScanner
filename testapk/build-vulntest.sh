#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir="$script_dir/vulntest-src"
output_apk="$script_dir/vulntest.apk"
test_keystore="$script_dir/vulntest-test-signing.jks"
build_dir=$(mktemp -d "$script_dir/.vulntest-build.XXXXXX")
unsigned_apk="$build_dir/vulntest-unsigned.apk"
normalized_apk="$build_dir/vulntest-normalized.apk"
aligned_apk="$build_dir/vulntest-aligned.apk"
signed_apk="$build_dir/vulntest-signed.apk"
unpacked_dir="$build_dir/unpacked"

cleanup() {
    rm -rf -- "$build_dir"
}
trap cleanup EXIT HUP INT TERM

if [ -x /usr/lib/jvm/java-17-openjdk-amd64/bin/java ]; then
    PATH="/usr/lib/jvm/java-17-openjdk-amd64/bin:$PATH"
    export PATH
fi

apktool b "$source_dir" -o "$unsigned_apk"
# Apktool stamps ZIP entries with the build time. Normalize every entry before
# signing so the checked-in fixture SHA binds the source, not the CI wall clock.
mkdir -p "$unpacked_dir"
unzip -q "$unsigned_apk" -d "$unpacked_dir"
find "$unpacked_dir" -type f -exec touch -t 198001010000 {} +
(
    cd "$unpacked_dir"
    find . -type f -printf '%P\n' | LC_ALL=C sort | zip -X -q "$normalized_apk" -@
)
zipalign -f 4 "$normalized_apk" "$aligned_apk"
apksigner sign \
    --v1-signing-enabled true \
    --v2-signing-enabled true \
    --v3-signing-enabled true \
    --v4-signing-enabled false \
    --ks "$test_keystore" \
    --ks-key-alias vulntest \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$signed_apk" \
    "$aligned_apk"
apksigner verify --verbose "$signed_apk"
mv -f -- "$signed_apk" "$output_apk"
sha256sum "$output_apk"
