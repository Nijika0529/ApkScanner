#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir="$script_dir/vulntest-src"
test_keystore="$script_dir/vulntest-test-signing.jks"
build_root=$(mktemp -d)

cleanup() {
    rm -rf "$build_root"
}
trap cleanup EXIT HUP INT TERM

if [ -x /usr/lib/jvm/java-17-openjdk-amd64/bin/java ]; then
    PATH="/usr/lib/jvm/java-17-openjdk-amd64/bin:$PATH"
    export PATH
fi

build_version() {
    version_code=$1
    version_name=$2
    variant=$3
    project="$build_root/$variant"
    unsigned_apk="$build_root/$variant-unsigned.apk"
    aligned_apk="$build_root/$variant-aligned.apk"
    output_apk="$script_dir/version-evolution-$variant.apk"

    cp -R "$source_dir" "$project"
    cp "$script_dir/version-evolution-manifest.xml" "$project/AndroidManifest.xml"
    find "$project/smali/io/apkscanner/vulntest" \
        -type f ! -name 'SecretProvider.smali' -delete
    sed -i \
        -e "s/android:versionCode=\"1\"/android:versionCode=\"$version_code\"/" \
        -e "s/android:versionName=\"1.0\"/android:versionName=\"$version_name\"/" \
        "$project/AndroidManifest.xml"
    sed -i \
        -e "s/versionCode: '1'/versionCode: '$version_code'/" \
        -e "s/versionName: '1.0'/versionName: '$version_name'/" \
        "$project/apktool.yml"

    if [ "$variant" = "v2" ]; then
        sed -i '/^    \.locals 6$/a\\    nop' \
            "$project/smali/io/apkscanner/vulntest/SecretProvider.smali"
    fi
    if [ "$variant" = "v3-fixed" ]; then
        sed -i \
            '/android:name="\.SecretProvider"/,/android:grantUriPermissions/ s/android:exported="true"/android:exported="true" android:permission="io.apkscanner.vulntest.SIGNATURE_ONLY"/' \
            "$project/AndroidManifest.xml"
    fi

    apktool b "$project" -o "$unsigned_apk"
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
}

build_version 101 1.0.1 v1
build_version 102 1.0.2 v2
build_version 103 1.0.3 v3-fixed
