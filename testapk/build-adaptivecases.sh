#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir="$script_dir/adaptivecases-src"
output_apk="$script_dir/adaptivecases.apk"
test_keystore="$script_dir/vulntest-test-signing.jks"
worker_image=${APKSCANNER_CODEX_DOCKER_IMAGE:-apk-scanner-codex-worker:0.2.0}

docker run --rm \
    --entrypoint /bin/sh \
    --volume "$script_dir:/fixture" \
    --workdir /fixture \
    "$worker_image" \
    -eu -c '
source_dir=/fixture/adaptivecases-src
build_dir=$source_dir/build
classes_dir=$build_dir/classes
dex_dir=$build_dir/dex
android_jar=/usr/lib/android-sdk/platforms/android-36/android.jar
build_tools=/usr/lib/android-sdk/build-tools/36.1.0
unsigned_apk=$build_dir/adaptivecases-unsigned.apk
aligned_apk=$build_dir/adaptivecases-aligned.apk
output_apk=/fixture/adaptivecases.apk

rm -rf "$build_dir"
mkdir -p "$classes_dir" "$dex_dir"
find "$source_dir/java" -name "*.java" -print | sort > "$build_dir/sources.list"
javac -source 8 -target 8 -bootclasspath "$android_jar" \
    -d "$classes_dir" @"$build_dir/sources.list"
find "$classes_dir" -name "*.class" -print | sort > "$build_dir/classes.list"
"$build_tools/d8" --lib "$android_jar" --min-api 26 \
    --output "$dex_dir" @"$build_dir/classes.list"
touch -t 198001010000 "$dex_dir/classes.dex"
"$build_tools/aapt2" link \
    -I "$android_jar" \
    --manifest "$source_dir/AndroidManifest.xml" \
    --min-sdk-version 26 \
    --target-sdk-version 36 \
    --version-code 1 \
    --version-name 1.0 \
    -o "$unsigned_apk"
zip -X -q -j "$unsigned_apk" "$dex_dir/classes.dex"
"$build_tools/zipalign" -f 4 "$unsigned_apk" "$aligned_apk"
"$build_tools/apksigner" sign \
    --v1-signing-enabled false \
    --v2-signing-enabled true \
    --v3-signing-enabled true \
    --v4-signing-enabled false \
    --ks /fixture/vulntest-test-signing.jks \
    --ks-key-alias vulntest \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$output_apk" \
    "$aligned_apk"
"$build_tools/apksigner" verify --verbose "$output_apk"
'

sha256sum "$output_apk"
