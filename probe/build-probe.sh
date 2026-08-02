#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
output_dir="$script_dir/app/build/outputs/apk/debug"
worker_image=${APKSCANNER_CODEX_WORKER_IMAGE:-apk-scanner-codex-worker:0.2.0}

mkdir -p "$output_dir"

docker run --rm \
    --network none \
    --user "$(id -u):$(id -g)" \
    --entrypoint /bin/sh \
    -v "$repository_dir:/src:ro" \
    -v "$output_dir:/out" \
    "$worker_image" \
    -lc '
set -eu
sdk=/usr/lib/android-sdk
tools="$sdk/build-tools/36.1.0"
android_jar="$sdk/platforms/android-36/android.jar"
build=/out/.probe-build
classes="$build/classes"
dex="$build/dex"

rm -rf "$build"
mkdir -p "$classes" "$dex"

"$tools/aapt2" link \
    -o "$build/unsigned.apk" \
    -I "$android_jar" \
    --manifest /src/probe/app/src/main/AndroidManifest.xml \
    --min-sdk-version 26 \
    --target-sdk-version 36 \
    --version-code 3 \
    --version-name 0.3.0

javac \
    -encoding UTF-8 \
    -source 8 \
    -target 8 \
    -classpath "$android_jar" \
    -d "$classes" \
    /src/probe/app/src/main/java/io/apkscanner/probe/ProbeReceiver.java

"$tools/d8" \
    --lib "$android_jar" \
    --min-api 26 \
    --output "$dex" \
    $(find "$classes" -name "*.class" -type f | sort)

jar uf "$build/unsigned.apk" -C "$dex" classes.dex
"$tools/zipalign" -f 4 "$build/unsigned.apk" "$build/aligned.apk"
"$tools/apksigner" sign \
    --ks /src/testapk/vulntest-test-signing.jks \
    --ks-key-alias vulntest \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out /out/app-debug.apk \
    "$build/aligned.apk"
"$tools/apksigner" verify --verbose /out/app-debug.apk
rm -rf "$build"
'

sha256sum "$output_dir/app-debug.apk"
