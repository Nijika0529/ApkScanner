#!/bin/sh
set -eu

fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
builder_script='
fixture_dir=$1
source_dir=$fixture_dir/bridgefocus-src
build_dir=$source_dir/build
classes_dir=$build_dir/classes
dex_dir=$build_dir/dex
android_jar=/usr/lib/android-sdk/platforms/android-36/android.jar
build_tools=/usr/lib/android-sdk/build-tools/36.1.0
unsigned_apk=$build_dir/bridgefocus-unsigned.apk
aligned_apk=$build_dir/bridgefocus-aligned.apk
output_apk=$fixture_dir/bridgefocus.apk

test "$build_dir" = "$source_dir/build"
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
    --ks "$fixture_dir/vulntest-test-signing.jks" \
    --ks-key-alias vulntest \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$output_apk" \
    "$aligned_apk"
"$build_tools/apksigner" verify --verbose "$output_apk"
'

if [ -f /usr/lib/android-sdk/platforms/android-36/android.jar ] && \
   [ -x /usr/lib/android-sdk/build-tools/36.1.0/aapt2 ] && \
   [ -x /usr/lib/jvm/java-17-openjdk-amd64/bin/java ]; then
    apk_java_home=/usr/lib/jvm/java-17-openjdk-amd64
    JAVA_HOME="$apk_java_home" PATH="$apk_java_home/bin:$PATH" \
        /bin/sh -eu -c "$builder_script" sh "$fixture_dir"
else
    worker_image=${APKSCANNER_CODEX_DOCKER_IMAGE:-apk-scanner-codex-worker:0.2.0}
    docker run --rm --entrypoint /bin/sh \
        --volume "$fixture_dir:/fixture" --workdir /fixture "$worker_image" \
        -eu -c "$builder_script" sh /fixture
fi

sha256sum "$fixture_dir/bridgefocus.apk"
