#!/usr/bin/env bash
# Build (and test) the Privara Burp extension. No Gradle, no Maven: javac + jar from any JDK 17+.
#
#   ./build.sh            compile, run the unit tests, write dist/privara-burp.jar (+ .sha256)
#   ./build.sh test       compile and run the unit tests only
#   ./build.sh clean
#
# The Montoya API jar is fetched from Maven Central ONCE into lib/ and checked against the sha256
# pinned below; a mismatch stops the build. It is compile-time only: Burp provides the API at run
# time, so it is never put inside our jar.
#
# JDK: $JAVA_HOME, else /usr/libexec/java_home (macOS), else Android Studio's bundled JBR, else
# javac on PATH. Nothing is installed system-wide.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

MONTOYA_VERSION="2025.5"
MONTOYA_SHA256="72189ffd322763dcf182accb5e742948d6bc203f22e4dce934fb70f9290de57c"
MONTOYA_URL="https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/${MONTOYA_VERSION}/montoya-api-${MONTOYA_VERSION}.jar"
MONTOYA_JAR="lib/montoya-api-${MONTOYA_VERSION}.jar"
# Fixed so the jar's bytes depend only on the sources and the JDK (reproducible within one JDK).
JAR_DATE="2026-11-12T00:00:00Z"

find_jdk() {
    local c
    for c in "${JAVA_HOME:-}" \
             "$( [ -x /usr/libexec/java_home ] && /usr/libexec/java_home -v 17+ 2>/dev/null || true)" \
             "/Applications/Android Studio.app/Contents/jbr/Contents/Home"; do
        if [ -n "$c" ] && [ -x "$c/bin/javac" ] && "$c/bin/javac" -version >/dev/null 2>&1; then
            echo "$c"; return 0
        fi
    done
    if command -v javac >/dev/null 2>&1 && javac -version >/dev/null 2>&1; then
        dirname "$(dirname "$(command -v javac)")"; return 0
    fi
    return 1
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

if [ "${1:-}" = "clean" ]; then
    rm -rf build
    echo "cleaned build/ (lib/ and dist/ kept)"
    exit 0
fi

JDK="$(find_jdk)" || { echo "no JDK 17+ found: set JAVA_HOME (a JDK under your home folder is fine)" >&2; exit 2; }
JAVAC="$JDK/bin/javac"; JAVA="$JDK/bin/java"; JAR="$JDK/bin/jar"
echo "JDK: $("$JAVAC" -version 2>&1)  ($JDK)"

mkdir -p lib
if [ ! -f "$MONTOYA_JAR" ]; then
    echo "fetching montoya-api ${MONTOYA_VERSION} from Maven Central"
    curl -fsSL --max-time 120 -o "$MONTOYA_JAR.part" "$MONTOYA_URL"
    mv "$MONTOYA_JAR.part" "$MONTOYA_JAR"
fi
GOT="$(sha256 "$MONTOYA_JAR")"
if [ "$GOT" != "$MONTOYA_SHA256" ]; then
    echo "montoya-api jar sha256 mismatch: got $GOT, pinned $MONTOYA_SHA256 -- refusing" >&2
    rm -f "$MONTOYA_JAR"
    exit 3
fi

rm -rf build
mkdir -p build/classes build/test-classes
find src/main/java -name '*.java' | LC_ALL=C sort > build/main-sources.txt
"$JAVAC" --release 17 -encoding UTF-8 -Xlint:all,-serial -Werror -cp "$MONTOYA_JAR" \
    -d build/classes @build/main-sources.txt

# Unit tests: core only (no Burp on the class path), against a loopback stub of the Privara API.
find src/test/java -name '*.java' | LC_ALL=C sort > build/test-sources.txt
"$JAVAC" --release 17 -encoding UTF-8 -cp "build/classes:$MONTOYA_JAR" -d build/test-classes @build/test-sources.txt
# core tests run with NO Burp API on the class path: the core must not depend on it
"$JAVA" -cp build/classes:build/test-classes com.privara.burp.core.CoreTests
# the Montoya side, inside a recording fake of Burp (headless)
"$JAVA" -Djava.awt.headless=true -cp "build/classes:build/test-classes:$MONTOYA_JAR" com.privara.burp.MontoyaSmoke
# every Montoya reference in the built classes resolves in the pinned API jar
"$JAVA" -cp build/test-classes com.privara.burp.LinkCheck build/classes "$MONTOYA_JAR"
# Optional, against a REAL Burp Suite jar (Burp ships the Montoya API inside it), e.g. the official
# burpsuite_<version>.jar from portswigger.net: link check + the fake-Burp smoke on Burp's own API
# classes. Burp itself is not started. BURP_JAR=/path/to/burpsuite.jar ./build.sh test
if [ -n "${BURP_JAR:-}" ]; then
    [ -f "$BURP_JAR" ] || { echo "BURP_JAR=$BURP_JAR: no such file" >&2; exit 4; }
    echo "== against the real Burp jar: $(basename "$BURP_JAR")"
    "$JAVA" -cp build/test-classes com.privara.burp.LinkCheck build/classes "$BURP_JAR"
    "$JAVA" -Djava.awt.headless=true -cp "build/classes:build/test-classes:$BURP_JAR" com.privara.burp.MontoyaSmoke
fi

if [ "${1:-}" = "test" ]; then
    exit 0
fi

VERSION="$(sed -n 's/.*String VERSION = "\([^"]*\)".*/\1/p' src/main/java/com/privara/burp/core/Version.java)"
cat > build/MANIFEST.MF <<EOF
Manifest-Version: 1.0
Implementation-Title: Privara iOS kit for Burp Suite
Implementation-Version: ${VERSION}
Implementation-Vendor: TAJ APPS LLC
Created-By: privara build.sh
EOF
mkdir -p dist
( cd build/classes && find . -name '*.class' | LC_ALL=C sort | sed 's|^\./||' > ../jar-list.txt )
rm -f dist/privara-burp.jar
( cd build/classes && "$JAR" --create --file ../../dist/privara-burp.jar --manifest ../MANIFEST.MF \
    --date "$JAR_DATE" @../jar-list.txt )
echo "$(sha256 dist/privara-burp.jar)  privara-burp.jar" > dist/privara-burp.jar.sha256
echo "built dist/privara-burp.jar  version ${VERSION}  $(wc -c < dist/privara-burp.jar | tr -d ' ') bytes"
cat dist/privara-burp.jar.sha256
