#!/bin/bash
# Compila o OVPNBar.app (sem projeto Xcode).  Uso: ./build.sh [--install | --dmg]
set -euo pipefail
cd "$(dirname "$0")"

APP=build/OVPNBar.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# binário universal (Apple Silicon + Intel)
for arch in arm64 x86_64; do
    swiftc -swift-version 5 -O -target $arch-apple-macos14.0 -parse-as-library \
        -o build/OVPNBar-$arch Sources/*.swift
done
lipo -create build/OVPNBar-arm64 build/OVPNBar-x86_64 -output "$APP/Contents/MacOS/OVPNBar"
rm -f build/OVPNBar-arm64 build/OVPNBar-x86_64

cp Info.plist "$APP/Contents/"
cp ../ovpnc.py "$APP/Contents/Resources/"

if [ ! -f build/AppIcon.icns ]; then
    swift Tools/make_icon.swift build/AppIcon.iconset
    iconutil -c icns build/AppIcon.iconset -o build/AppIcon.icns
    rm -rf build/AppIcon.iconset
fi
cp build/AppIcon.icns "$APP/Contents/Resources/"

codesign --force --sign - "$APP"
echo "ok: $APP"

if [ "${1:-}" = "--dmg" ]; then
    VERSION=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' Info.plist)
    DMG=build/OVPNBar-$VERSION.dmg
    STAGE=build/dmg
    rm -rf "$STAGE" "$DMG"
    mkdir -p "$STAGE"
    cp -R "$APP" "$STAGE/"
    ln -s /Applications "$STAGE/Applications"
    hdiutil create -volname "OVPNBar" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$DMG" >/dev/null
    rm -rf "$STAGE"
    codesign --force --sign - "$DMG"
    echo "dmg: $DMG"
fi

if [ "${1:-}" = "--install" ]; then
    pkill -x OVPNBar 2>/dev/null && sleep 2 || true
    rm -rf /Applications/OVPNBar.app
    cp -R "$APP" /Applications/
    echo "instalado em /Applications/OVPNBar.app"
fi
