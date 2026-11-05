#!/bin/sh
# Builds Poppy.app. Pass --install to copy it to ~/Applications and start it.
set -e
cd "$(dirname "$0")"

APP=Poppy.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"

swiftc -O -o "$APP/Contents/MacOS/Poppy" Poppy.swift

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key><string>party.chee.poppy</string>
	<key>CFBundleName</key><string>Poppy</string>
	<key>CFBundleDisplayName</key><string>Poppy</string>
	<key>CFBundleExecutable</key><string>Poppy</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>1.0</string>
	<key>CFBundleVersion</key><string>1</string>
	<key>LSMinimumSystemVersion</key><string>13.0</string>
	<key>LSUIElement</key><true/>
	<key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

codesign --force --sign - "$APP"
echo "built $APP"

if [ "$1" = "--install" ]; then
	pkill -x Poppy 2>/dev/null || true
	mkdir -p "$HOME/Applications"
	rm -rf "$HOME/Applications/$APP"
	cp -R "$APP" "$HOME/Applications/"
	open "$HOME/Applications/$APP"
	echo "installed to ~/Applications/$APP and started"
fi
