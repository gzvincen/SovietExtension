#!/bin/bash
# ==============================================================================
# build_framework.sh
#
# 用 Command Line Tools 的 clang 直接把 SovietExtension 源码编译成 universal
# (x86_64 + arm64) framework，无需完整 Xcode。
#
# 产物会覆盖 Rely/Plugin/SovietExtension.framework，可直接被 install.sh 使用。
#
# 用法：
#   sh Rely/build_framework.sh
#   ARCHS="x86_64 arm64" sh Rely/build_framework.sh   # 自定义架构
# ==============================================================================

set -euo pipefail

if [ -z "${BASH_VERSION:-}" ]; then
    exec /bin/bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${PROJECT_DIR}/SovietExtension"

FRAMEWORK_NAME="SovietExtension"
PLUGIN_DIR="${SCRIPT_DIR}/Plugin"
FRAMEWORK_DIR="${PLUGIN_DIR}/${FRAMEWORK_NAME}.framework"

# 默认产出 universal，让插件在 Intel(x86_64) 和 Apple Silicon(arm64) 上都能加载。
ARCHS="${ARCHS:-x86_64 arm64}"
MIN_VERSION="${MIN_VERSION:-11.0}"

BUILD_DIR="$(mktemp -d /tmp/se_build.XXXXXX)"
trap 'rm -rf "${BUILD_DIR}"' EXIT

SDK="$(xcrun --show-sdk-path)"
CXX_V1="${SDK}/usr/include/c++/v1"

ARCH_FLAGS=()
for a in ${ARCHS}; do
    ARCH_FLAGS+=("-arch" "${a}")
done

COMMON_FLAGS=(
    "${ARCH_FLAGS[@]}"
    -isysroot "${SDK}"
    -mmacosx-version-min="${MIN_VERSION}"
    -fobjc-arc
    -fvisibility=hidden
    -O2
    -Wno-deprecated-declarations
    -Wno-reorder-init-list
    -I"${SRC_DIR}"
)

echo "=============================="
echo " Build ${FRAMEWORK_NAME}.framework"
echo "=============================="
echo "ARCHS=${ARCHS}"
echo "SDK=${SDK}"
echo "SRC_DIR=${SRC_DIR}"
echo "OUTPUT=${FRAMEWORK_DIR}"
echo ""

OBJECTS=()

echo "👉 Compile .m (Objective-C) ..."
for f in "${SRC_DIR}"/*.m; do
    [ -e "${f}" ] || continue
    obj="${BUILD_DIR}/$(basename "${f%.m}").o"
    clang -c "${COMMON_FLAGS[@]}" -std=gnu17 "${f}" -o "${obj}"
    OBJECTS+=("${obj}")
    echo "   ok: $(basename "${f}")"
done

echo "👉 Compile .mm (Objective-C++) ..."
for f in "${SRC_DIR}"/*.mm; do
    [ -e "${f}" ] || continue
    obj="${BUILD_DIR}/$(basename "${f%.mm}").o"
    clang++ -c "${COMMON_FLAGS[@]}" -std=gnu++20 -stdlib=libc++ -isystem "${CXX_V1}" "${f}" -o "${obj}"
    OBJECTS+=("${obj}")
    echo "   ok: $(basename "${f}")"
done

echo "👉 Link dylib ..."
clang++ -dynamiclib \
    "${ARCH_FLAGS[@]}" \
    -isysroot "${SDK}" \
    -mmacosx-version-min="${MIN_VERSION}" \
    -stdlib=libc++ \
    -install_name "@rpath/${FRAMEWORK_NAME}.framework/Versions/A/${FRAMEWORK_NAME}" \
    -compatibility_version 1.0.0 -current_version 1.0.0 \
    -framework Foundation -framework AppKit -framework Cocoa -lobjc \
    "${OBJECTS[@]}" \
    -o "${BUILD_DIR}/${FRAMEWORK_NAME}"

echo "👉 Assemble .framework bundle ..."
rm -rf "${FRAMEWORK_DIR}"
mkdir -p "${FRAMEWORK_DIR}/Versions/A/Resources"
cp "${BUILD_DIR}/${FRAMEWORK_NAME}" "${FRAMEWORK_DIR}/Versions/A/${FRAMEWORK_NAME}"

cat > "${FRAMEWORK_DIR}/Versions/A/Resources/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleExecutable</key>
	<string>${FRAMEWORK_NAME}</string>
	<key>CFBundleIdentifier</key>
	<string>com.mustangym.${FRAMEWORK_NAME}</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>${FRAMEWORK_NAME}</string>
	<key>CFBundlePackageType</key>
	<string>FMWK</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
	<key>CFBundleSupportedPlatforms</key>
	<array>
		<string>MacOSX</string>
	</array>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>LSMinimumSystemVersion</key>
	<string>${MIN_VERSION}</string>
</dict>
</plist>
PLIST

# Framework 标准符号链接结构
ln -sf A "${FRAMEWORK_DIR}/Versions/Current"
ln -sf "Versions/Current/${FRAMEWORK_NAME}" "${FRAMEWORK_DIR}/${FRAMEWORK_NAME}"
ln -sf "Versions/Current/Resources" "${FRAMEWORK_DIR}/Resources"

echo "👉 Code sign (ad-hoc) ..."
codesign --force --sign - --timestamp=none "${FRAMEWORK_DIR}" || true

echo ""
echo "✅ Done."
echo "    Binary: ${FRAMEWORK_DIR}/Versions/A/${FRAMEWORK_NAME}"
lipo -info "${FRAMEWORK_DIR}/Versions/A/${FRAMEWORK_NAME}"
echo ""
echo "Next / 接下来："
echo "  sh ${SCRIPT_DIR}/install.sh"
