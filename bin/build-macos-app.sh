#!/usr/bin/env bash
# 用 jpackage 将客户端打成 macOS 原生 .app（双击启动，自带精简 JRE）
# 产物：dist/RootKeyToolkit.app
set -e
cd "$(dirname "$0")/.."

mvn -q package

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp target/rootkey-toolkit.jar "$STAGE/"

# jpackage 不覆盖已存在的产物，先清掉旧包
rm -rf "dist/RootKeyToolkit.app"
mkdir -p dist

jpackage \
  --type app-image \
  --name RootKeyToolkit \
  --input "$STAGE" \
  --main-jar rootkey-toolkit.jar \
  --main-class com.metrace.rootkey.client.RootKeyClient \
  --app-version 2.0.0 \
  --vendor metrace \
  --dest dist

echo
echo "已生成 dist/RootKeyToolkit.app —— 双击即可打开客户端"
echo "本地试运行: open dist/RootKeyToolkit.app"
