@echo off
rem rootkey 本地管理工具启动脚本（Windows）
setlocal
set "JAR=%~dp0..\target\rootkey-toolkit.jar"
if not exist "%JAR%" (
  echo 未找到 %JAR%，请先在项目根目录执行: mvn -q package
  exit /b 1
)
java -jar "%JAR%" %*
