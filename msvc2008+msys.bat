@echo off

call "C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" amd64

set PATH=%PATH%;C:\MinGW\msys\1.0\bin

bash
