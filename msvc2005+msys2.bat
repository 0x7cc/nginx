@echo off

call "C:\Program Files (x86)\Microsoft Visual Studio 8\VC\vcvarsall.bat" amd64

set PATH=%PATH%;C:\msys64\usr\bin

bash
