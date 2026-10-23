@echo off
call "D:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat"
cl /nologo /O2 /W4 tests\load_dll.c /Fe:tests\load_dll.exe
