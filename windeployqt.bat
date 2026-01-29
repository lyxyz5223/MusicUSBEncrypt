
@REM set QtPath=K:\Qt\Qt5.9.9\5.9.9\msvc2015
set QtPath=%PATH%
set PATH=%QtPath%;

%QtPath%\bin\windeployqt.exe --libdir .\dlls --release .