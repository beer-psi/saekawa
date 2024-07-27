<h1 align="center">saekawa</h1>

<p align="center">インパアフェクシオン・ホワイトガアル</p>

CHUNITHM hook to submit your scores to Tachi every credit.

### Features
- Submit scores to Tachi after each credit.
- Submit dan and emblem classes to Tachi.

### Installation
- [Install Visual C++ Redistributable 2022](https://github.com/abbodi1406/vcredist/releases/latest) if you haven't already.
- Download the [latest release](https://github.com/beer-psi/saekawa/releases/latest)
- Extract the zip (if you downloaded the zip) and put `saekawa.dll` in the game folder, where
`chusanApp.exe`/`chuniApp.exe` is (usually the `bin` folder)
- Create and edit the [config file](https://github.com/beer-psi/saekawa/blob/trunk/res/saekawa.toml)
(download a config file pre-filled with your Tachi API key [here](https://kamai.tachi.ac/client-file-flow/CXSaekawa)),
and place it in the same folder as the DLL.
- When you start the game, inject the DLL into the game process. For segatools, that would be
adding `-k saekawa.dll` to the arguments of `inject_x86.exe` so it looks like the second line:
```batchfile
REM inject_x86.exe -d -k chusanhook.dll chusanApp.exe
inject_x86.exe -d -k chusanhook.dll -k saekawa.dll chusanApp.exe
```

**DO NOT INJECT THIS DLL INTO `amdaemon.exe`! THE HOOK DOES NOT USE ANYTHING FROM amdaemon, AND YOU MIGHT GET A CRASH!**

### Credits
- Adam Thibert ([adamaq01](https://github.com/adamaq01)). A lot of the code was copied from
[Mikado](https://github.com/adamaq01/Mikado), a similar hook for SDVX.

### License
0BSD
