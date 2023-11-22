<h1 align="center">saekawa</h1>

<p align="center">インパアフェクシオン・ホワイトガアル</p>

CHUNITHM hook to submit your scores to Tachi every credit.

### Features
- Submit scores to Tachi after each credit.
- Submit dan and emblem classes to Tachi.

### Installation
- Download the [latest release](https://github.com/beerpiss/saekawa/releases/latest)
- Put it in your game installation root folder.
- Create and edit the [config file](https://github.com/beerpiss/saekawa/blob/trunk/res/saekawa.toml)
(download a config file pre-filled with your Tachi API key [here](https://kamaitachi.xyz/client-file-flow/CXSaekawa)),
and place it in the same folder as the DLL.
- When you start the game, inject the DLL into the game process. For example,
edit your segatools game.bat to look like the green line:
```diff
- inject_x86.exe -d -k chusanhook.dll chusanApp.exe
+ inject_x86.exe -d -k saekawa.dll -k chusanhook.dll chusanApp.exe
```

### Caveats
This hook requires the game's network communications to be decrypted, which can be done
by patching the game binary with your preferred patcher. (if you're already running a local
server like Aqua or ARTEMiS and had no idea encryption even existed, you're good to go)

If you choose not to patch, you will need to obtain the necessary keys and provide them
in the configuration file.

### Credits
- Adam Thibert ([adamaq01](https://github.com/adamaq01)). A lot of the code was copied from
[Mikado](https://github.com/adamaq01/Mikado), a similar hook for SDVX.

### License
0BSD
