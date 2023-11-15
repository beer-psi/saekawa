## Saekawa
CHUNITHM hook to submit your scores to Tachi every credit.

### Features
- Submit scores to Tachi after each credit.
- Submit dan and emblem classes to Tachi.

### Installation
- Put it in your game installation root directory
- Create and edit the config file to set your API key (optional, if it doesn't exist it
will be created automatically)
- When you start the game, inject the DLL into the game process. For example,
edit your segatools game.bat to look like the green line:
```diff
- inject_x86.exe -d -k chusanhook.dll chusanApp.exe
+ inject_x86.exe -d -k saekawa.dll -k chusanhook.dll chusanApp.exe
```

### Caveats
This hook requires the game's network communications to be decrypted, which can be done
by patching the game binary with your preferred patcher.

If you choose not to patch, you will need to obtain the necessary keys and provide them
in `saekawa.toml`.

### Credits
- Adam Thibert ([adamaq01](https://github.com/adamaq01)). A lot of the code was
shamelessly lifted from his [Mikado](https://github.com/adamaq01/Mikado), a similar
hook for SDVX.

### License
0BSD