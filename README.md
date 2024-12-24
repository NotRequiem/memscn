**memscn** is a tool that analyzes processes in search of a specific string in memory. This string is chosen by the user.

# Usage

## Scanning All Processes
1. Run the program
2. Input the target string when prompted

## Scanning Specific Processes
To scan one or only certain processes for a specific string:

1. Open the console.
2. Add the -p, -pid, or -process flag followed by the PID numbers and/or process names before executing the program.

Example: 
`C:\Windows\System32>D:\memscn-main\src\x64\Release\scn.exe -p 13000,javaw,4124,SystemInformer,msedge.exe`

This command line will scan the specified processes for the target string:
- PIDs: 13000 and 4124
- Process names: javaw.exe, SystemInformer.exe, and msedge.exe

3. Input the target string when prompted

# Features
> **__1.__** Does not use external programs or dependencies to scan the memory

> **__2.__** Low resouce consumption (CPU and RAM usage)

> **__3.__** Able to detect any string: ASCII, Unicode and Extended Unicode, with any string length

> **__4.__** Easily portable

> **__5.__** Compatible with any Windows x64 system

# Legal
I am not responsible nor liable for any damage you cause through any malicious usage of this project.

License: MIT