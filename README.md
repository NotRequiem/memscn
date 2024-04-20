Memory string scanner that analyzes all running processes in search of a specific string.

This scanner is my from scratch improvement of "Method Finder", a Java program that executed the program "strings.exe" (**https://github.com/glmcdona/strings2**) to every running process in the system to search for a specific memory string

# Usage

## Scanning All Processes
1. Run the program
2. Input the target string when prompted

## Scanning Specific Processes
To scan one or only certain processes for a specific string:

1. Open the console.
2. Add the -p, --pid, or --process flag followed by the PID numbers and/or process names before executing the program

Example: 
`C:\Windows\System32>D:\memscn-main\src\x64\Release\scn.exe -p 13000,javaw,4124,SystemInformer,msedge.exe`

This command line will scan the specified processes for the target string:
- PIDs: 13000 and 4124
- Process names: javaw.exe, SystemInformer.exe, and msedge.exe

# Features

> **__1.__** Does not use external programs or dependencies to scan the memory

> **__2.__** Fast scan algorithm based on manipulating memory with CPU registers, direct system calls and KMP algorithms

> **__3.__** Safe dynamic buffer allocation, should not take excessive memory resources while also having good scan speeds

> **__4.__** Parallel hardware processing: I made a function called __intr that selects the best intrinsic functions (SIMD instructions) to execute based on your CPU's capabilities to process memory. If your hardware does not support AVX-512, AVX or SSE instruction sets, it will switch to a callback else block that will perform normal string filtering without using my algorithms

> **__5.__** Can scan for every string that you put, both ASCII and Unicode and with any string length, but I left a comment with an extra conditional if block to only search for 1 byte strings

> **__6.__** Detection and filtering of useless processes to search for a specific string

> **__7.__** Token privilege escalation, a very common practice which makes my scanner able to scan more user-mode processes, which Method Finder did not have

> **__8.__** Easily portable, as you only have to remove the main function and redirect the strings found to your program

# Compatibility

> Any Windows system

> Any C++ standard

> Any processor architecture (32 or 64 bits)

> Any floating point model

> Any compiler optimization (tested every flag only on MSVC and GCC, but should work for Clang too)

# Improvements over Method Finder

- Enhanced Speed: Significantly faster scanning process.
- Reduced Program Size: Optimized for smaller footprint.
- Self-Contained: Doesn't rely on external dependencies or programs.
- Expanded Process Coverage: Capable of scanning a larger number of processes.
- Advanced Filtering: Filters out non-essential processes for efficient scanning.
- Streamlined Usage: Eliminates the need to set minimum string lengths for scanning.
- Automatic Termination: Halts automatically upon completing the scan, eliminating the need to manually exit the program.
- Heightened Accuracy: Improved detection capability ensures more accurate identification of the specified string across processes.