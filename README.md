Memory string scanner that analyzes all running processes in search of a specific string.

This scanner is my from scratch improvement of "Method Finder", a Java program that executed the program "strings.exe" (**https://github.com/glmcdona/strings2**) to every running process in the system to search for a specific memory string.

# In-Depth Explanation (skip if you do not want to read)

This memory scanner utilizes CPU registers, SIMD (Single Instruction, Multiple Data) instructions, and the Knuth-Morris-Pratt (KMP) algorithm for efficient memory scanning.

CPU registers are small, high-speed storage locations within the CPU used to hold data temporarily during program execution. SIMD instructions allow a single instruction to operate on multiple data elements simultaneously, which significantly boosts performance for certain types of operations, such as those commonly encountered in memory scanning tasks.

The KMP algorithm is employed for pattern searching within memory regions. It efficiently finds occurrences of a substring within a larger string by avoiding unnecessary backtracking, making it particularly suitable for searching large memory regions quickly.

The SE_DEBUG_PRIVILEGE privilege is needed to access the memory of certain user-mode processes. This privilege allows the scanner to bypass certain security restrictions imposed by the operating system, enabling it to read the memory of processes running in user mode.

The program determines which intrinsic to use based on the CPU's capabilities. It does this through a function called __intr, which selects the best intrinsic functions (SIMD instructions) to execute based on the CPU's capabilities. If the hardware supports AVX-512, AVX, or SSE instruction sets, the program utilizes the corresponding intrinsic functions to maximize processing efficiency. Otherwise, it falls back to standard string filtering methods. This dynamic selection ensures optimal performance across different hardware configurations.

1. **CPU Registers:**

They are small, high-speed storage locations within the CPU. They store data temporarily during program execution, providing fast access for the CPU to operands and intermediate results. Registers are built directly into the CPU, making them the fastest storage option available.

When a program executes, the CPU fetches instructions and data from memory into its registers to perform calculations and operations. These registers are organized into different types, such as general-purpose registers, floating-point registers, and special-purpose registers.

General-purpose registers (like EAX, EBX, ECX, and EDX in x86 architecture) are used for general computation and data manipulation. They store operands and intermediate results during arithmetic and logical operations. Floating-point registers (like XMM0, XMM1, etc.) are dedicated to floating-point arithmetic operations. Special-purpose registers serve various functions, such as storing the instruction pointer, stack pointer, and status flags.

Due to their proximity to the CPU's execution units and their fast access time, CPU registers are the fastest storage option for data processing. Accessing data stored in registers is significantly faster than accessing data in system memory.

2. **SIMD (Single Instruction, Multiple Data):**

SIMD is a parallel processing technique that allows a single instruction to operate on multiple data elements simultaneously. It is commonly used in tasks that involve processing large amounts of data in parallel, such as multimedia processing, scientific computing, and image processing.

Internally, SIMD instructions are executed by vector processing units within the CPU. These units are specialized hardware components designed to perform parallel computations on data vectors. SIMD instructions operate on SIMD registers, which are larger than traditional CPU registers and can hold multiple data elements (e.g., integers or floating-point numbers) in a single register.

When a SIMD instruction is executed, the CPU's vector processing units simultaneously apply the instruction to each element in the SIMD register. This allows for parallel computation across multiple data elements, leading to significant performance improvements compared to scalar processing (where each operation is performed sequentially).

SIMD instructions are particularly effective for tasks that involve repetitive operations on large arrays or matrices, as they can process multiple elements in parallel with a single instruction. This parallelism exploits the inherent data-level parallelism present in many computational tasks, making SIMD an essential tool for optimizing performance in a wide range of applications.

3. **KMP:**
   
The Knuth-Morris-Pratt (KMP) algorithm is an efficient string searching algorithm that works by exploiting the structure of the pattern being searched for. Unlike naive string searching algorithms that examine every character in the text for each occurrence of the pattern, KMP avoids redundant comparisons by utilizing information about the pattern itself.

At the core of the KMP algorithm is the concept of a "failure function" or "partial match table," which is precomputed based on the pattern to be searched. This table provides information about the longest proper prefix of the pattern that is also a suffix at each position within the pattern.

Here's how the failure function is computed:

> 1. Start with an empty prefix/suffix match length of 0 for the first character of the pattern.

> 2. Iterate through the pattern, updating the prefix/suffix match length for each character.

> 3. When extending the prefix/suffix match length for a character, check if the next character also matches the corresponding character in the current prefix/suffix. If it does, increment the match length; if it doesn't, reset the match length based on the previously computed values.

> 4. This precomputed failure function allows the KMP algorithm to efficiently skip unnecessary comparisons during the search process. Instead of blindly sliding the pattern along the text and comparing characters at each position, KMP uses the failure function to determine how far it can shift the pattern without missing potential matches.

During the search process, KMP maintains two pointers: one for the text and one for the pattern. The pattern pointer is adjusted based on the failure function, allowing the algorithm to skip ahead in the text without revisiting characters that have already been matched.

By avoiding redundant comparisons and intelligently skipping ahead in the text, the KMP algorithm achieves linear-time complexity in the worst case, making it significantly faster than naive string searching algorithms, especially for large texts and patterns.

**Dynamic detection of the best intrinsics**

The function __intr is responsible for dynamically detecting the best intrinsic function to use based on the CPU's capabilities. 
This function utilizes the __cpuidex instruction to query the CPU for information about its features and instruction set extensions.
The CPUID instruction is a privileged x86 instruction that allows software to query the CPU for information about its features and capabilities. It returns a set of values in the EAX, EBX, ECX, and EDX registers, which encode various CPU features and supported instruction set extensions.

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

> Any floating point model

> Any compiler optimization

# Improvements over Method Finder

- Enhanced Speed: Significantly faster scanning process.
- Reduced Program Size: Optimized for smaller footprint.
- Self-Contained: Doesn't rely on external dependencies or programs.
- Expanded Process Coverage: Capable of scanning a larger number of processes.
- Advanced Filtering: Filters out non-essential processes for efficient scanning.
- Streamlined Usage: Eliminates the need to set minimum string lengths for scanning.
- Automatic Termination: Halts automatically upon completing the scan, eliminating the need to manually exit the program.
- Heightened Accuracy: Improved detection capability ensures more accurate identification of the specified string across processes.