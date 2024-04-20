#include <intrin.h>
#include <memory>
#include <algorithm>
#include <vector>
#include <functional>
#include <string>
#include <iostream>
#include <sstream>
#include <windows.h>
#include <psapi.h>

#include "kernel_call.h"

#define cpuid(info, x)    __cpuidex(info, x, 0)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation,
    MemorySharedCommitInformation,
    MemoryImageInformation,
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation,
    MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

EXTERN_C NTSTATUS RequiemNtClose(
    IN HANDLE Handle);

EXTERN_C NTSTATUS RequiemNtQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength OPTIONAL);

EXTERN_C NTSTATUS RequiemNtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS RequiemNtReadVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress OPTIONAL,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesRead OPTIONAL);

__forceinline void __intr(BOOL& _SSE, BOOL& _AVX, BOOL& _AVX512) {
    int info[4];
    cpuid(info, 0);
    int nIds = info[0];

    cpuid(info, 0x80000000);

    _SSE = _AVX = _AVX512 = 0;

    if (nIds >= 0x00000001) {
        cpuid(info, 0x00000001);
        _SSE = (info[3] & ((int)1 << 25)) != 0;
        _AVX = (info[2] & ((int)1 << 28)) != 0;
    }

    if (nIds >= 0x00000007) {
        cpuid(info, 0x00000007);
        _AVX512 = (info[1] & ((int)1 << 16)) != 0;
    }
}

__forceinline void RPM(const std::string& __str, BOOL SSE, BOOL AVX, BOOL AVX512, const std::vector<DWORD>& pids = std::vector<DWORD>()) {
    /*

    push ebp
        mov ebp, esp
        sub esp, __LOCAL_SIZE
        push ebx
        push esi
        push edi

    */

    DWORD p[1024]; DWORD n, j; 
    if (!pids.empty()) {
        DWORD* px = const_cast<DWORD*>(pids.data());
        j = static_cast<DWORD>(pids.size());
        std::copy(px, px + j, p);
    }
    else {
        if (!K32EnumProcesses(p, sizeof(p), &n)) {
            std::cerr << "Failed to enumerate all processes in the system." << std::endl;
            return;
        }
        j = n / sizeof(DWORD);
    }

    DWORD _p = GetCurrentProcessId();

    // My custom KMP algorithm
    std::vector<int> lps(__str.size(), 0);
    int len = 0;
    for (size_t i = 1; i < __str.size();) {
        if (__str[i] == __str[len]) {
            len++;
            lps[i] = len;
            i++;
        }
        else {
            if (len != 0) {
                len = lps[static_cast<std::vector<int, std::allocator<int>>::size_type>(len) - 1];
            }
            else {
                lps[i] = 0;
                i++;
            }
        }
    }

    for (DWORD i = 0; i < j; i++) {
        DWORD __p = p[i];
        if (__p == 0 || __p == 4 || __p == 140 || __p == 104 || __p == _p) {
            continue;
        }

        HANDLE h;
        NTSTATUS status;
        OBJECT_ATTRIBUTES objAttr{};
        CLIENT_ID clientId{};
        HANDLE processHandle;

        RtlSecureZeroMemory(&objAttr, sizeof(OBJECT_ATTRIBUTES));
        objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

        RtlSecureZeroMemory(&clientId, sizeof(CLIENT_ID));
        clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(__p));

        status = RequiemNtOpenProcess(&processHandle, (0x0400) | (0x0010), &objAttr, &clientId);
        if (NT_SUCCESS(status)) {
            h = processHandle;
            printf("Scanning Process: %d\n", __p);

            SYSTEM_INFO s;
            GetSystemInfo(&s);
            MEMORY_BASIC_INFORMATION z{};
            BOOL x = 0;

            for (LPVOID addr = s.lpMinimumApplicationAddress; addr < s.lpMaximumApplicationAddress;
                addr = (LPBYTE)z.BaseAddress + z.RegionSize) {
                PVOID BaseAddress = addr;
                SIZE_T Length = sizeof(z);
                SIZE_T ReturnLength;

                status = RequiemNtQueryVirtualMemory(h, BaseAddress, MemoryBasicInformation, &z, Length, &ReturnLength);
                if (NT_SUCCESS(status)) {
                    if (z.State == 0x00001000 && !(z.Protect & 0x100) && !(z.Protect & 0x01)) {
                        std::vector<char> n(z.RegionSize);
                        SIZE_T r;

                        status = RequiemNtReadVirtualMemory(h, z.BaseAddress, n.data(), z.RegionSize, &r);
                        if (NT_SUCCESS(status)) {
                            char* dataPtr = n.data();
                            if (AVX512) {
                                const size_t z = __str.size();
                                const size_t s = 64;

                                size_t __avx512 = (r - z) / s;

                                __m512i cmp = _mm512_loadu_epi32(reinterpret_cast<const __m512i*>(__str.c_str()));

                                for (size_t i = 0; i < __avx512; ++i) {
                                    __m512i data = _mm512_loadu_epi32(reinterpret_cast<const __m512i*>(dataPtr + i * s));

                                    size_t j = 0;
                                    while (j < s) {
                                        __m512i cmpData = _mm512_loadu_epi32(reinterpret_cast<const __m512i*>(dataPtr + i * s + j));
                                        __mmask64 m = _mm512_cmpeq_epu8_mask(cmpData, cmp);

                                        if (m != 0) {
                                            size_t k = 0; 
                                            /*
                                            If you want to only search for ASCII characters:
                                            if (dataPtr[i * s + j] >= 32 && dataPtr[i * s + j] <= 126) {
                                            */
                                            for (; k < z; ++k) {
                                                if (dataPtr[i * s + j + k] != __str[k]) {
                                                    break;
                                                }
                                            }
                                            if (k == z) {
                                                printf("[+] String detected in %d\n", __p);
                                                x = 1;
                                                break;
                                            }
                                            j += k - lps[k - 1];
                                        }
                                        else {
                                            ++j;
                                        }
                                    }
                                }
                            }
                            else if (AVX) {
                                const size_t z = __str.size();
                                const size_t s = 32;

                                size_t __avx = (r - z) / s;

                                __m256i cmp = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(__str.c_str()));

                                for (size_t i = 0; i < __avx; ++i) {
                                    __m256i data = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(dataPtr + i * s));

                                    size_t j = 0;
                                    while (j < s) {
                                        __m256i r = _mm256_cmpeq_epi8(data, cmp);
                                        int m = _mm256_movemask_epi8(r);

                                        if (m != 0) {
                                            size_t k = 0;
                                            for (; k < z; ++k) {
                                                if (dataPtr[i * s + j + k] != __str[k]) {
                                                    break;
                                                }
                                            }
                                            if (k == z) {
                                                printf("[+] String detected in %d\n", __p);
                                                x = 1;
                                                break;
                                            }
                                            j += k - lps[k - 1];
                                        }
                                        else {
                                            ++j;
                                        }
                                    }
                                }
                            }
                            else if (SSE) {
                                const size_t z = __str.size();
                                const size_t s = 16;

                                size_t __sse = (r - z) / s;

                                __m128i cmp = _mm_loadu_si128(reinterpret_cast<const __m128i*>(__str.c_str()));

                                for (size_t i = 0; i < __sse; ++i) {
                                    __m128i data = _mm_loadu_si128(reinterpret_cast<const __m128i*>(dataPtr + i * s));

                                    size_t j = 0;
                                    while (j < s) {
                                        __m128i r = _mm_cmpeq_epi8(data, cmp);
                                        int m = _mm_movemask_epi8(r);

                                        if (m != 0 && (z & 0xFFFF) != 0) {
                                            size_t k = 0;
                                            for (; k < z; ++k) {
                                                if (dataPtr[i * s + j + k] != __str[k]) {
                                                    break;
                                                }
                                            }
                                            if (k == z) {
                                                printf("[+] String detected in %d\n", __p);
                                                x = 1;
                                                break;
                                            }
                                            j += k - lps[k - 1];
                                        }
                                        else {
                                            ++j;
                                        }
                                    }
                                }
                            }
                            else {
                                const size_t z = __str.size();
                                for (size_t i = 0; i <= r - z; ++i) {
                                    if (dataPtr[i] >= 32 && dataPtr[i] <= 126) {
                                        int y = 1;
                                        for (size_t j = 0; j < z; ++j) {
                                            if (dataPtr[i + j] != __str[j]) {
                                                y = 0;
                                                break;
                                            }
                                        }
                                        if (y) {
                                            printf("[+] String detected in %d\n", __p);
                                            x = 1;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if (x)
                    break;
            }

            RequiemNtClose(h);
        }
    }
    /*
    
     pop edi
        pop esi
        pop ebx
        mov esp, ebp
        pop ebp
        ret

    */
}

static BOOL AdjustTokenPrivilege(HANDLE hproc)
{
    HANDLE htoken; 
    DWORD dw_t;

    if (OpenProcessToken(hproc, (((0x00020000L)) | (0x0008)) | (0x0008) | (0x0020), &htoken))
    {
        DWORD dw_s = sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES) * 100;
        std::unique_ptr<BYTE[]> memory = std::make_unique<BYTE[]>(dw_s);

        if (memory)
        {
            TOKEN_PRIVILEGES* priv = reinterpret_cast<TOKEN_PRIVILEGES*>(memory.get());
            if (GetTokenInformation(htoken, TokenPrivileges, priv, dw_s, &dw_t))
            {
                if (priv->PrivilegeCount > 0)
                {
                    for (DWORD i = 0; i < priv->PrivilegeCount; i++)
                    {
                        priv->Privileges[i].Attributes = 0x00000002L;
                    }

                    if (AdjustTokenPrivileges(htoken, 0, priv, dw_s, 0, 0))
                    {
                        CloseHandle(htoken);
                        return 1;
                    }
                }
            }
        }
        CloseHandle(htoken);
    }

    return 0;
}

static std::wstring toLower(const std::wstring& str) {
    std::wstring result = str;
    std::transform(result.begin(), result.end(), result.begin(), [](wchar_t c) {
        return std::tolower(c, std::locale());
        });
    return result;
}

static std::string __trim(const std::string& str) {
    size_t start = 0; 
    size_t end = str.length() - 1;

    while (start <= end && (std::isspace(str[start]) || str[start] == '\0')) {
        start++;
    }
    while (end >= start && (std::isspace(str[end]) || str[end] == '\0')) {
        end--;
    }

    return str.substr(start, end - start + 1);
}

static bool isValidProcessToken(const std::string& str) {
    return std::all_of(str.begin(), str.end(), [](unsigned char c) { return std::isdigit(c); });
}

static DWORD DetectProcessInstance(const std::wstring& searchString) {
    DWORD processes[1024], bytesReturned;

    if (EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
        DWORD numProcesses = bytesReturned / sizeof(DWORD);
        std::wstring searchLower = toLower(searchString);

        for (DWORD i = 0; i < numProcesses; ++i) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
            if (hProcess != NULL) {
                WCHAR processName[MAX_PATH];

                if (GetModuleBaseNameW(hProcess, NULL, processName, sizeof(processName) / sizeof(WCHAR))) {
                    std::wstring wideProcessName(processName);
                    std::wstring processLower = toLower(wideProcessName);

                    if (processLower.find(searchLower) != std::wstring::npos) {
                        CloseHandle(hProcess);
                        return processes[i];
                    }

                }

                CloseHandle(hProcess);
            }
        }
    }
    return 0;
}

int main(int argc, char* argv[]) {
    AdjustTokenPrivilege(GetCurrentProcess());
    BOOL SSE, AVX, AVX512;
    __intr(SSE, AVX, AVX512);

    std::cout << "Made by Requiem" << std::endl;

    std::string __str;
    while (__str.empty()) {
        std::cout << "Enter the string to scan: ";
        std::cin >> __str;
    }

    std::vector<DWORD> pids;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--pid" || arg == "--process" || arg == "-p") {
            if (i + 1 < argc) {
                std::string plist = argv[i + 1];
                plist.erase(std::remove(plist.begin(), plist.end(), ' '), plist.end());
                std::istringstream iss(plist);
                std::string token;
                while (std::getline(iss, token, ',')) {
                    token = __trim(token);
                    if (isValidProcessToken(token)) {
                        try {
                            DWORD pid = std::stoul(token);

                            HANDLE v = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                            if (v == NULL) {
                                std::cerr << "[-] Process does not exist: " << pid << std::endl;
                            }
                            else {
                                CloseHandle(v);
                                pids.push_back(pid);
                            }
                        }
                        catch (const std::exception& e) {
                            std::cerr << "[-] Invalid PID: " << token << " - " << e.what() << std::endl;
                        }
                    }
                    else {
                        DWORD pid = DetectProcessInstance(std::wstring(token.begin(), token.end()));
                        if (pid == 0) {
                            std::cerr << "[-] Process does not exist: " << token << std::endl;
                        }
                        else {
                            pids.push_back(pid);
                        }
                    }
                }
            }
            else {
                std::cerr << "[-] No PID or process names specified after --pid or --process or -p argument." << std::endl;
            }
        }
    }

    if (!pids.empty()) {
        std::cout << "[+] PIDs to be scanned:" << std::endl;
        for (DWORD pid : pids) {
            std::cout << pid << std::endl;
        }
    }
    else {
        std::cerr << "[*] No PIDs specified for scanning with -p parameter. The program will scan all processes" << std::endl;
    }

    std::string input;
    std::cout << "Are you sure you want to continue? (Y/N): ";
    std::getline(std::cin, input);
    std::cin >> input;
    if (input != "Y" && input != "y") {
        std::cerr << "[-] Operation cancelled by user." << std::endl;
        return -1;
    }

    if (pids.empty()) {
        RPM(__str, SSE, AVX, AVX512);
    }
    else {
        RPM(__str, SSE, AVX, AVX512, pids);
    }

    printf("[*] Scan finished\n");
    system("pause");
    return 0;
}