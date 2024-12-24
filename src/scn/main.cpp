#include "util.hpp"
#include "kernel_call.h"

inline static void __fastcall rpm(const std::wstring_view& wstr, const std::vector<DWORD>& pids = std::vector<DWORD>()) {
    DWORD p[1024];
    DWORD n, j;

    if (pids.empty()) {
        K32EnumProcesses(p, sizeof(p), &n);
        j = n / sizeof(DWORD);
    }
    else {
        j = static_cast<DWORD>(pids.size());
        std::copy(pids.begin(), pids.end(), p);
    }

    const DWORD currentProcessId = GetCurrentProcessId();
    const HANDLE currentProcess = GetCurrentProcess();

    for (DWORD i = 0; i < j; i++) {
        DWORD targetProcessId = p[i];
        if (targetProcessId == 0 || targetProcessId == 4 || targetProcessId == currentProcessId)
            continue;

        NTSTATUS status;
        OBJECT_ATTRIBUTES objAttr{};
        CLIENT_ID clientId{};
        HANDLE processHandle;

        RtlSecureZeroMemory(&objAttr, sizeof(OBJECT_ATTRIBUTES));
        objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
        RtlSecureZeroMemory(&clientId, sizeof(CLIENT_ID));
        clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(targetProcessId));

        status = SysNtOpenProcess(&processHandle, (0x0400) | (0x0010), &objAttr, &clientId);
        if (!NT_SUCCESS(status))
            continue;

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        MEMORY_BASIC_INFORMATION memoryInfo{};
        bool found = false;

        for (LPVOID addr = sysInfo.lpMinimumApplicationAddress; addr < sysInfo.lpMaximumApplicationAddress;
            addr = static_cast<LPBYTE>(memoryInfo.BaseAddress) + memoryInfo.RegionSize) {

            PVOID baseAddress = addr;
            SIZE_T regionSize = sizeof(memoryInfo);
            SIZE_T returnLength;

            status = SysNtQueryVirtualMemory(processHandle, baseAddress, MemoryBasicInformation, &memoryInfo, regionSize, &returnLength);
            if (!NT_SUCCESS(status) || memoryInfo.State != MEM_COMMIT || memoryInfo.Protect & PAGE_NOACCESS)
                continue;           

            SIZE_T allocationSize = memoryInfo.RegionSize + wstr.size() * sizeof(wchar_t) - 1; // Extra space for overlap
            PVOID buffer = nullptr;
            status = SysNtAllocateVirtualMemory(currentProcess, &buffer, 0, &allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!NT_SUCCESS(status))
                continue;

            SIZE_T bytesRead = 0;
            status = SysNtReadVirtualMemory(processHandle, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead);
            if (NT_SUCCESS(status)) {
                const wchar_t* dataPtr = reinterpret_cast<const wchar_t*>(buffer);
                size_t wordCount = bytesRead / sizeof(wchar_t);

                if (std::wstring_view(dataPtr, wordCount).find(wstr) != std::wstring_view::npos) {
                    found = true;

                    std::wstring processName;
                    if (GetProcessName(targetProcessId, processName)) {
                        wprintf(L"String found in process ID: %lu (%s)\n", targetProcessId, processName.c_str());
                    }
                    break;
                }
            }

            SysNtFreeVirtualMemory(currentProcess, &buffer, &allocationSize, MEM_RELEASE);
            if (found) break;
        }

        SysNtClose(processHandle);
    }
}

auto main(int argc, char* argv[]) -> __int32 {
    if (!IsRunningAsAdmin())
        std::cout << "[!] The program is not running as an administrator. It may not be able to scan some processes.\n";   

    adjustTokenPrivilege();

    std::wstring memoryString = getMemoryString();
    std::vector<DWORD> pids = parseProcessArguments(argc, argv);

    printPIDs(pids);

    if (!confirmOperation()) {
        std::cerr << "[-] Operation cancelled.\n";
        return 1;
    }

    std::wstring_view wstr(memoryString.begin(), memoryString.end());
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    if (pids.empty()) {
        rpm(wstr);
    }
    else {
        rpm(wstr, pids);
    }

    QueryPerformanceCounter(&end);
    double elapsedTime = static_cast<double>(end.QuadPart - start.QuadPart) / frequency.QuadPart;
    std::cout << "[+] Scan completed in " << elapsedTime << " seconds.\n";

    system("pause");
    return 0;
}