#pragma once

#include <intrin.h>
#include <memory>
#include <vector>
#include <functional>
#include <string>
#include <iostream>
#include <sstream>
#include <windows.h>
#include <psapi.h>
#include <string_view>
#include <algorithm>
#include <cwchar>
#include <cwctype>

#include "kernel_call.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

BOOL AdjustTokenPrivilege(const HANDLE hproc)
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

std::wstring toLower(const std::wstring& str) {
    std::wstring result = str;
    std::ranges::transform(result, result.begin(), [](wchar_t c) {
        return std::towlower(c);
        });
    return result;
}

std::string __trim(const std::string& str) {
    auto start = std::ranges::find_if(str, [](unsigned char c) { return !std::isspace(c); });
    auto end = std::ranges::find_if(str.rbegin(), str.rend(), [](unsigned char c) { return !std::isspace(c); }).base();
    return std::string(start, end);
}

bool isValidProcessToken(const std::string& str) {
    return std::ranges::all_of(str, [](unsigned char c) { return std::isdigit(c); });
}

inline bool __fastcall GetProcessName(const DWORD processId, std::wstring& processName) {
    HANDLE processHandle;
    OBJECT_ATTRIBUTES objAttr{};
    CLIENT_ID clientId{};

    clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId));
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

    NTSTATUS status = SysNtOpenProcess(&processHandle, PROCESS_QUERY_INFORMATION, &objAttr, &clientId);
    if (!NT_SUCCESS(status)) {
        return false;
    }

    BYTE buffer[sizeof(UNICODE_STRING) + MAX_PATH * sizeof(WCHAR)] = { 0 };
    PUNICODE_STRING pImageName = reinterpret_cast<PUNICODE_STRING>(buffer);
    pImageName->MaximumLength = MAX_PATH * sizeof(WCHAR);
    pImageName->Buffer = reinterpret_cast<PWSTR>(pImageName + 1);

    status = SysNtQueryInformationProcess(processHandle, ProcessImageFileName, pImageName, sizeof(buffer), nullptr);
    if (NT_SUCCESS(status)) {
        std::wstring fullPath(pImageName->Buffer, pImageName->Length / sizeof(WCHAR));
        size_t pos = fullPath.find_last_of(L'\\');
        processName = (pos != std::wstring::npos) ? fullPath.substr(pos + 1) : fullPath;
    }

    SysNtClose(processHandle);
    return NT_SUCCESS(status);
}

DWORD DetectProcessInstance(const std::wstring& searchString) {
    DWORD processes[1024], bytesReturned;

    if (K32EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
        DWORD numProcesses = bytesReturned / sizeof(DWORD);
        std::wstring searchLower = toLower(searchString);

        for (DWORD i = 0; i < numProcesses; ++i) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
            if (hProcess != NULL) {
                WCHAR processName[MAX_PATH];

                if (K32GetModuleBaseNameW(hProcess, NULL, processName, sizeof(processName) / sizeof(WCHAR))) {
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

inline void adjustTokenPrivilege() {
    AdjustTokenPrivilege(GetCurrentProcess());
}

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            std::cerr << "Error checking token membership: " << GetLastError() << "\n";
        }
        FreeSid(adminGroup);
    }
    else {
        std::cerr << "Error allocating SID: " << GetLastError() << "\n";
    }

    return isAdmin == TRUE;
}

std::wstring getMemoryString() {
    std::wstring memoryString;
    while (memoryString.empty()) {
        std::wcout << "Enter the memory string (ASCII, Unicode or Extended Unicode) to scan. Empty characters are scanned too: \n";
        std::wcin >> memoryString;
    }
    return memoryString;
}

std::vector<DWORD> parseProcessArguments(int argc, char* argv[]) {
    std::vector<DWORD> pids;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--pid" || arg == "-pid" || arg == "-process" || arg == "--process" || arg == "-p" || arg == "--p") {
            if (i + 1 < argc) {
                std::string plist = argv[i + 1];
                plist.erase(std::remove(plist.begin(), plist.end(), ' '), plist.end());
                std::istringstream iss(plist);
                std::string token;
                while (std::getline(iss, token, ',')) {
                    token = __trim(token);  // Assuming __trim is a valid function
                    if (isValidProcessToken(token)) {
                        try {
                            const DWORD pid = std::stoul(token);
                            HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                            if (processHandle == NULL) {
                                std::cerr << "[-] Process does not exist: " << pid << "\n";
                            }
                            else {
                                CloseHandle(processHandle);
                                pids.push_back(pid);
                            }
                        }
                        catch (const std::exception& e) {
                            std::cerr << "[-] Invalid PID: " << token << " - " << e.what() << "\n";
                        }
                    }
                    else {
                        const DWORD pid = DetectProcessInstance(std::wstring(token.begin(), token.end()));
                        if (pid == 0) {
                            std::cerr << "[-] Process does not exist: " << token << "\n";
                        }
                        else {
                            pids.push_back(pid);
                        }
                    }
                }
            }
        }
    }
    return pids;
}

void printPIDs(const std::vector<DWORD>& pids) {
    if (!pids.empty()) {
        std::cout << "[+] PIDs to be scanned:\n";
        for (DWORD pid : pids) {
            std::cout << "- " << pid << "\n";
        }
    }
    else {
        std::cerr << "No PID or process names specified with -p/--p, -pid/--pid, or -process/--process parameter.\n";
    }
}

bool confirmOperation() {
    std::string input;
    std::cout << "Are you sure you want to continue? (Y/N): ";
    std::getline(std::cin, input);
    std::cin >> input;
    return (input == "Y" || input == "y" || input == "yes" || input == "YES");
}
