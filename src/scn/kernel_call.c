#include "kernel_call.h"

Sys_SYSCALL_LIST Sys_SyscallList;

static DWORD Sys_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = 0x28C5192F;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + (Hash >> 8 | Hash << 24);
    }

    return Hash;
}

static PVOID SC_Address(PVOID NtApiAddress)
{
    (NtApiAddress);
    return ((void*)0);
}

static BOOL Sys_PopulateSyscallList()
{
    if (Sys_SyscallList.Count) return 1;

#ifdef _WIN64
    PSys_PEB Peb = (PSys_PEB)__readgsqword(0x60);
#else
    PSys_PEB Peb = (PSys_PEB)__readfsdword(0x30);
#endif
    PSys_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = ((void*)0);
    PVOID DllBase = ((void*)0);

    PSys_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSys_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != ((void*)0); LdrEntry = (PSys_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)DllBase + DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[0].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ULONG_PTR)((ULONG_PTR)DllBase + VirtualAddress);

        PCHAR DllName = (PCHAR)((ULONG_PTR)DllBase + ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }

    if (!ExportDirectory) return 0;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = (PDWORD)((ULONG_PTR)DllBase + ExportDirectory->AddressOfFunctions);
    PDWORD Names = (PDWORD)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNames);
    PWORD Ordinals = (PWORD)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNameOrdinals);

    DWORD i = 0;
    PSys_SYSCALL_ENTRY Entries = Sys_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = (PCHAR)((ULONG_PTR)DllBase + Names[NumberOfNames - 1]);

        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = Sys_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            Entries[i].SyscallAddress = SC_Address((PVOID)((ULONG_PTR)DllBase + Entries[i].Address));

            i++;
            if (i == 600) break;
        }
    } while (--NumberOfNames);

    Sys_SyscallList.Count = i;

    for (i = 0; i < Sys_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < Sys_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                Sys_SYSCALL_ENTRY TempEntry = { 0 };

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;
                TempEntry.SyscallAddress = Entries[j].SyscallAddress;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;
                Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
                Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
            }
        }
    }

    return TRUE;
}

extern DWORD Sys_GetSyscallNumber(DWORD FunctionHash)
{
    if (!Sys_PopulateSyscallList()) return 1;

    for (DWORD i = 0; i < Sys_SyscallList.Count; i++)
    {
        if (FunctionHash == Sys_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return 1;
}

extern PVOID Sys_GetSyscallAddress(DWORD FunctionHash)
{
    if (!Sys_PopulateSyscallList()) return ((void*)0);

    for (DWORD i = 0; i < Sys_SyscallList.Count; i++)
    {
        if (FunctionHash == Sys_SyscallList.Entries[i].Hash)
        {
            return Sys_SyscallList.Entries[i].SyscallAddress;
        }
    }

    return ((void*)0);
}
