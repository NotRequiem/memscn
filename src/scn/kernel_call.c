#include "kernel_call.h"
#include <stdio.h>

Requiem_SYSCALL_LIST Requiem_SyscallList;

DWORD Requiem_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = Requiem_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + Requiem_ROR8(Hash);
    }

    return Hash;
}

PVOID SC_Address(PVOID NtApiAddress)
{
    return NULL;
}

BOOL Requiem_PopulateSyscallList()
{
    if (Requiem_SyscallList.Count) return TRUE;

#ifdef _WIN64
    PRequiem_PEB Peb = (PRequiem_PEB)__readgsqword(0x60);
#else
    PRequiem_PEB Peb = (PRequiem_PEB)__readfsdword(0x30);
#endif
    PRequiem_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    PRequiem_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PRequiem_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PRequiem_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = Requiem_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)Requiem_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        PCHAR DllName = Requiem_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = Requiem_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = Requiem_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = Requiem_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    DWORD i = 0;
    PRequiem_SYSCALL_ENTRY Entries = Requiem_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = Requiem_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = Requiem_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            Entries[i].SyscallAddress = SC_Address(Requiem_RVA2VA(PVOID, DllBase, Entries[i].Address));

            i++;
            if (i == Requiem_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    Requiem_SyscallList.Count = i;

    for (DWORD i = 0; i < Requiem_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < Requiem_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                Requiem_SYSCALL_ENTRY TempEntry = { 0 };

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

EXTERN_C DWORD Requiem_GetSyscallNumber(DWORD FunctionHash)
{
    if (!Requiem_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < Requiem_SyscallList.Count; i++)
    {
        if (FunctionHash == Requiem_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

EXTERN_C PVOID Requiem_GetSyscallAddress(DWORD FunctionHash)
{
    if (!Requiem_PopulateSyscallList()) return NULL;

    for (DWORD i = 0; i < Requiem_SyscallList.Count; i++)
    {
        if (FunctionHash == Requiem_SyscallList.Entries[i].Hash)
        {
            return Requiem_SyscallList.Entries[i].SyscallAddress;
        }
    }

    return NULL;
}
