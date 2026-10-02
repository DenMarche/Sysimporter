#include "SysImport.h"
#include <windows.h>

int main() {
    using KiNtWriteVirtualMemory = NTSTATUS (__stdcall *)(HANDLE, PVOID, PVOID, SIZE_T, SIZE_T *);
    using KiNtCreateThreadEx = NTSTATUS (__stdcall *)(HANDLE *, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    
    // Sysimporter automatically resolves the SSNs.
    auto NtWriteVirtualMemory = SysImport::Resolve<KiNtWriteVirtualMemory>("NtWriteVirtualMemory");
    auto NtCreateThreadEx = SysImport::Resolve<KiNtCreateThreadEx>("NtCreateThreadEx");
    
    // You can also use manual tables.
    KiNtWriteVirtualMemory  Wvm = nullptr;
    SysImport::SyscallTable<1> Table;
    SysImport::InitializeTable(Table);
    SysImport::AddEntry(Table, "NtWriteVirtualMemory", reinterpret_cast<void **>(&Wvm), 0);
    SysImport::ResolveTable(Table);
    
    (void)NtWriteVirtualMemory;
    (void)NtCreateThreadEx;
    (void)Wvm;
    return 0;
}
