//
// By lucef
// 9/4/2026
// Licensed under the MIT license
//

#include "SysImport.h"
#include <windows.h>
#include <algorithm>
#include <functional>
#include <string>
#include <vector>
#include <cctype>
#include <intrin.h>

namespace SysImport {
namespace {

//
// Named export from a PE module.
// Address is the resolved VA.
//

struct ExportEntry {
    std::string Name;
    void *Address;
};

//
// ASCII lowercase, since we have nothing better to do.
// WinAPI names are case-insensitive.
//

inline std::string ToLowerCopy(std::string_view View) {
    std::string Out(View);
    for (char &C : Out) {
        if (C >= 'A' && C <= 'Z') C = static_cast<char>(C - 'A' + 'a');
    }
    return Out;
}

//
// Detects inline hooks on a stub, since i know you guys will use this on protected games.
// E9/EB = rel jmp, FF = indirect jmp/call, 48 B8 = mov rax, imm64.
// Any hit means the SSN at +4 is hooked / tampered with, thus untrustworthy.
//

inline bool IsHooked(const void *Addr) noexcept {
    if (!Addr) return true;
    const unsigned char *Bytes = static_cast<const unsigned char *>(Addr);
    if (Bytes[0] == 0xE9 || Bytes[0] == 0xEB || Bytes[0] == 0xFF) return true;
    if (Bytes[0] == 0x48 && Bytes[1] == 0xB8) return true;
    return false;
}

//
// A stub prologue usually looks like this:
//   mov r10, rcx    ; 4C 8B D1
//   mov eax, imm32  ; B8 xx xx xx xx  <- SSN
// So it's pretty easy to just pattern scan each function like so.
//

inline bool IsSyscallPrologue(const void *Addr) noexcept {
    if (!Addr) return false;
    const unsigned char *B = static_cast<const unsigned char *>(Addr);
    if (B[0] == 0x4C && B[1] == 0x8B && B[2] == 0xD1 && B[3] == 0xB8) return true;
    return false;
}

//
// Walks ntdll's PE export directory. DOS -> NT -> export dir -> Name / Function / Order arrays.
// Returns empty on any parse failure.
//

std::vector<ExportEntry> GetNtdllExports() {
    std::vector<ExportEntry> Exports;
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!Ntdll) Ntdll = LoadLibraryW(L"ntdll.dll");
    if (!Ntdll) return Exports;

    const unsigned char *Base = reinterpret_cast<const unsigned char *>(Ntdll);
    const IMAGE_DOS_HEADER *Dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(Base);
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) return Exports;

    const IMAGE_NT_HEADERS *Nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(Base + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE) return Exports;

    const IMAGE_DATA_DIRECTORY *ExpDir = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ExpDir->VirtualAddress == 0 || ExpDir->Size == 0) return Exports;

    const IMAGE_EXPORT_DIRECTORY *Ed = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(Base + ExpDir->VirtualAddress);
    const DWORD *Names = reinterpret_cast<const DWORD *>(Base + Ed->AddressOfNames);
    const DWORD *Funcs = reinterpret_cast<const DWORD *>(Base + Ed->AddressOfFunctions);
    const WORD *Ords = reinterpret_cast<const WORD *>(Base + Ed->AddressOfNameOrdinals);

    Exports.reserve(Ed->NumberOfNames);
    for (DWORD I = 0; I < Ed->NumberOfNames; ++I) {
        const char *Name = reinterpret_cast<const char *>(Base + Names[I]);
        const void *Addr = reinterpret_cast<const void *>(Base + Funcs[Ords[I]]);
        if (Name && Addr) {
            Exports.push_back({Name, const_cast<void *>(Addr)});
        }
    }
    return Exports;
}

//
// Resolved syscall consists of: Name, VA, and SSN, which we professionally read from +4.
//

struct SyscallCandidate {
    std::string Name;
    void *Address;
    std::uint32_t Number;
};

//
// Filters ntdll exports to valid, unhooked syscall stubs.
//

std::vector<SyscallCandidate> BuildSyscallMap() {
    std::vector<SyscallCandidate> Map;
    const auto Exports = GetNtdllExports();
    Map.clear();
    Map.reserve(Exports.size());
    for (const auto &E : Exports) {
        if (!E.Name.empty() && (E.Name[0] == 'N' || E.Name[0] == 'Z')) {
            if (IsSyscallPrologue(E.Address) && !IsHooked(E.Address)) {
                const unsigned char *B = static_cast<const unsigned char *>(E.Address);
                const std::uint32_t Num = *reinterpret_cast<const std::uint32_t *>(B + 4);
                Map.push_back({E.Name, E.Address, Num});
            }
        }
    }
    return Map;
}

} // namespace

//
// Pretty, thread safe, and statically initializes on first call. What else is there to dream of?
//

static std::vector<SyscallCandidate> &GetGlobalMap() {
    static std::vector<SyscallCandidate> Map = BuildSyscallMap();
    return Map;
}

//
// Linear lookup; Returns 0 if not found.
//

std::uint32_t GetSyscallNumber(std::string_view FunctionName) noexcept {
    const std::string Key = ToLowerCopy(FunctionName);
    const auto &Map = GetGlobalMap();
    for (const auto &C : Map) {
        if (ToLowerCopy(C.Name) == Key) return C.Number;
    }
    return 0;
}

//
// Resolves every entry in the caller's table against the global map.
// Returns false if any entry could not be resolved.
//

bool ResolveTable(SyscallTableHeader *Table) noexcept {
    if (!Table || Table->EntryCount == 0) return false;
    const auto &Map = GetGlobalMap();
    bool All = true;
    for (std::size_t I = 0; I < Table->EntryCount; ++I) {
        SyscallEntry &E = Table->Entries[I];
        if (!E.FunctionPointer) {
            All = false;
            continue;
        }
        const std::string Key = E.FunctionName ? ToLowerCopy(E.FunctionName) : std::string();
        bool Found = false;
        for (const auto &C : Map) {
            if (ToLowerCopy(C.Name) == Key) {
                *E.FunctionPointer = C.Address;
                E.SyscallNumber = C.Number;
                E.Resolved = true;
                Found = true;
                break;
            }
        }
        if (!Found) All = false;
    }
    return All;
}

//
// Forces map build. Returns true if the map is non-empty.
//

bool ResolveAll() noexcept {
    (void)GetGlobalMap();
    return !GetGlobalMap().empty();
}

//
// Populates the per-instance lookup.
//

Resolver::Resolver() : Initialized(false) {
    FunctionMap.clear();
    ResolveAll();
    const auto &Map = GetGlobalMap();
    for (const auto &C : Map) {
        FunctionMap[C.Name] = C.Address;
        const std::string Lower = ToLowerCopy(C.Name);
        if (Lower != C.Name) FunctionMap[Lower] = C.Address;
    }
    Initialized = !FunctionMap.empty();
}

//
// Rebuilds the instance map from the global map.
//

bool Resolver::ResolveAll() noexcept {
    const auto &Map = GetGlobalMap();
    FunctionMap.clear();
    for (const auto &C : Map) {
        FunctionMap[C.Name] = C.Address;
        FunctionMap[ToLowerCopy(C.Name)] = C.Address;
    }
    Initialized = !FunctionMap.empty();
    return Initialized;
}

} // namespace SysImport
