//
// By lucef
// 9/4/26
// Licensed under the MIT license
//

#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <type_traits>

namespace SysImport {

//
// Keeps Resolve<T>() honest, so only function pointer types get through.
// Both the plain and varargs flavors are matched since we can't know
// which calling convention your typedef is using.
//

template <typename T>
struct IsFunctionPointer : std::false_type {};

template <typename R, typename... Args>
struct IsFunctionPointer<R (*)(Args...)> : std::true_type {};

template <typename R, typename... Args>
struct IsFunctionPointer<R (*)(Args..., ...)> : std::true_type {};

template <typename T>
inline constexpr bool IsFunctionPointerV = IsFunctionPointer<T>::value;

//
// One slot of a caller-built table. FunctionPointer is the & of a
// function pointer you own; ResolveTable writes through it and
// fills in the SSN.
//

struct SyscallEntry {
    const char *FunctionName;
    void **FunctionPointer;
    std::uint32_t SyscallNumber;
    bool Resolved;
};

//
// Header view over a SyscallTable<Count>, so the non-template
// ResolveTable() can operate on any table size without knowing Count.
//

struct SyscallTableHeader {
    SyscallEntry *Entries;
    std::size_t EntryCount;
};

//
// Fixed-size, caller-owned. Zero-initialized.
//

template <std::size_t Count>
struct SyscallTable {
    SyscallEntry Entries[Count];
    std::size_t EntryCount;
    constexpr SyscallTable() : Entries{}, EntryCount(0) {}
};

//
// Wipes the table back to empty. Doesn't touch your function pointers.
//

template <std::size_t Count>
inline void InitializeTable(SyscallTable<Count> &Table) {
    Table.EntryCount = 0;
    for (std::size_t I = 0; I < Count; ++I) {
        Table.Entries[I] = {nullptr, nullptr, 0, false};
    }
}

//
// Appends an entry if there's room. Silently drops overflow.
// Number is a placeholder, since ResolveTable overwrites it with the real SSN.
//

template <std::size_t Count>
inline void AddEntry(SyscallTable<Count> &Table, const char *Name, void **Ptr, std::uint32_t Number) {
    if (Table.EntryCount < Count) {
        Table.Entries[Table.EntryCount++] = {Name, Ptr, Number, false};
    }
}

//
// Non-template. Runs against the global map built from ntdll's exports.
//

bool ResolveTable(SyscallTableHeader *Table) noexcept;

//
// Convenience wrapper. Wraps the table in a header view and forwards
// to the non-template overload.
//

template <std::size_t Count>
inline bool ResolveTable(SyscallTable<Count> &Table) noexcept {
    SyscallTableHeader Header;
    Header.Entries = Table.Entries;
    Header.EntryCount = Table.EntryCount;
    const bool Result = ResolveTable(&Header);
    Table.EntryCount = Header.EntryCount;
    return Result;
}

//
// Direct SSN lookup by name. Returns 0 if not found.
//

std::uint32_t GetSyscallNumber(std::string_view FunctionName) noexcept;

//
// Forces the global map to build. True if it's non-empty.
//

bool ResolveAll() noexcept;

//
// Instance resolver. Holds its own name -> address map.
//

class Resolver {
public:
    Resolver();
    ~Resolver() = default;
    bool ResolveAll() noexcept;

    //
    // Typed lookup. Returns nullptr if the name isn't in the map.
    // T must be a function pointer; enforced at compile time.
    //

    template <typename T>
    T Resolve(std::string_view Name) const noexcept {
        static_assert(IsFunctionPointerV<T>, "T must be a function pointer type");
        const auto It = FunctionMap.find(std::string(Name));
        if (It == FunctionMap.end()) return nullptr;
        return reinterpret_cast<T>(It->second);
    }
private:
    std::unordered_map<std::string, void *> FunctionMap;
    bool Initialized;
};

//
// Process-wide resolver, lazily constructed on first use.
// Thread safety by C++11 magic statics.
//

inline Resolver &GlobalResolver() noexcept {
    static Resolver Instance;
    return Instance;
}

//
// Free-function shortcut for GlobalResolver().Resolve<T>().
//

template <typename T>
inline T Resolve(std::string_view Name) noexcept {
    return GlobalResolver().Resolve<T>(Name);
}

} // namespace SysImport
