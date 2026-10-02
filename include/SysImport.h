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

template <typename T>
struct IsFunctionPointer : std::false_type {};

template <typename R, typename... Args>
struct IsFunctionPointer<R (*)(Args...)> : std::true_type {};

template <typename R, typename... Args>
struct IsFunctionPointer<R (*)(Args..., ...)> : std::true_type {};

template <typename T>
inline constexpr bool IsFunctionPointerV = IsFunctionPointer<T>::value;

struct SyscallEntry {
    const char *FunctionName;
    void **FunctionPointer;
    std::uint32_t SyscallNumber;
    bool Resolved;
};

struct SyscallTableHeader {
    SyscallEntry *Entries;
    std::size_t EntryCount;
};

template <std::size_t Count>
struct SyscallTable {
    SyscallEntry Entries[Count];
    std::size_t EntryCount;
    constexpr SyscallTable() : Entries{}, EntryCount(0) {}
};

template <std::size_t Count>
inline void InitializeTable(SyscallTable<Count> &Table) {
    Table.EntryCount = 0;
    for (std::size_t I = 0; I < Count; ++I) {
        Table.Entries[I] = {nullptr, nullptr, 0, false};
    }
}

template <std::size_t Count>
inline void AddEntry(SyscallTable<Count> &Table, const char *Name, void **Ptr, std::uint32_t Number) {
    if (Table.EntryCount < Count) {
        Table.Entries[Table.EntryCount++] = {Name, Ptr, Number, false};
    }
}

bool ResolveTable(SyscallTableHeader *Table) noexcept;

template <std::size_t Count>
inline bool ResolveTable(SyscallTable<Count> &Table) noexcept {
    SyscallTableHeader Header;
    Header.Entries = Table.Entries;
    Header.EntryCount = Table.EntryCount;
    const bool Result = ResolveTable(&Header);
    Table.EntryCount = Header.EntryCount;
    return Result;
}

std::uint32_t GetSyscallNumber(std::string_view FunctionName) noexcept;
bool ResolveAll() noexcept;

class Resolver {
public:
    Resolver();
    ~Resolver() = default;
    bool ResolveAll() noexcept;
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

inline Resolver &GlobalResolver() noexcept {
    static Resolver Instance;
    return Instance;
}

template <typename T>
inline T Resolve(std::string_view Name) noexcept {
    return GlobalResolver().Resolve<T>(Name);
}

} // namespace SysImport
