/// Dynamic definitions for psapi.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.windows.psapi_dyn;

version (Windows):

version (ANSI) {} else version = Unicode;

import core.sys.windows.windef;
public import core.sys.windows.psapi;

import adbg.object.symbols;

extern (Windows):

private {
    alias pEnumProcesses = BOOL function(DWORD*, DWORD, DWORD*);
    alias pGetProcessImageFileNameA = DWORD function(HANDLE, LPSTR, DWORD);
    alias pGetProcessImageFileNameW = DWORD function(HANDLE, LPWSTR, DWORD);
    alias pEnumProcessModules = BOOL function(HANDLE, HMODULE*, DWORD, LPDWORD);
    alias pEnumProcessModulesEx = BOOL function(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
    alias pGetModuleBaseNameA = DWORD function(HANDLE, HMODULE, LPSTR, DWORD);
    alias pGetModuleBaseNameW = DWORD function(HANDLE, HMODULE, LPWSTR, DWORD);
    alias pGetModuleFileNameExA = DWORD function(HANDLE, HMODULE, LPSTR, DWORD);
    alias pGetModuleFileNameExW = DWORD function(HANDLE, HMODULE, LPWSTR, DWORD);
    alias pGetModuleInformation = BOOL function(HANDLE, HMODULE, LPMODULEINFO, DWORD);
    alias pEnumDeviceDrivers = BOOL function(LPVOID*, DWORD, LPDWORD);
    alias pGetDeviceDriverBaseNameA = DWORD function(LPVOID, LPSTR, DWORD);
    alias pGetDeviceDriverBaseNameW = DWORD function(LPVOID, LPWSTR, DWORD);
    alias pGetDeviceDriverFileNameA = DWORD function(LPVOID, LPSTR, DWORD);
    alias pGetDeviceDriverFileNameW = DWORD function(LPVOID, LPWSTR, DWORD);
    alias pGetProcessMemoryInfo = BOOL function(HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD);
    alias pEmptyWorkingSet = BOOL function(HANDLE);
    alias pGetWsChanges = BOOL function(HANDLE, PPSAPI_WS_WATCH_INFORMATION, DWORD);
    alias pGetWsChangesEx = BOOL function(HANDLE, PPSAPI_WS_WATCH_INFORMATION_EX, DWORD);
    alias pInitializeProcessForWsWatch = BOOL function(HANDLE);
    alias pQueryWorkingSet = BOOL function(HANDLE, PVOID, DWORD);
    alias pQueryWorkingSetEx = BOOL function(HANDLE, PVOID, DWORD);
    alias pGetMappedFileNameW = DWORD function(HANDLE, LPVOID, LPWSTR, DWORD);
    alias pGetMappedFileNameA = DWORD function(HANDLE, LPVOID, LPSTR, DWORD);
    alias pGetPerformanceInfo = BOOL function(PPERFORMANCE_INFORMATION, DWORD);
    alias pEnumPageFilesW = BOOL function(PENUM_PAGE_FILE_CALLBACKW, LPVOID);
    alias pEnumPageFilesA = BOOL function(PENUM_PAGE_FILE_CALLBACKA, LPVOID);
}

version (ANSI) {
    alias GetProcessImageFileName = GetProcessImageFileNameA;
    alias GetModuleBaseName = GetModuleBaseNameA;
    alias GetModuleFileNameEx = GetModuleFileNameExA;
    alias GetDeviceDriverBaseName = GetDeviceDriverBaseNameA;
    alias GetDeviceDriverFileName = GetDeviceDriverFileNameA;
    alias GetMappedFileName = GetMappedFileNameA;
    alias EnumPageFiles = EnumPageFilesA;
} else {
    alias GetProcessImageFileName = GetProcessImageFileNameW;
    alias GetModuleBaseName = GetModuleBaseNameW;
    alias GetModuleFileNameEx = GetModuleFileNameExW;
    alias GetDeviceDriverBaseName = GetDeviceDriverBaseNameW;
    alias GetDeviceDriverFileName = GetDeviceDriverFileNameW;
    alias GetMappedFileName = GetMappedFileNameW;
    alias EnumPageFiles = EnumPageFilesW;
}

__gshared
{
    pEnumProcesses EnumProcesses;
    pGetProcessImageFileNameA GetProcessImageFileNameA;
    pGetProcessImageFileNameW GetProcessImageFileNameW;
    pEnumProcessModules EnumProcessModules;
    pEnumProcessModulesEx EnumProcessModulesEx;
    pGetModuleBaseNameA GetModuleBaseNameA;
    pGetModuleBaseNameW GetModuleBaseNameW;
    pGetModuleFileNameExA GetModuleFileNameExA;
    pGetModuleFileNameExW GetModuleFileNameExW;
    pGetModuleInformation GetModuleInformation;
    pEnumDeviceDrivers EnumDeviceDrivers;
    pGetDeviceDriverBaseNameA GetDeviceDriverBaseNameA;
    pGetDeviceDriverBaseNameW GetDeviceDriverBaseNameW;
    pGetDeviceDriverFileNameA GetDeviceDriverFileNameA;
    pGetDeviceDriverFileNameW GetDeviceDriverFileNameW;
    pGetProcessMemoryInfo GetProcessMemoryInfo;
    pEmptyWorkingSet EmptyWorkingSet;
    pGetWsChanges GetWsChanges;
    pGetWsChangesEx GetWsChangesEx;
    pInitializeProcessForWsWatch InitializeProcessForWsWatch;
    pQueryWorkingSet QueryWorkingSet;
    pQueryWorkingSetEx QueryWorkingSetEx;
    pGetMappedFileNameW GetMappedFileNameW;
    pGetMappedFileNameA GetMappedFileNameA;
    pGetPerformanceInfo GetPerformanceInfo;
    pEnumPageFilesW EnumPageFilesW;
    pEnumPageFilesA EnumPageFilesA;
}

union PSAPI_WORKING_SET_BLOCK {
/*  ULONG_PTR Protection : 5;
    ULONG_PTR ShareCount : 3;
    ULONG_PTR Shared : 1;
    ULONG_PTR Node : 3;
#ifdef _WIN64
    ULONG_PTR VirtualPage : 52;
#else
    ULONG Virtual : 20;*/
    ULONG_PTR VirtualPage;
}

struct PSAPI_WORKING_SET_INFORMATION {
  ULONG_PTR               NumberOfEntries;
  PSAPI_WORKING_SET_BLOCK[1] WorkingSetInfo;
}

union PSAPI_WORKING_SET_EX_BLOCK
{
    ULONG_PTR Flags;
    /*union {
        struct {
            ULONG_PTR Valid : 1;
            ULONG_PTR ShareCount : 3;
            ULONG_PTR Win32Protection : 11;
            ULONG_PTR Shared : 1;
            ULONG_PTR Node : 6;
            ULONG_PTR Locked : 1;
            ULONG_PTR LargePage : 1;
            ULONG_PTR Reserved : 7;
            ULONG_PTR Bad : 1;
            Win64: ULONG_PTR ReservedUlong : 32;
        }
        struct {
            ULONG_PTR Valid : 1;
            ULONG_PTR Reserved0 : 14;
            ULONG_PTR Shared : 1;
            ULONG_PTR Reserved1 : 15;
            ULONG_PTR Bad : 1;
            Win64: ULONG_PTR ReservedUlong : 32;
        } Invalid;
    }*/
}

struct PSAPI_WORKING_SET_EX_INFORMATION
{
    PVOID VirtualAddress;
    PSAPI_WORKING_SET_EX_BLOCK VirtualAttributes;
}

struct MEMORY_BASIC_INFORMATION32 {
    DWORD BaseAddress;
    DWORD AllocationBase;
    DWORD AllocationProtect;
    DWORD RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
}

align(16) struct MEMORY_BASIC_INFORMATION64 {
    ULONGLONG BaseAddress;
    ULONGLONG AllocationBase;
    DWORD     AllocationProtect;
    DWORD     __alignment1;
    ULONGLONG RegionSize;
    DWORD     State;
    DWORD     Protect;
    DWORD     Type;
    DWORD     __alignment2;
}

private __gshared bool __dynlib_psapi_loaded;

version (Trace) import adbg.error;

// Returns true on error.
bool __dynlib_psapi_load()
{
    if (__dynlib_psapi_loaded)
        return false;
    
    adbg_shared_lib_t *lib = adbg_symbols_load("psapi.dll");
    if (lib == null)
        return true;
    
    adbg_symbols_bind(lib, cast(void**)&EnumProcesses, "EnumProcesses");
    adbg_symbols_bind(lib, cast(void**)&GetProcessImageFileNameA, "GetProcessImageFileNameA");
    adbg_symbols_bind(lib, cast(void**)&GetProcessImageFileNameW, "GetProcessImageFileNameW");
    adbg_symbols_bind(lib, cast(void**)&EnumProcessModules, "EnumProcessModules");
    adbg_symbols_bind(lib, cast(void**)&EnumProcessModulesEx, "EnumProcessModulesEx");
    adbg_symbols_bind(lib, cast(void**)&GetModuleBaseNameA, "GetModuleBaseNameA");
    adbg_symbols_bind(lib, cast(void**)&GetModuleBaseNameW, "GetModuleBaseNameW");
    adbg_symbols_bind(lib, cast(void**)&GetModuleFileNameExA, "GetModuleFileNameExA");
    adbg_symbols_bind(lib, cast(void**)&GetModuleFileNameExW, "GetModuleFileNameExW");
    adbg_symbols_bind(lib, cast(void**)&GetModuleInformation, "GetModuleInformation");
    adbg_symbols_bind(lib, cast(void**)&EnumDeviceDrivers, "EnumDeviceDrivers");
    adbg_symbols_bind(lib, cast(void**)&GetDeviceDriverBaseNameA, "GetDeviceDriverBaseNameA");
    adbg_symbols_bind(lib, cast(void**)&GetDeviceDriverBaseNameW, "GetDeviceDriverBaseNameW");
    adbg_symbols_bind(lib, cast(void**)&GetDeviceDriverFileNameA, "GetDeviceDriverFileNameA");
    adbg_symbols_bind(lib, cast(void**)&GetDeviceDriverFileNameW, "GetDeviceDriverFileNameW");
    adbg_symbols_bind(lib, cast(void**)&GetProcessMemoryInfo, "GetProcessMemoryInfo");
    adbg_symbols_bind(lib, cast(void**)&EmptyWorkingSet, "EmptyWorkingSet");
    adbg_symbols_bind(lib, cast(void**)&GetWsChanges, "GetWsChanges");
    adbg_symbols_bind(lib, cast(void**)&GetWsChangesEx, "GetWsChangesEx");
    adbg_symbols_bind(lib, cast(void**)&InitializeProcessForWsWatch, "InitializeProcessForWsWatch");
    adbg_symbols_bind(lib, cast(void**)&QueryWorkingSet, "QueryWorkingSet");
    adbg_symbols_bind(lib, cast(void**)&QueryWorkingSetEx, "QueryWorkingSetEx");
    adbg_symbols_bind(lib, cast(void**)&GetMappedFileNameW, "GetMappedFileNameW");
    adbg_symbols_bind(lib, cast(void**)&GetMappedFileNameA, "GetMappedFileNameA");
    adbg_symbols_bind(lib, cast(void**)&GetPerformanceInfo, "GetPerformanceInfo");
    adbg_symbols_bind(lib, cast(void**)&EnumPageFilesW, "EnumPageFilesW");
    adbg_symbols_bind(lib, cast(void**)&EnumPageFilesA, "EnumPageFilesA");
    
    size_t missingcnt = adbg_symbols_missingcnt(lib);
    if (missingcnt)
    {
        version (Trace)
        {
            for (size_t i; i < missingcnt; ++i)
            {
                trace("missing symbol: %s", adbg_symbols_missing(lib, i));
            }
        }
        adbg_symbols_close(lib);
        return true;
    }
    
    __dynlib_psapi_loaded = true;
    
    version (Trace)
    {
        trace("psapi.dll loaded");
    }
    
    return false;
}
