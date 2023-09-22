/// Dynamic definitions for psapi.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.include.windows.psapi_dyn;

version (Windows):

version (ANSI) {} else version = Unicode;

import core.sys.windows.windef;
public import core.sys.windows.psapi;

import bindbc.loader;
import bindbc.loader.sharedlib;

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

__gshared {
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

private __gshared bool __dynlib_psapi_loaded;

bool __dynlib_psapi_load() {
    if (__dynlib_psapi_loaded)
        return false;
    
    SharedLib lib = load("psapi.dll");
    if (lib == invalidHandle)
        return true;
    
    bindSymbol(lib, cast(void**)&EnumProcesses, "EnumProcesses");
    bindSymbol(lib, cast(void**)&GetProcessImageFileNameA, "GetProcessImageFileNameA");
    bindSymbol(lib, cast(void**)&GetProcessImageFileNameW, "GetProcessImageFileNameW");
    bindSymbol(lib, cast(void**)&EnumProcessModules, "EnumProcessModules");
    bindSymbol(lib, cast(void**)&EnumProcessModulesEx, "EnumProcessModulesEx");
    bindSymbol(lib, cast(void**)&GetModuleBaseNameA, "GetModuleBaseNameA");
    bindSymbol(lib, cast(void**)&GetModuleBaseNameW, "GetModuleBaseNameW");
    bindSymbol(lib, cast(void**)&GetModuleFileNameExA, "GetModuleFileNameExA");
    bindSymbol(lib, cast(void**)&GetModuleFileNameExW, "GetModuleFileNameExW");
    bindSymbol(lib, cast(void**)&GetModuleInformation, "GetModuleInformation");
    bindSymbol(lib, cast(void**)&EnumDeviceDrivers, "EnumDeviceDrivers");
    bindSymbol(lib, cast(void**)&GetDeviceDriverBaseNameA, "GetDeviceDriverBaseNameA");
    bindSymbol(lib, cast(void**)&GetDeviceDriverBaseNameW, "GetDeviceDriverBaseNameW");
    bindSymbol(lib, cast(void**)&GetDeviceDriverFileNameA, "GetDeviceDriverFileNameA");
    bindSymbol(lib, cast(void**)&GetDeviceDriverFileNameW, "GetDeviceDriverFileNameW");
    bindSymbol(lib, cast(void**)&GetProcessMemoryInfo, "GetProcessMemoryInfo");
    bindSymbol(lib, cast(void**)&EmptyWorkingSet, "EmptyWorkingSet");
    bindSymbol(lib, cast(void**)&GetWsChanges, "GetWsChanges");
    bindSymbol(lib, cast(void**)&GetWsChangesEx, "GetWsChangesEx");
    bindSymbol(lib, cast(void**)&InitializeProcessForWsWatch, "InitializeProcessForWsWatch");
    bindSymbol(lib, cast(void**)&QueryWorkingSet, "QueryWorkingSet");
    bindSymbol(lib, cast(void**)&QueryWorkingSetEx, "QueryWorkingSetEx");
    bindSymbol(lib, cast(void**)&GetMappedFileNameW, "GetMappedFileNameW");
    bindSymbol(lib, cast(void**)&GetMappedFileNameA, "GetMappedFileNameA");
    bindSymbol(lib, cast(void**)&GetPerformanceInfo, "GetPerformanceInfo");
    bindSymbol(lib, cast(void**)&EnumPageFilesW, "EnumPageFilesW");
    bindSymbol(lib, cast(void**)&EnumPageFilesA, "EnumPageFilesA");
    
    __dynlib_psapi_loaded = errors.length == 0;
    return !__dynlib_psapi_loaded;
}
