#define WIN32_MEAN_AND_LEAN
#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>
#include <stdexcept>
#include <Psapi.h>
#include <fstream>
#include <string>
#include <map>
#include <sstream>

#if defined(DISABLE_OUTPUT)
#define ILog(data, ...)
#else
#define ILog(text, ...) printf(text, __VA_ARGS__);
#endif

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

DWORD GetProcessIdByName(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Failed to create process snapshot");
    }

    struct SnapshotHandle {
        HANDLE handle;
        ~SnapshotHandle() { CloseHandle(handle); }
    } snapshotGuard{ snapshot };

    PROCESSENTRY32W processEntry{};
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &processEntry)) {
        throw std::runtime_error("Failed to get first process");
    }

    do {
        if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0) {
            return processEntry.th32ProcessID;
        }
    } while (Process32NextW(snapshot, &processEntry));

    return 0;
}

HMODULE GetRemoteModuleHandle(HANDLE hProcess, const char* moduleName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    // EnumProcessModules requires PROCESS_QUERY_INFORMATION and PROCESS_VM_READ
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];

            // Get the module's base name
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                // Extract the base name from the full path
                char* baseName = strrchr(szModName, '\\');
                if (baseName) baseName++;
                else baseName = szModName;

                // Compare the module name (case-insensitive)
                if (_stricmp(baseName, moduleName) == 0) {
                    return hMods[i]; // Found the module
                }
            }
        }
    }

    return NULL; // Module not found
}

// Function to inject a DLL into a remote process
bool InjectDLL(DWORD processId, const char* dllPath) {
    bool result = false;
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId); // Open process with sufficient rights

    if (processHandle != NULL) {
        LPVOID remoteString = VirtualAllocEx(processHandle, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (remoteString != NULL) {
            SIZE_T bytesWritten;
            if (WriteProcessMemory(processHandle, remoteString, dllPath, strlen(dllPath) + 1, &bytesWritten)) {
                // Find the LoadLibraryA function address in kernel32.dll (guaranteed to be loaded)
                HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
                if (kernel32 != NULL) {
                    LPTHREAD_START_ROUTINE loadLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32, "LoadLibraryA");

                    if (loadLibraryAddress != NULL) {
                        HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, loadLibraryAddress, remoteString, 0, NULL);

                        if (remoteThread != NULL) {
                            WaitForSingleObject(remoteThread, INFINITE); // Wait for thread to finish
                            CloseHandle(remoteThread);
                            result = true;
                        }
                        else {
                            std::cerr << "Error creating remote thread: " << GetLastError() << std::endl;
                        }
                    }
                    else {
                        std::cerr << "Error getting LoadLibraryA address: " << GetLastError() << std::endl;
                    }
                }
                else {
                    std::cerr << "Error getting kernel32.dll handle: " << GetLastError() << std::endl;
                }
            }
            else {
                std::cerr << "Error writing to process memory: " << GetLastError() << std::endl;
            }

            VirtualFreeEx(processHandle, remoteString, 0, MEM_RELEASE);
        }
        else {
            std::cerr << "Error allocating memory in remote process: " << GetLastError() << std::endl;
        }

        CloseHandle(processHandle);
    }
    else {
        std::cerr << "Error opening process: " << GetLastError() << std::endl;
    }

    return result;
}


using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);
#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif
struct MANUAL_MAPPING_DATA
{
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
    f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
    BYTE* pbase;
    HINSTANCE hMod;
    DWORD fdwReasonParam;
    LPVOID reservedParam;
    BOOL SEHSupport;
};

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) 
{
    if (!pData) {
        pData->hMod = (HINSTANCE)0x404040;
        return;
    }

    BYTE* pBase = pData->pbase;
    auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
    auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;

    auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);
    BYTE* LocationDelta = pBase - pOpt->ImageBase;
    if (LocationDelta) 
    {
        if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        {
            auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

            while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
                UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
                for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
                    if (RELOC_FLAG(*pRelativeInfo)) {
                        UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                        *pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
                    }
                }
                pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
            }
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) 
    {
        auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDescr->Name) 
        {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);
            ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

            if (!pThunkRef)
                pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
                }
                else {
                    auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDescr;
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback)
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

    bool ExceptionSupportFailed = false;

    if (pData->SEHSupport) {
        auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excep.Size) {
            if (!_RtlAddFunctionTable(
                reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
                excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
                ExceptionSupportFailed = true;
            }
        }
    }

    _DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

    if (ExceptionSupportFailed)
        pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
    else
        pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}

bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, bool ClearHeader, bool ClearNonNeededSections, bool AdjustProtections, bool SEHExceptionSupport, DWORD fdwReason, LPVOID lpReserved) 
{
    IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
    IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
    IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
    BYTE* pTargetBase = nullptr;

    if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) { //"MZ"
        ILog("Invalid file\n");
        return false;
    }

    pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
    pOldOptHeader = &pOldNtHeader->OptionalHeader;
    pOldFileHeader = &pOldNtHeader->FileHeader;

    if (pOldFileHeader->Machine != CURRENT_ARCH) {
        ILog("Invalid platform\n");
        return false;
    }

    ILog("File ok\n");

    pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pTargetBase) {
        ILog("Target process memory allocation failed (ex) 0x%X\n", GetLastError());
        return false;
    }

    DWORD oldp = 0;
    VirtualProtectEx(hProc, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);


    MANUAL_MAPPING_DATA data{ 0 };
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
    data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else 
    SEHExceptionSupport = false;
#endif
    data.pbase = pTargetBase;
    data.fdwReasonParam = fdwReason;
    data.reservedParam = lpReserved;
    data.SEHSupport = SEHExceptionSupport;

    //File header
    if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)) { //only first 0x1000 bytes for the header
        ILog("Can't write file header 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
    for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
                ILog("Can't map sections: 0x%x\n", GetLastError());
                VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
                return false;
            }
        }
    }

    //Mapping params
    BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!MappingDataAlloc) {
        ILog("Target process mapping allocation failed (ex) 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }
    if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
        ILog("Can't write mapping 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        return false;
    }

    //Shell code
    void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode) {
        ILog("Memory shellcode allocation failed (ex) 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr)) {
        ILog("Can't write shellcode 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }
    ILog("Mapped DLL at %p\n", pTargetBase);
    ILog("Mapping info at %p\n", MappingDataAlloc);
    ILog("Shell code at %p\n", pShellcode);

    ILog("Data allocated\n");

    ILog("My shellcode pointer %p\n", Shellcode);
    ILog("Target point %p\n", pShellcode);
    system("pause");

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
    if (!hThread) {
        ILog("Thread creation failed 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }
    CloseHandle(hThread);

    ILog("Thread created at: %p, waiting for return...\n", pShellcode);
    HINSTANCE hCheck = NULL;

    while (!hCheck) {
        DWORD exitcode = 0;
        GetExitCodeProcess(hProc, &exitcode);
        if (exitcode != STILL_ACTIVE) {
            ILog("Process crashed, exit code: %d\n", exitcode);
            return false;
        }
        MANUAL_MAPPING_DATA data_checked{ 0 };
        ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
        hCheck = data_checked.hMod;
        if (hCheck == (HINSTANCE)0x404040) {
            ILog("Wrong mapping ptr\n");
            VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
            return false;
        }
        else if (hCheck == (HINSTANCE)0x505050) {
            ILog("WARNING: Exception support failed!\n");
        }
        Sleep(10);
    }

    BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
    if (emptyBuffer == nullptr) {
        ILog("Unable to allocate memory\n");
        return false;
    }
    memset(emptyBuffer, 0, 1024 * 1024 * 20);

    //CLEAR PE HEAD
    if (ClearHeader) {
        if (!WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, nullptr)) {
            ILog("WARNING!: Can't clear HEADER\n");
        }
    }
    //END CLEAR PE HEAD

    if (ClearNonNeededSections) {
        pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
        for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->Misc.VirtualSize) {
                if ((SEHExceptionSupport ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) ||
                    strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
                    strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
                    ILog("Processing %s removal\n", pSectionHeader->Name);
                    if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr)) {
                        ILog("Can't clear section %s: 0x%x\n", pSectionHeader->Name, GetLastError());
                    }
                }
            }
        }
    }

    if (AdjustProtections) {
        pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
        for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->Misc.VirtualSize) {
                DWORD old = 0;
                DWORD newP = PAGE_READONLY;
                if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
                    newP = PAGE_READWRITE;
                }
                else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
                    newP = PAGE_EXECUTE_READ;
                }
                if (VirtualProtectEx(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old)) {
                    ILog("section %s set as %lX\n", (char*)pSectionHeader->Name, newP);
                }
                else {
                    ILog("FAIL: section %s not set as %lX\n", (char*)pSectionHeader->Name, newP);
                }
            }
        }
        DWORD old = 0;
        VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
    }

    if (!WriteProcessMemory(hProc, pShellcode, emptyBuffer, 0x1000, nullptr)) {
        ILog("WARNING: Can't clear shellcode\n");
    }
    if (!VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE)) {
        ILog("WARNING: can't release shell code memory\n");
    }
    if (!VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE)) {
        ILog("WARNING: can't release mapping data memory\n");
    }

    return true;
}


// INI Parser
// Function to trim leading and trailing whitespace from a string
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (std::string::npos == first) {
        return "";
    }
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}

// Function to read an INI file into a map
std::map<std::string, std::string> readIniFile(const std::string& filePath) {
    std::map<std::string, std::string> config;
    std::ifstream file(filePath);

    if (!file.is_open()) {
        std::cerr << "Error opening INI file: " << filePath << std::endl;
        return config; // Return an empty map
    }

    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);

        // Skip empty lines and comments
        if (line.empty() || line[0] == ';') {
            continue;
        }

        // Find the position of the equals sign
        size_t equalsPos = line.find('=');
        if (equalsPos != std::string::npos) {
            std::string key = trim(line.substr(0, equalsPos));
            std::string value = trim(line.substr(equalsPos + 1));
            config[key] = value;
        }
    }

    file.close();
    return config;
}
// Function to write a map to an INI file
bool writeIniFile(const std::string& filePath, const std::map<std::string, std::string>& config) {
    std::ofstream file(filePath);

    if (!file.is_open()) {
        std::cerr << "Error opening INI file for writing: " << filePath << std::endl;
        return false;
    }

    for (const auto& entry : config) {
        file << entry.first << " = " << entry.second << std::endl;
    }

    file.close();
    return true;
}
//

int main()
{
    const std::string iniFilePath = "config.ini";

    std::map<std::string, std::string> defaultConfig = {
        {"executablePath", "E:\\Games\\Netmarble Game\\sololv\\Solo_Leveling_ARISE.exe"},
        {"libraryPath", "E:\\self-project\\IL2CPP_Scanner_Reborn\\Il2CppScn.dll"}
    };

    std::map<std::string, std::string> config = readIniFile(iniFilePath);

    // Load default config if any missing
    for (const auto& entry : defaultConfig) {
        if (config.find(entry.first) == config.end()) {
            config[entry.first] = entry.second;
        }
    }

    const char* executablePath = config["executablePath"].c_str();
    const char* libraryPath = config["libraryPath"].c_str();

    if (writeIniFile(iniFilePath, config)) {
        printf("Config written to %s\n", iniFilePath.c_str());
    }

    STARTUPINFOA startupInfo = { 0 };
    PROCESS_INFORMATION processInfo = { 0 };
    startupInfo.cb = sizeof(startupInfo);

    // Create the notepad process suspended
    if (CreateProcessA(executablePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo)) {
        std::cout << "Notepad.exe created successfully (suspended)." << std::endl;
        DWORD processId = processInfo.dwProcessId;
        HANDLE processHandle = processInfo.hProcess;

        // Inject the DLL
        if (InjectDLL(processId, libraryPath)) {
            std::cout << "DLL injected successfully." << std::endl;
        }
        else {
            std::cerr << "DLL injection failed." << std::endl;
        }

        // Resume the notepad process
        if (ResumeThread(processInfo.hThread) != -1) {
            std::cout << "Notepad.exe resumed." << std::endl;
        }
        else {
            std::cerr << "Error resuming notepad.exe: " << GetLastError() << std::endl;
        }

        // Close handles (important to avoid resource leaks)
        CloseHandle(processInfo.hThread);
        CloseHandle(processHandle);  // Use the handle from CreateProcess

    }
    else {
        std::cerr << "Error creating notepad.exe: " << GetLastError() << std::endl;
    }

    system("pause");
    return 0;
}