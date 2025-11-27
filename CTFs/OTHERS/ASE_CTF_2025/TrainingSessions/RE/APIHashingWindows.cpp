#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <intrin.h>
#pragma comment(lib, "user32.lib")

// required typedefs
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // we don't need the rest
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    // rest not needed
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    // rest not needed
} PEB, * PPEB;

// example hash func
uint32_t djb2_hash(const char* str) {
    uint32_t hash = 5381u;
    int c;
    while ((c = (unsigned char)*str++) != 0)
        hash = ((hash << 5) + hash) + (uint32_t)c; // hash * 33 + c
    return hash;
}

// walk PEB for module base
HMODULE get_module_by_hash(uint32_t target_hash) {
#ifdef _M_X64
    PPEB peb = (PPEB)__readgsqword(0x60);   // TEB -> PEB on x64
#else
    PPEB peb = (PPEB)__readfsdword(0x30);   // x86 variant (not tested here)
#endif

    if (!peb || !peb->Ldr)
        return NULL;

    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY mod =
            (PLDR_DATA_TABLE_ENTRY)((BYTE*)entry -
                offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

        WCHAR* wname = mod->BaseDllName.Buffer;
        if (wname && mod->BaseDllName.Length) {
            char nameA[260] = { 0 };
            int len = WideCharToMultiByte(
                CP_ACP, 0,
                wname, mod->BaseDllName.Length / sizeof(WCHAR),
                nameA, sizeof(nameA) - 1,
                NULL, NULL);

            if (len > 0) {
                if (djb2_hash(nameA) == target_hash)
                    return (HMODULE)mod->DllBase;
            }
        }

        entry = entry->Flink;
    }

    return NULL;
}

// parse module for exports
FARPROC resolve_export_by_hash(HMODULE module, uint32_t target_hash) {
    if (!module) return NULL;

    BYTE* base = (BYTE*)module;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_DATA_DIRECTORY expDirData =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (!expDirData.VirtualAddress || !expDirData.Size)
        return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + expDirData.VirtualAddress);

    DWORD* nameRvas = (DWORD*)(base + exp->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcRvas = (DWORD*)(base + exp->AddressOfFunctions);
    DWORD  nameCount = exp->NumberOfNames;

    for (DWORD i = 0; i < nameCount; ++i) {
        const char* name = (const char*)(base + nameRvas[i]);
        if (!name) continue;

        if (djb2_hash(name) == target_hash) {
            WORD ord = ordinals[i];
            DWORD funcRva = funcRvas[ord];
            return (FARPROC)(base + funcRva);
        }
    }

    return NULL;
}

int main(void) {
    // in real malware, these would be hardcoded constants
    uint32_t HASH_KERNEL32 = djb2_hash("KERNEL32.DLL");
    uint32_t HASH_USER32 = djb2_hash("USER32.DLL");
    uint32_t HASH_LOADLIBA = djb2_hash("LoadLibraryA");
    uint32_t HASH_GETPROC = djb2_hash("GetProcAddress");
    uint32_t HASH_MSGBOXA = djb2_hash("MessageBoxA");

    // get kernel32 for loadlib and getprocaddr
    HMODULE hKernel32 = get_module_by_hash(HASH_KERNEL32);
    if (!hKernel32)
        return 1;

    // resolve them
    FARPROC pLL = resolve_export_by_hash(hKernel32, HASH_LOADLIBA);
    FARPROC pGP = resolve_export_by_hash(hKernel32, HASH_GETPROC);
    if (!pLL || !pGP)
        return 1;

    typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);
    typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);

    LoadLibraryA_t   MyLoadLibraryA = (LoadLibraryA_t)pLL;
    GetProcAddress_t MyGetProcAddress = (GetProcAddress_t)pGP;

    // locate user32.dll and load it if its not
    HMODULE hUser32 = get_module_by_hash(HASH_USER32);
    if (!hUser32) {
        // in real malware this would be encrypted
        hUser32 = MyLoadLibraryA("user32.dll");
    }
    if (!hUser32)
        return 1;

    // resolve target func
    FARPROC pMsg = resolve_export_by_hash(hUser32, HASH_MSGBOXA);
    if (!pMsg)
        return 1;

    typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT); // init appropriate typedef
    MessageBoxA_t MyMessageBoxA = (MessageBoxA_t)pMsg;

    // use the resolved func
    char text[512];
    wsprintfA(
        text,
        "All of this was resolved via hashing:\n"
        "  kernel32 base: 0x%p\n"
        "  user32 base:   0x%p\n"
        "  MessageBoxA:   0x%p\n",
        (void*)hKernel32, (void*)hUser32, (void*)MyMessageBoxA
    );

    MyMessageBoxA(NULL, text, "API Hashing Demo", MB_OK | MB_ICONINFORMATION);
    return 0;
}
