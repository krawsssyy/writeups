import pefile
import os
import sys
import ctypes
from ctypes import wintypes
import traceback

DLLS_TO_SCAN = [
    "kernel32.dll",
    "user32.dll",
    "advapi32.dll",
    "ws2_32.dll",
    "ntdll.dll",
    "wininet.dll",
    "shell32.dll",
    "ole32.dll",
]

# hash func
def hashFunc(s: str) -> int:
    h = 5381
    for c in s:
        h = ((h << 5) + h) + ord(c)
    return h & 0xFFFFFFFF

# get dll path from loaded modules
def get_dll_path(name):
    # attempt to load the dll if not loaded
    ctypes.windll.LoadLibrary(name)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi    = ctypes.WinDLL("psapi",    use_last_error=True)

    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype  = wintypes.HMODULE

    psapi.GetModuleFileNameExW.argtypes = [
        wintypes.HANDLE, # hProcess
        wintypes.HMODULE, # hModule
        wintypes.LPWSTR, # lpFilename
        wintypes.DWORD # nSize
    ]
    psapi.GetModuleFileNameExW.restype = wintypes.DWORD
    handle = kernel32.GetModuleHandleW(name)
    if not handle:
        return ""

    buffer = ctypes.create_unicode_buffer(260)
    hProcess = kernel32.GetCurrentProcess()
    result = psapi.GetModuleFileNameExW(
        hProcess,
        handle,
        buffer,
        260
    )

    if result == 0:
        return ""

    return buffer.value

# enum exports from PE and resolve hash
def scan_dll_for_hash(dll_path, target):
    try:
        pe = pefile.PE(dll_path)
    except Exception:
        return []

    exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if not exports:
        return []

    for sym in exports.symbols:
        if not sym.name:
            continue

        name = sym.name.decode(errors="ignore")
        h = hashFunc(name)

        if h == target:
            return name

    return ""

def main():
    target = hashFunc("SystemFunction034")

    print(f"[+] Searching for DJB2 hash: 0x{target:08X}\n")

    for dll in DLLS_TO_SCAN:
        if hashFunc(dll) == target:
            print(f"Found -> {dll}")
            break
        else:
            try:
                dll_path = get_dll_path(dll)
            except Exception as e:
                traceback.print_exception(e)
                continue

            print(f"[+] Scanning {dll_path} ...")

            match = scan_dll_for_hash(dll_path, target)
            if match:
                print(f"Found -> {dll}!{match}")
                break

    print("\nDone.")

if __name__ == "__main__":
    main()