#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>

typedef struct _MSGBOXDATA
{
    MSGBOXPARAMSW mbp;          
    HWND     hwndOwner;         
#if defined(_WIN32) && (_WIN32_WINNT >= _WIN32_WINNT_WIN7) 
    DWORD    dwPadding;
#endif
    WORD     wLanguageId;
    INT*     pidButton;            
    LPCWSTR* ppszButtonText;    
    DWORD    dwButtons;        
    UINT     uDefButton;   
    UINT     uCancelId;       
#if (_WIN32_WINNT >= _WIN32_WINNT_WINXP) 
    DWORD    dwTimeout;         
#endif
    DWORD    dwReserved0;
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7) 
    DWORD    dwReserved[4];
#endif
} MSGBOXDATA, * PMSGBOXDATA, * LPMSGBOXDATA;

typedef __int64(__fastcall* tMessageBoxTimeoutW)(__int64 hWnd, __int64 lpText, __int64 lpCaption, int utype, __int16 a5, int a6);
tMessageBoxTimeoutW MessageBoxTimeoutW = nullptr;

typedef __int64(__fastcall* tMessageBoxWorker)(struct _MSGBOXDATA* a1);
tMessageBoxWorker MessageBoxWorker = nullptr;

typedef __int64(__fastcall* tGetProcAddressForCaller)(HMODULE, LPCSTR, void*);
tGetProcAddressForCaller GetProcAddressForCaller = nullptr;

uintptr_t SignatureScan(const char* module, const char* pattern)
{
    uintptr_t moduleAdress = 0;
    moduleAdress = (uintptr_t)GetModuleHandleA(module);

    static auto patternToByte = [](const char* pattern)
    {
        auto       bytes = std::vector<int>{};
        const auto start = const_cast<char*>(pattern);
        const auto end = const_cast<char*>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current)
        {
            if (*current == '?')
            {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            }
            else { bytes.push_back(strtoul(current, &current, 16)); }
        }
        return bytes;
    };

    const auto dosHeader = (PIMAGE_DOS_HEADER)moduleAdress;
    const auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)moduleAdress + dosHeader->e_lfanew);

    const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    auto       patternBytes = patternToByte(pattern);
    const auto scanBytes = reinterpret_cast<std::uint8_t*>(moduleAdress);

    const auto s = patternBytes.size();
    const auto d = patternBytes.data();

    for (auto i = 0ul; i < sizeOfImage - s; ++i)
    {
        bool found = true;
        for (auto j = 0ul; j < s; ++j)
        {
            if (scanBytes[i + j] != d[j] && d[j] != -1)
            {
                found = false;
                break;
            }
        }
        if (found) { return reinterpret_cast<uintptr_t>(&scanBytes[i]); }
    }
    return NULL;
}

void MyMessageBox(LPCWSTR lpszText, LPCWSTR lpszCaption, DWORD dwStyle, LPCWSTR lpszIcon)
{
    INT pids[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 };
    LPCWSTR ppText[] = { L"", L"", L"", L"", L"", L"", L"", L"", L"", L"", L"", L"", L"" };

    _MSGBOXDATA msgBoxData;
    msgBoxData.mbp.cbSize = sizeof(msgBoxData.mbp);
    msgBoxData.mbp.hwndOwner = 0;
    msgBoxData.mbp.hInstance = NULL;
    msgBoxData.mbp.lpszText = lpszText;
    msgBoxData.mbp.lpszCaption = lpszCaption;
    msgBoxData.mbp.dwStyle = dwStyle;
    msgBoxData.mbp.lpszIcon = lpszIcon;
    msgBoxData.wLanguageId = 0;
    msgBoxData.pidButton = pids;
    msgBoxData.ppszButtonText = ppText;
    msgBoxData.dwButtons = _countof(pids);
    msgBoxData.uDefButton = 2;
    msgBoxData.uCancelId = 0;
#if (_WIN32_WINNT >= _WIN32_WINNT_WINXP) 
    msgBoxData.dwTimeout = 3 * 1000;
#endif

    MessageBoxWorker(&msgBoxData);
}

int main()
{
    //ShowWindow(GetConsoleWindow(), SW_HIDE);
    HMODULE user32HMod = LoadLibraryA("user32.dll");
    uintptr_t user32Addr = (uintptr_t)GetModuleHandle(L"user32.dll");
    GetProcAddressForCaller = (tGetProcAddressForCaller)(SignatureScan("kernel32.dll", "48 FF 25 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? 40 55"));
    void* retaddr = nullptr;
    MessageBoxTimeoutW = (tMessageBoxTimeoutW)((uintptr_t)GetProcAddressForCaller(user32HMod, "MessageBoxTimeoutW", retaddr));

    //MessageBoxTimeoutW((__int64)0, (__int64)L"MessageBoxTimeoutW", (__int64)L"SUCCESS", MB_ICONINFORMATION, 0, -1);

    MessageBoxWorker = (tMessageBoxWorker)(SignatureScan("user32.dll", "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 54 41 55 41 56 41 57 48 8D 6C 24 ?"));
    MyMessageBox(L"MessageBoxWorker", L"Success", 0x00000040L, L"IDI_EXCLAMATION");

    std::cout << std::hex << std::uppercase << "GetProcAddressForCaller 0x" << (uintptr_t)GetProcAddressForCaller << '\n';
    std::cout << std::hex << std::uppercase << "MessageBoxTimeoutW 0x" << (uintptr_t)MessageBoxTimeoutW << '\n';
    std::cout << std::hex << std::uppercase << "MessageBoxWorker 0x" << (uintptr_t)MessageBoxWorker << '\n';

    //std::cin.get();

	return EXIT_SUCCESS;
}