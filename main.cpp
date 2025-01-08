#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <psapi.h>
#include <ntstatus.h>
#include <thread>
#include <mutex>
#include <queue>

DWORD pid = 0;
DWORD threads_count = 0;
std::string pattern = "";

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* NtQueryVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
    );

typedef NTSTATUS(WINAPI* NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T Size,
    PSIZE_T NumberOfBytesRead
    );

std::mutex queueMutex;
std::queue<MEMORY_BASIC_INFORMATION> regionQueue;

bool SetSeDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

bool ParsePattern(const std::string& pattern, std::vector<BYTE>& bytePattern, std::string& mask) {
    std::istringstream iss(pattern);
    std::string byteStr;
    while (iss >> byteStr) {
        if (byteStr == "?") {
            bytePattern.push_back(0x00);
            mask += "?";
        }
        else {
            bytePattern.push_back(static_cast<BYTE>(std::stoi(byteStr, nullptr, 16)));
            mask += "x";
        }
    }
    return !bytePattern.empty();
}

bool CompareMemory(const BYTE* data, const std::vector<BYTE>& pattern, const std::string& mask) {
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (mask[i] == 'x' && data[i] != pattern[i]) {
            return false;
        }
    }
    return true;
}

void ScanRegion(HANDLE hProcess, const std::vector<BYTE>& pattern, const std::string& mask, NtReadVirtualMemory_t NtReadVirtualMemory) {
    while (true) {
        MEMORY_BASIC_INFORMATION mbi;

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            if (regionQueue.empty()) {
                return;
            }
            mbi = regionQueue.front();
            regionQueue.pop();
        }

        SIZE_T bytesRead;
        std::vector<BYTE> buffer(mbi.RegionSize);
        if (NT_SUCCESS(NtReadVirtualMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead))) {
            for (SIZE_T i = 0; i < bytesRead - pattern.size(); ++i) {
                if (CompareMemory(buffer.data() + i, pattern, mask)) {
                    std::cout << "Pattern encontrado em: 0x" << std::hex << (uintptr_t(mbi.BaseAddress) + i) << std::endl;
                }
            }
        }
    }
}

void PatternScan(HANDLE hProcess, const std::vector<BYTE>& pattern, const std::string& mask) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    auto NtQueryVirtualMemory = reinterpret_cast<NtQueryVirtualMemory_t>(GetProcAddress(hNtdll, "NtQueryVirtualMemory"));
    auto NtReadVirtualMemory = reinterpret_cast<NtReadVirtualMemory_t>(GetProcAddress(hNtdll, "NtReadVirtualMemory"));
    if (!NtQueryVirtualMemory || !NtReadVirtualMemory) return;

    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = nullptr;

    while (NT_SUCCESS(NtQueryVirtualMemory(hProcess, address, MemoryBasicInformation, &mbi, sizeof(mbi), nullptr))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_EXECUTE_READWRITE)) {
            std::lock_guard<std::mutex> lock(queueMutex);
            regionQueue.push(mbi);
        }
        address = static_cast<PBYTE>(mbi.BaseAddress) + mbi.RegionSize;
    }

    std::vector<std::thread> threads;
    for (int i = 0; i < threads_count; ++i) {
        threads.emplace_back(ScanRegion, hProcess, std::ref(pattern), std::ref(mask), NtReadVirtualMemory);
    }

    for (auto& t : threads) {
        t.join();
    }
}

int main() {
    if (!SetSeDebugPrivilege()) {
        std::cerr << "Falha ao definir SeDebugPrivilege." << std::endl;
        return 1;
    }

    std::cout << "Digite o PID do processo: ";
    std::cin >> pid;

    std::cout << "Digite o pattern no formato IDA (ex: 48 89 5C 24 ? 57 ...): ";
    std::cin.ignore();
    std::getline(std::cin, pattern);

    std::cout << "Digite a quantidade de threads a procurar pelo pattern no processo: ";
    std::cin >> threads_count;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Falha ao abrir o processo. Código de erro: " << GetLastError() << std::endl;
        return 1;
    }

    std::vector<BYTE> bytePattern;
    std::string mask;
    if (!ParsePattern(pattern, bytePattern, mask)) {
        std::cerr << "Falha ao processar o pattern." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    PatternScan(hProcess, bytePattern, mask);

    CloseHandle(hProcess);
    return 0;
}