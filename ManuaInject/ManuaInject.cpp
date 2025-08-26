#include <stdio.h>
#include <Windows.h>

// Tipos de funções usadas pelo Windows para carregar DLLs e localizar funções
typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);

// Tipo da função entry point de uma DLL
typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

// Estrutura que guarda todas as informações necessárias para a injeção
typedef struct _MANUAL_INJECT
{
    PVOID ImageBase; // Endereço base da DLL na memória do processo alvo
    PIMAGE_NT_HEADERS NtHeaders; // Cabeçalho NT da DLL
    PIMAGE_BASE_RELOCATION BaseRelocation; // Informação para realocar endereços
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory; // Diretório de imports da DLL
    pLoadLibraryA fnLoadLibraryA; // Função LoadLibrary
    pGetProcAddress fnGetProcAddress; // Função GetProcAddress
}MANUAL_INJECT, * PMANUAL_INJECT;

// Função que será executada dentro do processo alvo para carregar a DLL
DWORD WINAPI LoadDll(PVOID p)
{
    PMANUAL_INJECT ManualInject; // Estrutura com informações da DLL

    HMODULE hModule;
    DWORD i, Function, count, delta;

    PDWORD ptr;
    PWORD list;

    PIMAGE_BASE_RELOCATION pIBR;
    PIMAGE_IMPORT_DESCRIPTOR pIID;
    PIMAGE_IMPORT_BY_NAME pIBN;
    PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

    PDLL_MAIN EntryPoint;

    ManualInject = (PMANUAL_INJECT)p; // Recebe os dados da DLL

    // Realoca a DLL na memória do processo (ajusta endereços)
    pIBR = ManualInject->BaseRelocation;
    delta = (DWORD)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);

    while (pIBR->VirtualAddress)
    {
        if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            list = (PWORD)(pIBR + 1);

            for (i = 0; i < count; i++)
            {
                if (list[i])
                {
                    ptr = (PDWORD)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
                    *ptr += delta; // Ajusta o endereço
                }
            }
        }

        pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
    }

    // Resolve imports (funções que a DLL precisa do Windows)
    pIID = ManualInject->ImportDirectory;

    while (pIID->Characteristics)
    {
        OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
        FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

        // Carrega a DLL que será usada como dependência
        hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);
        if (!hModule)
        {
            return FALSE; // Falha ao carregar DLL
        }

        while (OrigFirstThunk->u1.AddressOfData)
        {
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // Importação por ordinal
                Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));
                if (!Function)
                    return FALSE;
                FirstThunk->u1.Function = Function;
            }
            else
            {
                // Importação por nome
                pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
                Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
                if (!Function)
                    return FALSE;
                FirstThunk->u1.Function = Function;
            }

            OrigFirstThunk++;
            FirstThunk++;
        }

        pIID++;
    }

    // Chama o entry point da DLL (DllMain)
    if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
        return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
    }

    return TRUE;
}

// Função auxiliar para calcular tamanho do loader
DWORD WINAPI LoadDllEnd()
{
    return 0;
}

// Função principal do programa console
int wmain(int argc, wchar_t* argv[])
{
    PIMAGE_DOS_HEADER pIDH;
    PIMAGE_NT_HEADERS pINH;
    PIMAGE_SECTION_HEADER pISH;

    HANDLE hProcess, hThread, hFile, hToken;
    PVOID buffer, image, mem;
    DWORD i, FileSize, ProcessId, ExitCode, read;

    TOKEN_PRIVILEGES tp;
    MANUAL_INJECT ManualInject;

    // Verifica se usuário passou DLL e PID
    if (argc < 3)
    {
        printf("\nUsage: ManualInject [DLL name] [PID]\n");
        return -1;
    }

    // Ajusta privilégios do processo atual
    if (OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        tp.Privileges[0].Luid.LowPart = 20;
        tp.Privileges[0].Luid.HighPart = 0;

        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        CloseHandle(hToken);
    }

    // Abre a DLL do disco
    printf("\nOpening the DLL.\n");
    hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("\nError: Unable to open the DLL (%d)\n", GetLastError());
        return -1;
    }

    FileSize = GetFileSize(hFile, NULL);
    buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer)
    {
        printf("\nError: Unable to allocate memory for DLL data (%d)\n", GetLastError());
        CloseHandle(hFile);
        return -1;
    }

    // Lê a DLL para memória
    if (!ReadFile(hFile, buffer, FileSize, &read, NULL))
    {
        printf("\nError: Unable to read the DLL (%d)\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return -1;
    }

    CloseHandle(hFile);

    // Verifica se é um arquivo PE válido
    pIDH = (PIMAGE_DOS_HEADER)buffer;
    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("\nError: Invalid executable image.\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }

    pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);
    if (pINH->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("\nError: Invalid PE header.\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }

    if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        printf("\nError: The image is not DLL.\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }

    // Converte argumento do PID
    ProcessId = wcstoul(argv[2], NULL, 0);

    // Abre processo alvo
    printf("\nOpening target process.\n");
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    if (!hProcess)
    {
        printf("\nError: Unable to open target process (%d)\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Aloca memória para DLL no processo alvo
    printf("\nAllocating memory for the DLL.\n");
    image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image)
    {
        printf("\nError: Unable to allocate memory for the DLL (%d)\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Copia cabeçalhos da DLL
    printf("\nCopying headers into target process.\n");
    if (!WriteProcessMemory(hProcess, image, buffer, pINH->OptionalHeader.SizeOfHeaders, NULL))
    {
        printf("\nError: Unable to copy headers to target process (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }

    // Copia seções da DLL
    pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);
    printf("\nCopying sections to target process.\n");
    for (i = 0; i < pINH->FileHeader.NumberOfSections; i++)
    {
        WriteProcessMemory(hProcess, (PVOID)((LPBYTE)image + pISH[i].VirtualAddress), (PVOID)((LPBYTE)buffer + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, NULL);
    }

    // Aloca memória para loader
    printf("\nAllocating memory for the loader code.\n");
    mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem)
    {
        printf("\nError: Unable to allocate memory for the loader code (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }

    printf("\nLoader code allocated at %#x\n", mem);
    memset(&ManualInject, 0, sizeof(MANUAL_INJECT));

    // Prepara informações da DLL para enviar ao processo alvo
    ManualInject.ImageBase = image;
    ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
    ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    ManualInject.fnLoadLibraryA = LoadLibraryA;
    ManualInject.fnGetProcAddress = GetProcAddress;

    // Escreve loader no processo alvo
    printf("\nWriting loader code to target process.\n");
    WriteProcessMemory(hProcess, mem, &ManualInject, sizeof(MANUAL_INJECT), NULL);
    WriteProcessMemory(hProcess, (PVOID)((PMANUAL_INJECT)mem + 1), LoadDll, (DWORD)LoadDllEnd - (DWORD)LoadDll, NULL);

    // Cria thread remota para executar loader
    printf("\nExecuting loader code.\n");
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((PMANUAL_INJECT)mem + 1), mem, 0, NULL);
    if (!hThread)
    {
        printf("\nError: Unable to execute loader code (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }

    // Espera terminar
    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, &ExitCode);

    if (!ExitCode)
    {
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    printf("\nDLL injected at %#x\n", image);
    if (pINH->OptionalHeader.AddressOfEntryPoint)
        printf("\nDLL entry point: %#x\n", (PVOID)((LPBYTE)image + pINH->OptionalHeader.AddressOfEntryPoint));

    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}
