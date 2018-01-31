
#define UNICODE

#include <windows.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <wincrypt.h>
#include <shlwapi.h>

#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shlwapi.lib")

#define SERVICE_NAME L"IPv4 Route Protect"
#define NAMED_PIPE_NAME L"__ipv4_route_protect__"
#define VERSION "IPv4 Route Protect version 1.0"

// Size in bytes of sha256 hash
#define SHA256_HASH_SIZE 32

// Maximum numer of authorized modules
#define MAX_AUTHORIZED_MODULES 32

// Maximum number of modules the rtprotect service looks for when verifying
// if a process is authorized
#define MAX_PROCESS_MODULES 256

// Maximum for the file name of the authorized module
#define MAX_AUTHORIZED_MODULE_NAME_LENGTH 256

// This is the size of the hexadecimal encoded string representing the hash
// of the authorized module (should be at least 32 * 2 + 1 as long as we are
// using sha256)
#define MAX_AUTHORIZED_HASH_LENGTH 128

// Where rtprotect looks for its configuration (authorized modules)
#define CONFIGURATION_REGISTRY_KEY L"SOFTWARE\\BMV"

// Maximum length of comminucation named pipe name
#define MAX_NAMED_PIPE_NAME_LENGTH 64

// Windows prefix for named pipe pathes
#define NAMED_PIPE_NAME_PREFIX L"\\\\.\\pipe\\"

// Maximum length of named pipe path
#define MAX_NAMED_PIPE_PATH_LENGTH \
    sizeof(NAMED_PIPE_NAME_PREFIX) + MAX_NAMED_PIPE_NAME_LENGTH

// Default value for named pipe path
#define NAMED_PIPE_PATH NAMED_PIPE_NAME_PREFIX NAMED_PIPE_NAME

// Communication named pipe path
TCHAR g_pszNamedPipePath[MAX_NAMED_PIPE_PATH_LENGTH] = NAMED_PIPE_PATH;

// Where all fprintf calls go
FILE *g_pLogFile = stdout;

// Number of authorized modules found in windows registry configuration
DWORD g_nAuthorizedModule = 0;

// The hexadecimal encoded string representing hashes of authorized modules
TCHAR *g_pAuthorizedModule[MAX_AUTHORIZED_MODULES] = { 0 };

// The name of authorized modules (authorized module hash and name share the
// same array index between g_pAuthorizedModule and g_pAuthorizedModuleName
// arrays)
TCHAR *g_pAuthorizedModuleName[MAX_AUTHORIZED_MODULES] = { 0 };

// Global variables needed for windows service handling
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
SERVICE_STATUS g_ServiceStatus = { 0 };
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;

// Crypto Provider handle using for crypto operations (only sha256)
HCRYPTPROV g_hProv = NULL;

// Named pipe handle used by rtprotect client to request an IPv4 route
// protection
HANDLE g_hPipe = INVALID_HANDLE_VALUE;

bool CheckAccessFile(TCHAR *pszModuleName)
{
    bool bOk = false;

    TCHAR *pszModuleBaseName = PathFindFileName(pszModuleName);

    DWORD dwIdx = 0;

    while (dwIdx < g_nAuthorizedModule)
    {
        if (0 == _wcsicmp(pszModuleBaseName,
                          g_pAuthorizedModuleName[dwIdx]))
        {
            break;
        }
        dwIdx ++;
    }
    if (dwIdx >= g_nAuthorizedModule)
    {
        return bOk;
    }

    HANDLE hFile =
        CreateFile(pszModuleName, GENERIC_READ, FILE_SHARE_WRITE, NULL,
                   OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        return bOk;
    }

    HCRYPTHASH hHash;
    if (!CryptCreateHash(g_hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CloseHandle(hFile);
        return bOk;
    }

    DWORD dwRead;
    BYTE pBuffer[4096];
    while (true)
    {
        if (!ReadFile(hFile, pBuffer, sizeof(pBuffer), &dwRead, NULL))
        {
            fprintf(
                g_pLogFile, "ReadFile() failed with code [%d]\n",
                GetLastError());

            CloseHandle(hFile);
            return bOk;
        }

        if (!CryptHashData(hHash, pBuffer, dwRead, 0))
        {
            break;
        }

        if (dwRead < sizeof(pBuffer))
        {
            break;
        }
    }
    CloseHandle(hFile);

    BYTE pHash[SHA256_HASH_SIZE];
    DWORD nHashSize = sizeof(pHash);

    if (CryptGetHashParam(hHash, HP_HASHVAL, pHash, &nHashSize, 0))
    {
        TCHAR pszHexaHash[sizeof(pHash) * 2 + 1];
        pszHexaHash[0] = '\0';

        for (DWORD dwIdx = 0; dwIdx < nHashSize; dwIdx ++)
        {
            TCHAR pszByteHexa[3];
            swprintf(pszByteHexa, L"%2.2x", pHash[dwIdx]);
            wcscat(pszHexaHash, pszByteHexa);
        }

        if (0 == _wcsicmp(g_pAuthorizedModule[dwIdx], pszHexaHash))
        {
            bOk = true;
        }
    }
    CryptDestroyHash(hHash);

    return bOk;
}

bool CheckAccessModule(HANDLE hProcess, HMODULE hModule)
{
    bool bOk = false;

    TCHAR pszModuleName[MAX_PATH];

    memset(pszModuleName, 0, sizeof(pszModuleName));

    DWORD dwLength = GetModuleFileNameEx(hProcess, hModule, pszModuleName,
                                         MAX_PATH);
    if (0 == dwLength)
    {
        fprintf(
            g_pLogFile, "GetModuleFileNameEx(%p) failed with code [%d]\n",
            hModule,
            GetLastError());

        return bOk;
    }

    return CheckAccessFile(pszModuleName);
}

HMODULE * EnumModules(HANDLE hProcess)
{
    HMODULE *phModules = NULL;
    DWORD dwModuleArraySize = 0;
    DWORD dwModules;
    DWORD dwMaxAttempts = 4;

    do
    {
        dwModules = dwModuleArraySize;

        if (phModules)
        {
            free(phModules);
            phModules = NULL;
        }
        if (dwModules)
        {
            if (dwModules > MAX_PROCESS_MODULES * sizeof(HMODULE))
            {
                fprintf(
                    g_pLogFile,
                    "EnumProcessModulesEx() returned too many modules [%zd]",
                    dwModules / sizeof(HMODULE));
                break;
            }
            // Make it one HMODULE bigger to store terminal NULL value
            phModules = (HMODULE *)malloc(dwModules + sizeof(HMODULE));
        }

        if (!EnumProcessModulesEx(hProcess, phModules, dwModules,
                                  &dwModuleArraySize, LIST_MODULES_ALL))
        {
            fprintf(
                g_pLogFile,
                "EnumProcessModulesEx() failed with code [%d]\n",
                GetLastError());

            free(phModules);
            phModules = NULL;

            break;
        }
        dwMaxAttempts --;
    }
    while (dwModuleArraySize != dwModules && dwMaxAttempts > 0);

    if (phModules)
    {
        phModules[dwModuleArraySize / sizeof(HMODULE)] = NULL;
    }

    return phModules;
}

void FreeModules(HMODULE *phModules)
{
    free(phModules);
}

bool CheckAccess(HANDLE hNamedPipe)
{
    bool bOk = false;

    ULONG nProcessID = 0;
    if (!GetNamedPipeClientProcessId(g_hPipe, &nProcessID))
    {
        fprintf(
            g_pLogFile,
            "GetNamedPipeClientProcessId() failed with code [%d]\n",
            GetLastError());

        return bOk;
    }

    HANDLE hProcess =
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, nProcessID);

    if (INVALID_HANDLE_VALUE == hProcess)
    {
        fprintf(
            g_pLogFile, "OpenProcess() failed with code [%d]",
            GetLastError());
        return bOk;
    }

    HMODULE *phModules = EnumModules(hProcess);
    if (phModules)
    {
        for (DWORD dwIdx = 0; phModules[dwIdx]; dwIdx ++)
        {
            if (CheckAccessModule(hProcess, phModules[dwIdx]))
            {
                bOk = true;

                break;
            }
        }
        FreeModules(phModules);
    }

    CloseHandle(hProcess);

    return bOk;
}

bool BuildSecurityAttributes(SECURITY_ATTRIBUTES *psa)
{
    bool bOk = false;

    PSECURITY_DESCRIPTOR psd;

    do
    {
        psd = (PSECURITY_DESCRIPTOR)malloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
        memset(psd, 0, SECURITY_DESCRIPTOR_MIN_LENGTH);

        if (!InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION))
        {
            fprintf(
                g_pLogFile,
                "InitializeSecurityDescriptor() failed with code [%d]\n",
                GetLastError());
            break;
        }

        if (!SetSecurityDescriptorDacl(psd, TRUE, NULL, FALSE))
        {
            fprintf(
                g_pLogFile,
                "SetSecurityDescriptorDacl() failed with code [%d]\n",
                GetLastError());
            break;
        }

        psa->nLength = sizeof(SECURITY_ATTRIBUTES);
        psa->bInheritHandle = FALSE;
        psa->lpSecurityDescriptor = psd;

        bOk = true;
    }
    while (false);

    return bOk;
}

void LoadConfiguration()
{
    LONG nRet;
    HKEY hConfigurationKey;
    HKEY hAuthorizedKey;

    nRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                        CONFIGURATION_REGISTRY_KEY,
                        0,
                        KEY_READ,
                        &hConfigurationKey);

    if (ERROR_SUCCESS == nRet)
    {
        DWORD dwIdx = 0;

        DWORD dwType;
        TCHAR pszPipeName[MAX_NAMED_PIPE_NAME_LENGTH + 1];
        DWORD dwPipeNameSize = sizeof(pszPipeName);

        nRet = RegQueryValueEx(hConfigurationKey,
                               L"NamedPipeName",
                               0,
                               &dwType,
                               (LPBYTE)pszPipeName,
                               &dwPipeNameSize);

        if (ERROR_SUCCESS == nRet && REG_SZ == dwType)
        {
            wcscpy(g_pszNamedPipePath, NAMED_PIPE_NAME_PREFIX);
            wcscat(g_pszNamedPipePath, pszPipeName);
        }

        nRet = RegOpenKeyEx(hConfigurationKey,
                            L"Authorized",
                            0,
                            KEY_READ,
                            &hAuthorizedKey);

        if (ERROR_SUCCESS == nRet)
        {
            while (true)
            {
                TCHAR pszName[MAX_AUTHORIZED_MODULE_NAME_LENGTH];
                DWORD dwNameSize = MAX_AUTHORIZED_MODULE_NAME_LENGTH;
                TCHAR pszHash[MAX_AUTHORIZED_HASH_LENGTH];
                DWORD dwHashSize = sizeof(pszHash);

                nRet = RegEnumValue(hAuthorizedKey,
                                    dwIdx,
                                    pszName,
                                    &dwNameSize,
                                    NULL,
                                    &dwType,
                                    (LPBYTE)pszHash,
                                    &dwHashSize);

                if (ERROR_SUCCESS == nRet && REG_SZ == dwType)
                {
                    if (g_nAuthorizedModule >= MAX_AUTHORIZED_MODULES)
                    {
                        break;
                    }

                    g_pAuthorizedModuleName[g_nAuthorizedModule] =
                        (TCHAR *)malloc((dwNameSize + 1) * sizeof(TCHAR));

                    g_pAuthorizedModule[g_nAuthorizedModule] =
                        (TCHAR *)malloc(dwHashSize);

                    wcscpy(
                        g_pAuthorizedModule[g_nAuthorizedModule], pszHash);

                    wcscpy(
                        g_pAuthorizedModuleName[g_nAuthorizedModule], pszName);

                    g_nAuthorizedModule ++;
                }
                else
                {
                    break;
                }
                dwIdx ++;
            }
            RegCloseKey(hAuthorizedKey);

        }
        else
        {
            fprintf(g_pLogFile, "RegOpenKeyEx() failed with code [%d]\n", nRet);
        }
        RegCloseKey(hConfigurationKey);
    }
    else
    {
        fprintf(g_pLogFile, "RegOpenKeyEx() failed with code [%d]\n", nRet);
    }
}

void Initialize()
{
    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    LoadConfiguration();

    SECURITY_ATTRIBUTES sa;
    if (BuildSecurityAttributes(&sa))
    {
        g_hPipe =
            CreateNamedPipe(
                g_pszNamedPipePath,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                64,
                64,
                NMPWAIT_USE_DEFAULT_WAIT,
                &sa);

        free(sa.lpSecurityDescriptor);
    }

    if (!CryptAcquireContext(&g_hProv, 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        fprintf(
            g_pLogFile, "CryptAcquireContext() failed with code [%d]\n",
            GetLastError());
    }
}

bool ProtectIPv4Route(DWORD nRouteDest)
{
    MIB_IPFORWARDROW stRoute;

    DWORD dwErr = GetBestRoute(nRouteDest, 0, &stRoute);
    if (NO_ERROR != dwErr)
    {
        fprintf(g_pLogFile, "GetBestRoute() failed with code [%d]", dwErr);

        return false;
    }

    bool bUpdate = false;

    if (0xffffffff == stRoute.dwForwardMask)
    {
        bUpdate = true;
    }

    stRoute.dwForwardDest = nRouteDest;
    stRoute.dwForwardMask = 0xffffffff;
    stRoute.dwForwardAge = 0;
    stRoute.dwForwardProto = MIB_IPPROTO_NETMGMT;

    dwErr =
        bUpdate ? SetIpForwardEntry(&stRoute) : CreateIpForwardEntry(&stRoute);

    if (NO_ERROR != dwErr)
    {
        fprintf(
            g_pLogFile, "CreateIpForwardEntry() failed with code [%d]", dwErr);

        return false;
    }
    return true;
}

void ConnectPipe()
{
    HANDLE hPipe =
        CreateFile(
            g_pszNamedPipePath,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

    if (INVALID_HANDLE_VALUE != hPipe)
    {
        CloseHandle(hPipe);
    }
}

bool AcceptPipeClient()
{
    if (ConnectNamedPipe(g_hPipe, NULL))
    {
        DWORD dwRead = 0;
        DWORD nRouteDest;

        if (ReadFile(g_hPipe, &nRouteDest, sizeof(nRouteDest), &dwRead, NULL) &&
            dwRead > 0)
        {
            uint32_t nResponseCode = 0;

            if (CheckAccess(g_hPipe))
            {
                if (!ProtectIPv4Route(nRouteDest))
                {
                    nResponseCode = 2;
                }
            }
            else
            {
                nResponseCode = 1;
            }
            if (!WriteFile(g_hPipe, &nResponseCode, sizeof(nResponseCode),
                           &dwRead, NULL))
            {
                fprintf(
                    g_pLogFile, "WriteFile() failed with code [%d]\n",
                    GetLastError());
            }
        }
        else
        {
            fprintf(
                g_pLogFile, "ReadFile() failed with code [%d]\n",
                GetLastError());
        }

        DisconnectNamedPipe(g_hPipe);
    }
    else
    {
        fprintf(g_pLogFile, "ConnectNamedPipe() failed with code [%d]\n",
                GetLastError());

        return false;
    }
    return true;
}

void Cleanup()
{
    if (g_hPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
    if (g_hProv)
    {
        CryptReleaseContext(g_hProv, 0);
        g_hProv = NULL;
    }

    for (DWORD dwIdx = 0; dwIdx < g_nAuthorizedModule; dwIdx ++)
    {
        if (g_pAuthorizedModuleName[dwIdx])
        {
            free(g_pAuthorizedModuleName[dwIdx]);
            g_pAuthorizedModuleName[dwIdx] = NULL;
        }

        if (g_pAuthorizedModule[dwIdx])
        {
            free(g_pAuthorizedModule[dwIdx]);
            g_pAuthorizedModule[dwIdx] = NULL;
        }
    }

    g_nAuthorizedModule = 0;
}

void WINAPI ServiceCtrlHandler(DWORD dwCtrlCode);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

void WINAPI ServiceMain(DWORD , LPTSTR *)
{
    DWORD Status = E_FAIL;

    g_StatusHandle =
        RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);

    if (g_StatusHandle == NULL)
    {
        return;
    }

    memset(&g_ServiceStatus, 0, sizeof(g_ServiceStatus));

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    SetServiceStatus(g_StatusHandle , &g_ServiceStatus);

    Initialize();

    if (g_ServiceStopEvent == NULL)
    {
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        g_ServiceStatus.dwCheckPoint = 1;

        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);

    WaitForSingleObject(hThread, INFINITE);

    Cleanup();

    CloseHandle(g_ServiceStopEvent);

    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 3;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

void WINAPI ServiceCtrlHandler(DWORD dwCtrlCode)
{
    switch (dwCtrlCode)
    {
     case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
        {
           break;
        }

        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 4;

        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

        SetEvent(g_ServiceStopEvent);

        ConnectPipe();
        break;

     default:
         break;
    }
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0)
    {
        if (!AcceptPipeClient())
        {
            break;
        }
    }

    return ERROR_SUCCESS;
}

int main(int argc, char *argv[])
{
    if (argc > 1 && 0 == stricmp("--debug", argv[1]))
    {
        fprintf(g_pLogFile, VERSION "\n");

        Initialize();
        while (AcceptPipeClient());
        Cleanup();
    }
    else
    {
        SERVICE_TABLE_ENTRY ServiceTable[] =
            {
                { SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
                { NULL, NULL }
            };

        StartServiceCtrlDispatcher(ServiceTable);
    }

    return 0;
}

