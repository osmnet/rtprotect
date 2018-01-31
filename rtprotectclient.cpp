
#include <winsock2.h>
#include <windows.h>

#include <stdint.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

int main(int argc, char *argv[])
{
    uint32_t nIP;

    WSADATA wsaData;

    if (argc != 2)
    {
        fprintf(stderr, "\nUsage:\n\nrtprotectclient.exe <IPv4>\n");
        return 1;
    }

    if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData))
    {
        fprintf(stderr, "WSAStartup() failed\n");
        return 2;
    }

    nIP = inet_addr(argv[1]);

    if (INADDR_NONE == nIP)
    {
        fprintf(stderr, "Invalid IP address\n");
        WSACleanup();
        return 3;
    }

    HANDLE hPipe =
        CreateFile(
              "\\\\.\\pipe\\__ipv4_route_protect__",
              GENERIC_READ | GENERIC_WRITE,
              0,
              NULL,
              OPEN_EXISTING,
              FILE_ATTRIBUTE_NORMAL,
              NULL);

    if (hPipe != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;

        if (!WriteFile(hPipe, &nIP, sizeof(nIP), &dwWritten, NULL) ||
            sizeof(nIP) != dwWritten)
        {
            fprintf(
                stderr, "WriteFile() failed with code [%d]", GetLastError());
        }
        else
        {
            DWORD dwRead;
            uint32_t nCode = 0;

            if (!ReadFile(hPipe, &nCode, sizeof(nCode), &dwRead, NULL))
            {
                fprintf(
                    stderr, "ReadFile() failed with code [%d]", GetLastError());
            }
            else
            {
                fprintf(stdout, "Response: [%u]\n", nCode);
            }
        }
        CloseHandle(hPipe);
    }
    else
    {
        fprintf(
            stdout, "CreateFile() returned [%p] error code [%d]\n",
            hPipe, GetLastError());
    }

    WSACleanup();

    return 0;
}

