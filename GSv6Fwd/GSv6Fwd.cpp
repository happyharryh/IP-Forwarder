#define _CRT_SECURE_NO_WARNINGS

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#pragma comment(lib, "ws2_32")
#include <WinSock2.h>
#include <Mswsock.h>
#include <Ws2ipdef.h>
#include <WS2tcpip.h>

#pragma comment(lib, "iphlpapi")
#include <Iphlpapi.h>

#include "../version.h"

LPFN_WSARECVMSG WSARecvMsg;

typedef struct _SOCKET_TUPLE {
    SOCKET s1;
    SOCKET s2;
} SOCKET_TUPLE, *PSOCKET_TUPLE;

typedef struct _LISTENER_TUPLE {
    SOCKET listener;
    IN_ADDR address;
    unsigned short port;
} LISTENER_TUPLE, *PLISTENER_TUPLE;

typedef struct _UDP_TUPLE {
    SOCKET ipv6Socket;
    SOCKET ipv4Socket;
    IN_ADDR address;
    unsigned short port;
} UDP_TUPLE, *PUDP_TUPLE;

int
ForwardSocketData(SOCKET from, SOCKET to)
{
    char buffer[4096];
    int len;

    len = recv(from, buffer, sizeof(buffer), 0);
    if (len <= 0) {
        return len;
    }

    if (send(to, buffer, len, 0) != len) {
        return SOCKET_ERROR;
    }

    return len;
}

DWORD
WINAPI
TcpRelayThreadProc(LPVOID Context)
{
    PSOCKET_TUPLE tuple = (PSOCKET_TUPLE)Context;
    fd_set fds;
    int err;
    bool s1ReadShutdown = false;
    bool s2ReadShutdown = false;

    for (;;) {
        FD_ZERO(&fds);

        if (!s1ReadShutdown) {
            FD_SET(tuple->s1, &fds);
        }
        if (!s2ReadShutdown) {
            FD_SET(tuple->s2, &fds);
        }
        if (s1ReadShutdown && s2ReadShutdown) {
            // Both sides gracefully closed
            break;
        }

        err = select(0, &fds, NULL, NULL, NULL);
        if (err <= 0) {
            break;
        }
        else if (FD_ISSET(tuple->s1, &fds)) {
            err = ForwardSocketData(tuple->s1, tuple->s2);
            if (err == 0) {
                // Graceful closure from s1. Propagate to s2.
                shutdown(tuple->s2, SD_SEND);
                s1ReadShutdown = true;
            }
            else if (err < 0) {
                // Forceful closure. Tear down the whole connection.
                break;
            }
        }
        else if (FD_ISSET(tuple->s2, &fds)) {
            err = ForwardSocketData(tuple->s2, tuple->s1);
            if (err == 0) {
                // Graceful closure from s2. Propagate to s1.
                shutdown(tuple->s1, SD_SEND);
                s2ReadShutdown = true;
            }
            else if (err < 0) {
                // Forceful closure. Tear down the whole connection.
                break;
            }
        }
    }

    closesocket(tuple->s1);
    closesocket(tuple->s2);
    free(tuple);
    return 0;
}

DWORD
WINAPI
TcpListenerThreadProc(LPVOID Context)
{
    PLISTENER_TUPLE tuple = (PLISTENER_TUPLE)Context;
    SOCKET acceptedSocket, targetSocket;
    SOCKADDR_IN targetAddress;
    PSOCKET_TUPLE relayTuple;
    HANDLE thread;

    printf("TCP relay running for port %d\n", tuple->port);

    for (;;) {
        acceptedSocket = accept(tuple->listener, NULL, 0);
        if (acceptedSocket == INVALID_SOCKET) {
            printf("accept() failed: %d\n", WSAGetLastError());
            break;
        }

        targetSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (targetSocket == INVALID_SOCKET) {
            printf("socket() failed: %d\n", WSAGetLastError());
            closesocket(acceptedSocket);
            continue;
        }

        RtlZeroMemory(&targetAddress, sizeof(targetAddress));
        targetAddress.sin_family = AF_INET;
        targetAddress.sin_addr = tuple->address;
        targetAddress.sin_port = htons(tuple->port);

        if (connect(targetSocket, (PSOCKADDR)&targetAddress, sizeof(targetAddress)) == SOCKET_ERROR) {
            // FIXME: This can race with reopening stdout and cause a crash in the CRT
            //printf("connect() failed: %d\n", WSAGetLastError());
            closesocket(acceptedSocket);
            closesocket(targetSocket);
            continue;
        }

        relayTuple = (PSOCKET_TUPLE)malloc(sizeof(*relayTuple));
        if (relayTuple == NULL) {
            closesocket(acceptedSocket);
            closesocket(targetSocket);
            break;
        }

        relayTuple->s1 = acceptedSocket;
        relayTuple->s2 = targetSocket;

        thread = CreateThread(NULL, 0, TcpRelayThreadProc, relayTuple, 0, NULL);
        if (thread == NULL) {
            printf("CreateThread() failed: %d\n", GetLastError());
            closesocket(acceptedSocket);
            closesocket(targetSocket);
            free(relayTuple);
            break;
        }

        CloseHandle(thread);
    }

    closesocket(tuple->listener);
    free(tuple);
    return 0;
}

int StartTcpRelay(char* listenAddress, unsigned short listenPort, char* targetAddress, unsigned short targetPort)
{
    SOCKET listeningSocket;
    SOCKADDR_IN addr6;
    HANDLE thread;
    PLISTENER_TUPLE tuple;

    listeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listeningSocket == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    RtlZeroMemory(&addr6, sizeof(addr6));
    addr6.sin_family = AF_INET;
    inet_pton(AF_INET, listenAddress, &addr6.sin_addr);
    addr6.sin_port = htons(listenPort);
    if (bind(listeningSocket, (PSOCKADDR)&addr6, sizeof(addr6)) == SOCKET_ERROR) {
        printf("bind() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    if (listen(listeningSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    tuple = (PLISTENER_TUPLE)malloc(sizeof(*tuple));
    if (tuple == NULL) {
        return ERROR_OUTOFMEMORY;
    }

    tuple->listener = listeningSocket;
    inet_pton(AF_INET, targetAddress, &tuple->address);
    tuple->port = targetPort;

    thread = CreateThread(NULL, 0, TcpListenerThreadProc, tuple, 0, NULL);
    if (thread == NULL) {
        printf("CreateThread() failed: %d\n", GetLastError());
        return GetLastError();
    }

    CloseHandle(thread);
    return 0;
}

int
ForwardUdpPacketV4toV6(PUDP_TUPLE tuple,
                       WSABUF* sourceInfoControlBuffer,
                       PSOCKADDR_IN targetAddress)
{
    DWORD len;
    char buffer[4096];
    WSABUF buf;
    WSAMSG msg;

    buf.buf = buffer;
    buf.len = sizeof(buffer);

    msg.name = NULL;
    msg.namelen = 0;
    msg.lpBuffers = &buf;
    msg.dwBufferCount = 1;
    msg.Control.buf = NULL;
    msg.Control.len = 0;
    msg.dwFlags = 0;
    if (WSARecvMsg(tuple->ipv4Socket, &msg, &len, NULL, NULL) == SOCKET_ERROR) {
        printf("WSARecvMsg() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    msg.name = (PSOCKADDR)targetAddress;
    msg.namelen = sizeof(*targetAddress);
    msg.lpBuffers->len = len;
    msg.Control = *sourceInfoControlBuffer;
    msg.dwFlags = 0;
    if (WSASendMsg(tuple->ipv6Socket, &msg, 0, &len, NULL, NULL) == SOCKET_ERROR) {
        printf("WSASendMsg() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    return 0;
}

int
ForwardUdpPacketV6toV4(PUDP_TUPLE tuple,
                       PSOCKADDR_IN targetAddress,
                       /* Out */ WSABUF* destInfoControlBuffer,
                       /* Out */ PSOCKADDR_IN sourceAddress)
{
    DWORD len;
    char buffer[4096];
    WSABUF buf;
    WSAMSG msg;

    buf.buf = buffer;
    buf.len = sizeof(buffer);

    msg.name = (PSOCKADDR)sourceAddress;
    msg.namelen = sizeof(*sourceAddress);
    msg.lpBuffers = &buf;
    msg.dwBufferCount = 1;
    msg.Control = *destInfoControlBuffer;
    msg.dwFlags = 0;
    if (WSARecvMsg(tuple->ipv6Socket, &msg, &len, NULL, NULL) == SOCKET_ERROR) {
        printf("WSARecvMsg() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    // IPV6_PKTINFO must be populated
    assert(WSA_CMSG_FIRSTHDR(&msg)->cmsg_level == IPPROTO_IPV6);
    assert(WSA_CMSG_FIRSTHDR(&msg)->cmsg_type == IPV6_PKTINFO);

    // Copy the returned data length back
    destInfoControlBuffer->len = msg.Control.len;

    msg.name = (PSOCKADDR)targetAddress;
    msg.namelen = sizeof(*targetAddress);
    msg.lpBuffers->len = len;
    msg.Control.buf = NULL;
    msg.Control.len = 0;
    msg.dwFlags = 0;
    if (WSASendMsg(tuple->ipv4Socket, &msg, 0, &len, NULL, NULL) == SOCKET_ERROR) {
        printf("WSASendMsg() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    return 0;
}

DWORD
WINAPI
UdpRelayThreadProc(LPVOID Context)
{
    PUDP_TUPLE tuple = (PUDP_TUPLE)Context;
    fd_set fds;
    int err;
    SOCKADDR_IN lastRemote;
    SOCKADDR_IN localTarget;
    char lastSourceBuf[1024];
    WSABUF lastSource;

    printf("UDP relay running for port %d\n", tuple->port);

    RtlZeroMemory(&localTarget, sizeof(localTarget));
    localTarget.sin_family = AF_INET;
    localTarget.sin_addr = tuple->address;
    localTarget.sin_port = htons(tuple->port);

    RtlZeroMemory(&lastRemote, sizeof(lastRemote));
    RtlZeroMemory(&lastSource, sizeof(lastSource));

    for (;;) {
        FD_ZERO(&fds);

        FD_SET(tuple->ipv6Socket, &fds);
        FD_SET(tuple->ipv4Socket, &fds);

        err = select(0, &fds, NULL, NULL, NULL);
        if (err <= 0) {
            break;
        }
        else if (FD_ISSET(tuple->ipv6Socket, &fds)) {
            // Forwarding incoming IPv6 packets to the IPv4 port
            // and storing the source address as our current remote
            // target for sending IPv4 data back. Collect the address
            // we received the packet on to be able to send from the same
            // source when we relay.
            lastSource.buf = lastSourceBuf;
            lastSource.len = sizeof(lastSourceBuf);

            // Don't check for errors to prevent transient issues (like GFE not having started yet)
            // from bringing down the whole relay.
            ForwardUdpPacketV6toV4(tuple, &localTarget, &lastSource, &lastRemote);
        }
        else if (FD_ISSET(tuple->ipv4Socket, &fds)) {
            // Forwarding incoming IPv4 packets to the last known
            // address IPv6 address we've heard from. Pass the destination data
            // from the last v6 packet we received to use as the source address.

            // Don't check for errors to prevent transient issues (like GFE not having started yet)
            // from bringing down the whole relay.
            ForwardUdpPacketV4toV6(tuple, &lastSource, &lastRemote);
        }
    }

    closesocket(tuple->ipv6Socket);
    closesocket(tuple->ipv4Socket);
    free(tuple);
    return 0;
}

int StartUdpRelay(char* listenAddress, unsigned short listenPort, char* targetAddress, unsigned short targetPort)
{
    SOCKET ipv6Socket;
    SOCKET ipv4Socket;
    SOCKADDR_IN addr6;
    SOCKADDR_IN addr;
    PUDP_TUPLE tuple;
    HANDLE thread;
    GUID wsaRecvMsgGuid = WSAID_WSARECVMSG;
    DWORD bytesReturned;
    DWORD val;

    ipv6Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ipv6Socket == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    if (WSAIoctl(ipv6Socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &wsaRecvMsgGuid, sizeof(wsaRecvMsgGuid),
                 &WSARecvMsg, sizeof(WSARecvMsg), &bytesReturned, NULL, NULL) == SOCKET_ERROR) {
        printf("WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSARecvMsg) failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    // IPV6_PKTINFO is required to ensure that the destination IPv6 address matches the source that
    // we send our reply from. If we don't do this, traffic destined to addresses that aren't the default
    // outgoing NIC/address will get dropped by the remote party.
    val = TRUE;
    if (setsockopt(ipv6Socket, IPPROTO_IP, IP_PKTINFO, (char*)&val, sizeof(val)) == SOCKET_ERROR) {
        printf("setsockopt(IPV6_PKTINFO) failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    RtlZeroMemory(&addr6, sizeof(addr6));
    addr6.sin_family = AF_INET;
    inet_pton(AF_INET, listenAddress, &addr6.sin_addr);
    addr6.sin_port = htons(listenPort);
    if (bind(ipv6Socket, (PSOCKADDR)&addr6, sizeof(addr6)) == SOCKET_ERROR) {
        printf("bind() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    ipv4Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ipv4Socket == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    RtlZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    if (bind(ipv4Socket, (PSOCKADDR)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("bind() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    tuple = (PUDP_TUPLE)malloc(sizeof(*tuple));
    if (tuple == NULL) {
        return ERROR_OUTOFMEMORY;
    }

    tuple->ipv4Socket = ipv4Socket;
    tuple->ipv6Socket = ipv6Socket;
    inet_pton(AF_INET, targetAddress, &tuple->address);
    tuple->port = targetPort;

    thread = CreateThread(NULL, 0, UdpRelayThreadProc, tuple, 0, NULL);
    if (thread == NULL) {
        printf("CreateThread() failed: %d\n", GetLastError());
        return GetLastError();
    }

    CloseHandle(thread);

    return 0;
}


void NETIOAPI_API_ IpInterfaceChangeNotificationCallback(PVOID context, PMIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE)
{
    SetEvent((HANDLE)context);
}

void ResetLogFile(bool standaloneExe)
{
    char timeString[MAX_PATH + 1] = {};
    SYSTEMTIME time;

    if (!standaloneExe) {
        char oldLogFilePath[MAX_PATH + 1];
        char currentLogFilePath[MAX_PATH + 1];

        ExpandEnvironmentStringsA("%ProgramData%\\MISS\\GSv6Fwd-old.log", oldLogFilePath, sizeof(oldLogFilePath));
        ExpandEnvironmentStringsA("%ProgramData%\\MISS\\GSv6Fwd-current.log", currentLogFilePath, sizeof(currentLogFilePath));

        // Close the existing stdout handle. This is important because otherwise
        // it may still be open as stdout when we try to MoveFileEx below.
        fclose(stdout);

        // Rotate the current to the old log file
        MoveFileExA(currentLogFilePath, oldLogFilePath, MOVEFILE_REPLACE_EXISTING);

        // Redirect stdout to this new file
        if (freopen(currentLogFilePath, "w", stdout) == NULL) {
            // If we couldn't create a log file, just redirect stdout to NUL.
            // We have to open _something_ or printf() will crash.
            freopen("NUL", "w", stdout);
        }
    }

    // Print a log header
    printf("IPv6 Forwarder for GameStream v" VER_VERSION_STR "\n");

    // Print the current time
    GetSystemTime(&time);
    GetTimeFormatA(LOCALE_SYSTEM_DEFAULT, 0, &time, "hh':'mm':'ss tt", timeString, ARRAYSIZE(timeString));
    printf("The current UTC time is: %s\n", timeString);
}

int Run(bool standaloneExe)
{
    int err;
    WSADATA data;
    FILE* f;
    char protocal[4], listenAddress[16], targetAddress[16];
    unsigned short listenPort, targetPort;

    ResetLogFile(standaloneExe);

    HANDLE ifaceChangeEvent = CreateEvent(nullptr, true, false, nullptr);

    err = WSAStartup(MAKEWORD(2, 0), &data);
    if (err == SOCKET_ERROR) {
        printf("WSAStartup() failed: %d\n", err);
        return err;
    }

    // Watch for IPv6 address and interface changes
    HANDLE ifaceChangeHandle;
    NotifyIpInterfaceChange(AF_INET, IpInterfaceChangeNotificationCallback, ifaceChangeEvent, false, &ifaceChangeHandle);

    // Ensure we get adequate CPU time even when the PC is heavily loaded
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    err = fopen_s(&f, "rules.conf", "r");
    if (err != 0) {
        return err;
    }

    while (fscanf_s(f, "%[CDPTU]: %[0-9.]:%hu -> %[0-9.]:%hu\n", protocal, sizeof(protocal),
                    listenAddress, sizeof(listenAddress), &listenPort,
                    targetAddress, sizeof(targetAddress), &targetPort) != EOF) {
        if (strncmp(protocal, "TCP", 3) == 0) {
            err = StartTcpRelay(listenAddress, listenPort, targetAddress, targetPort);
            if (err != 0) {
                printf("Failed to start relay on TCP %s:%u -> %s:%u : %d\n",
                       listenAddress, listenPort, targetAddress, targetPort, err);
                return err;
            }
        }

        if (strncmp(protocal, "UDP", 3) == 0) {
            err = StartUdpRelay(listenAddress, listenPort, targetAddress, targetPort);
            if (err != 0) {
                printf("Failed to start relay on UDP %s:%u -> %s:%u : %d\n",
                       listenAddress, listenPort, targetAddress, targetPort, err);
                return err;
            }
        }
    }

    fclose(f);

    for (;;) {
        ResetEvent(ifaceChangeEvent);

        printf("Going to sleep...\n");
        fflush(stdout);

        if (WaitForSingleObject(ifaceChangeEvent, 120 * 1000) == WAIT_FAILED) {
            break;
        }

        ResetLogFile(standaloneExe);
    }

    return 0;
}

int main(int argc, char* argv[])
{
    Run(true);
    return 0;
}
