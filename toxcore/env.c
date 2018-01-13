#include "env.h"

#include <stdlib.h>

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32) /* Put win32 includes here */
#ifndef WINVER
//Windows XP
#define WINVER 0x0501
#endif

// The mingw32/64 Windows library warns about including winsock2.h after
// windows.h even though with the above it's a valid thing to do. So, to make
// mingw32 headers happy, we include winsock2.h first.
#include <winsock2.h>

#include <windows.h>
#include <ws2tcpip.h>

#else // UNIX includes

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#endif

static void opsys_closesocket(Socket sock)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    closesocket(sock);
#else
    close(sock);
#endif
}

Env *opsys_new(void)
{
    Env *env = (Env *)calloc(1, sizeof(Env *));
    if (env == NULL) {
        return NULL;
    }

    env->closesocket = opsys_closesocket;

    return env;
}

void opsys_free(Env *env)
{
    free(env);
}
