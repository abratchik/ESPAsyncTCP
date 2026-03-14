#ifndef ASYNCTYPEDEFS_H
#define ASYNCTYPEDEFS_H

extern "C" {
#include <lwip/err.h>
#include "lwip/init.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/dns.h"
#include "lwip/inet.h"
#include "lwip/opt.h"
};

#include <functional>
#include <memory>

class AsyncClient;

typedef std::function<void(void*, AsyncClient*)> AcConnectHandler;
typedef std::function<void(void*, AsyncClient*, size_t len, uint32_t time)> AcAckHandler;
typedef std::function<void(void*, AsyncClient*, err_t error)> AcErrorHandler;
typedef std::function<void(void*, AsyncClient*, void* data, size_t len)> AcDataHandler;
typedef std::function<void(void*, AsyncClient*, struct pbuf* pb)> AcPacketHandler;
typedef std::function<void(void*, AsyncClient*, uint32_t time)> AcTimeoutHandler;
typedef std::function<void(void*, size_t event)> AsNotifyHandler;

#if ASYNC_TCP_SSL_ENABLED
typedef std::function<int(void* arg, const char* filename, uint8_t** buf)> AcSSlFileHandler;
#endif


#endif