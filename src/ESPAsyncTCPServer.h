#ifndef ESPASYNCTCPSERVER_H
#define ESPASYNCTCPSERVER_H

#if ASYNC_TCP_SSL_ENABLED
#include <BearSSLHelpers.h>
#include <FS.h>
#include "tcp_bearssl.h"
#endif

#include <IPAddress.h>

#include "async_config.h"
#include "async_typedefs.h"

#include "ESPAsyncTCPClient.h"

struct pending_pcb;

/*****************************************
 * Class managing incoming TCP connections
 *****************************************/
class AsyncServer {
    public:
        AsyncServer(IPAddress addr, uint16_t port);
        AsyncServer(uint16_t port);
        ~AsyncServer();

        void onClient(AcConnectHandler cb, void* arg);
    #if ASYNC_TCP_SSL_ENABLED
        void onSslFileRequest(AcSSlFileHandler cb, void* arg);
        void beginSecure(const char* cert, const char* private_key_file, const char* password);
    #endif
        void begin();
        void end();
        void setNoDelay(bool nodelay);
        bool getNoDelay();
        uint8_t status();
    #ifdef DEBUG_MORE
        int getEventCount(size_t ee) const { return _event_count[ee]; }
    #endif
    
    protected:
        err_t _accept(tcp_pcb* newpcb, err_t err);
        static err_t _s_accept(void* arg, tcp_pcb* newpcb, err_t err);
    #ifdef DEBUG_MORE
        int incEventCount(size_t ee) { return ++_event_count[ee]; }
    #endif
    #if ASYNC_TCP_SSL_ENABLED
        //   int _cert(const char* filename, uint8_t** buf);
        //   err_t _poll(tcp_pcb* pcb);
        //   err_t _recv(tcp_pcb* pcb, struct pbuf* pb, err_t err);
        //   static int _s_cert(void* arg, const char* filename, uint8_t** buf);
        //   static err_t _s_poll(void* arg, struct tcp_pcb* tpcb);
        //   static err_t _s_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* pb, err_t err);
    #endif


        uint16_t _port;
        IPAddress _addr;
        bool _noDelay;
        tcp_pcb* _pcb;
        AcConnectHandler _connect_cb;
        void* _connect_cb_arg;
    #if ASYNC_TCP_SSL_ENABLED
        // REMOVE the old _pending, _file_cb, _file_cb_arg members if they are still there.
        // struct pending_pcb * _pending;
        // AcSSlFileHandler _file_cb;
        // void* _file_cb_arg;

        // ADD/RESTORE the _ssl_ctx member
        SSL_CTX* _ssl_ctx;
    #endif


};



#endif