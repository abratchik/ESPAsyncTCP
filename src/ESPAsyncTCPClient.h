#ifndef ESPASYNCTCPCLIENT_H
#define ESPASYNCTCPCLIENT_H

extern "C" {
#include <lwip/init.h>
#include <lwip/pbuf.h>
};

#include <functional>

#include <IPAddress.h>

#if ASYNC_TCP_SSL_ENABLED
#include <BearSSLHelpers.h>
#include <FS.h>
#include "tcp_bearssl.h"
#endif

#include "async_config.h"
#include "async_typedefs.h"

#include "ESPAsyncTCPErrorTracker.h"



/***************************************
 * Class managing outgoing connections
 **************************************/
class AsyncClient {
    public:

    #if ASYNC_TCP_SSL_ENABLED
        AsyncClient(tcp_pcb* pcb = 0, SSL_CTX* ssl_ctx = NULL);
        bool connect(IPAddress ip, uint16_t port, bool use_tls = false);
        bool connect(const char* host, uint16_t port, bool use_tls = false);

        SSL* getSSL() {return _pcb?tcp_ssl_get_ssl(_pcb):NULL; };
        // load X.509 certificates from the file system
        void load_ca_certs_from_pem(FS* fs, const char* path);
        void setInsecure(bool insecure = true) { _use_insecure = insecure;};
    #else
        AsyncClient(tcp_pcb* pcb = 0);
        bool connect(IPAddress ip, uint16_t port);
        bool connect(const char* host, uint16_t port);
    #endif
        ~AsyncClient();

        AsyncClient* prev;
        AsyncClient* next;

        AsyncClient& operator=(const AsyncClient& other);
        AsyncClient& operator+=(const AsyncClient& other);

        bool operator==(const AsyncClient& other);
        bool operator!=(const AsyncClient& other) { return !(*this == other); }

        void close(bool now = false);
        
        void abort();


        // ack is not pending
        bool canSend() { return !_pcb_busy && (space() > 0); };

        size_t space();

        // add for sending or actually send data in case of TLS connection.
        size_t add(const char* data, size_t size, uint8_t apiflags = 0); 
        
        // send all data added with the method above
        bool send();        

        // ack data that you have not acked using the method below                   
        size_t ack(size_t len);   

        // will not ack the current packet. Call from onData             
        void ackLater() { _ack_pcb = false; };

        bool isRecvPush() { return !!(_recv_pbuf_flags & PBUF_FLAG_PUSH); }
    
    #if DEBUG_ESP_ASYNC_TCP
        size_t getConnectionId(void) const { return _errorTracker->getConnectionId(); }
    #endif

        size_t write(const char* data);
        size_t write(const char* data, size_t size, uint8_t apiflags = 0);  // only when canSend() == true
        
        void ackPacket(struct pbuf* pb);

        bool connecting() { return _pcb?_pcb->state > CLOSED && _pcb->state < ESTABLISHED : false; };
        bool connected();
        bool disconnecting() { return _pcb?_pcb->state > ESTABLISHED && _pcb->state < TIME_WAIT:false; };
        bool disconnected() {return _pcb?_pcb->state == CLOSED || _pcb->state == TIME_WAIT: true; };
        // disconnected or disconnecting
        bool freeable() { return _pcb? _pcb->state == CLOSED || _pcb->state > ESTABLISHED: true; };

        // Getters & setters

        uint16_t getMss() { return _pcb? tcp_mss(_pcb):0; };
        uint32_t getRxTimeout() { return _rx_since_timeout; };
        // no RX data timeout for the connection in seconds
        void setRxTimeout(uint32_t timeout) { _rx_since_timeout = timeout; };
        uint32_t getAckTimeout() { return _ack_timeout; };
        // no ACK timeout for the last sent packet in milliseconds
        void setAckTimeout(uint32_t timeout) { _ack_timeout = timeout; };
        void setNoDelay(bool nodelay);
        bool getNoDelay() { return _pcb? tcp_nagle_disabled(_pcb): false; };

        IPAddress remoteIP() { return _pcb?(IPAddress)_pcb->remote_ip : IPAddress(0); };
        IPAddress localIP() { return _pcb?(IPAddress)_pcb->local_ip : IPAddress(0); };
        uint16_t localPort() { return _pcb?_pcb->local_port:0;  };
        uint16_t remotePort() { return _pcb? _pcb->remote_port:0;  };

        uint8_t state() { return _pcb?_pcb->state:0; };

        // Callback Setters

        void onConnect(AcConnectHandler cb, void* arg) { _connect_cb = cb;_connect_cb_arg = arg; };
        void onDisconnect(AcConnectHandler cb, void* arg) { _discard_cb = cb; _discard_cb_arg = arg;};
        void onAck(AcAckHandler cb, void* arg) { _sent_cb = cb; _sent_cb_arg = arg; };
        // unsuccessful connect or error
        void onError( AcErrorHandler cb, void* arg) { _error_cb = cb; _error_cb_arg = arg; };
        // data received (called if onPacket is not used)
        void onData(AcDataHandler cb, void* arg) { _recv_cb = cb; _recv_cb_arg = arg; };
        // data received
        void onPacket(AcPacketHandler cb, void* arg) { _pb_cb = cb; _pb_cb_arg = arg; };
        // ack timeout
        void onTimeout(AcTimeoutHandler cb, void* arg) { _timeout_cb = cb; _timeout_cb_arg = arg; };
        // every 125ms when connected
        void onPoll(AcConnectHandler cb, void* arg) { _poll_cb = cb; _poll_cb_arg = arg; };
      
        const char* stateToString();

        void _recv(std::shared_ptr<ACErrorTracker>& closeAbort, tcp_pcb* pcb, pbuf* pb, err_t err);
        err_t getCloseError(void) const { return _errorTracker->getCloseError(); }
        void setCloseError(err_t e) const { _errorTracker->setCloseError(e); }
        std::shared_ptr<ACErrorTracker> getACErrorTracker(void) const { return _errorTracker; };

        // deprecated methods, mostly duplicates
        // @deprecated Use remotePort() instead
        uint16_t getRemotePort() { return remotePort(); };
        // @deprecated Use localPort() instead
        uint16_t getLocalPort() { return localPort(); };
        // @deprecated use ACErrorTracker::errorToString instead
        static const char* errorToString(err_t error) { return ACErrorTracker::errorToString(error);};
         // @deprecated use freeable() instead
        bool free() { return freeable();  };
        // @deprecated use close() instead
        void stop() { close(false); };

    protected:

        tcp_pcb* _pcb;
        AcConnectHandler _connect_cb;
        void* _connect_cb_arg;
        AcConnectHandler _discard_cb;
        void* _discard_cb_arg;
        AcAckHandler _sent_cb;
        void* _sent_cb_arg;
        AcErrorHandler _error_cb;
        void* _error_cb_arg;
        AcDataHandler _recv_cb;
        void* _recv_cb_arg;
        AcPacketHandler _pb_cb;
        void* _pb_cb_arg;
        AcTimeoutHandler _timeout_cb;
        void* _timeout_cb_arg;
        AcConnectHandler _poll_cb;
        void* _poll_cb_arg;
        bool _pcb_busy;
        uint32_t _pcb_sent_at;
        bool _close_pcb;
        bool _ack_pcb;
        uint32_t _tx_unacked_len;
        uint32_t _tx_acked_len;
        uint32_t _rx_ack_len;
        uint32_t _rx_last_packet;
        uint32_t _rx_since_timeout;
        uint32_t _ack_timeout;
        uint16_t _connect_port;
        u8_t _recv_pbuf_flags;

        std::shared_ptr<ACErrorTracker> _errorTracker;

        void _close();
        void _connected(std::shared_ptr<ACErrorTracker>& closeAbort, void* pcb, err_t err);
        void _error(err_t err);
        void _poll(std::shared_ptr<ACErrorTracker>& closeAbort, tcp_pcb* pcb);
        void _sent(std::shared_ptr<ACErrorTracker>& closeAbort, tcp_pcb* pcb, uint16_t len);
    #if LWIP_VERSION_MAJOR == 1
        void _dns_found(struct ip_addr* ipaddr);
        static void _s_dns_found(const char* name, struct ip_addr* ipaddr, void* arg);
    #else
        void _dns_found(const ip_addr* ipaddr);
        static void _s_dns_found(const char* name, const ip_addr* ipaddr, void* arg);
    #endif
        static err_t _s_poll(void* arg, struct tcp_pcb* tpcb);
        static err_t _s_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* pb, err_t err);
        static void _s_error(void* arg, err_t err);
        static err_t _s_sent(void* arg, struct tcp_pcb* tpcb, uint16_t len);
        static err_t _s_connected(void* arg, void* tpcb, err_t err);

    #if ASYNC_TCP_SSL_ENABLED
        bool _use_tls; // if false the TLS is switched off (unencrypted connection)
        bool _use_insecure; // true if X.509 server validation is to be skipped
        bool _use_fingerprint;
        uint8_t _fingerprint[20];
        bool _use_self_signed;
        
        unsigned _knownkey_usages;

        bool _handshake_done;
        const char* _host;
        
        const BearSSL::PublicKey *_knownkey;
        // Storage for certs (empty when insecure because we do not validate the server certificate)
        BearSSL::X509List* _ca_certs;

        std::shared_ptr<br_x509_minimal_context> _x509_minimal;
        std::shared_ptr<x509_insecure_context> _x509_insecure;
        std::shared_ptr<br_x509_knownkey_context> _x509_knownkey;

         bool _initClientX509Validator(); // Set up X509 validator for a client conn.

        void _ssl_error(int8_t err) {if (_error_cb) _error_cb(_error_cb_arg, this, err + 64);};
        static void _s_data(void* arg, struct tcp_pcb* tcp, uint8_t* data, size_t len);
        static void _s_handshake(void* arg, struct tcp_pcb* tcp, SSL* ssl);
        static void _s_ssl_error(void* arg, struct tcp_pcb* tcp, int8_t err);
    #endif

};

#endif