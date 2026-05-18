#ifndef LIBRARIES_ESPASYNCTCP_SRC_ASYNC_CONFIG_H_
#define LIBRARIES_ESPASYNCTCP_SRC_ASYNC_CONFIG_H_

#ifndef ASYNC_TCP_SSL_ENABLED
#define ASYNC_TCP_SSL_ENABLED 0
#else
#define TCP_SSL_HANDSHAKE_TIMEOUT 2000
#endif

#ifndef ASYNC_TCP_SSL_IN_BUFFER_SIZE
#define ASYNC_TCP_SSL_IN_BUFFER_SIZE 1024
#endif

#ifndef ASYNC_TCP_SSL_OUT_BUFFER_SIZE
#define ASYNC_TCP_SSL_OUT_BUFFER_SIZE 1024
#endif

#ifndef ASYNC_TCP_SSL_X509_MODE
// 0: secure mode (perform full certificate validation with CA certs, etc.)
// 1: insecure mode (skip all certificate validation, accept any cert)
// 2: fingerprint mode (only check that the cert matches a given SHA1 fingerprint)
// 3: self-signed mode (accept any cert that is self-signed, i.e. where the issuer and subject are the same)
// 4: known key mode (only check that the cert's public key matches a known key, ignore the cert otherwise)
#define ASYNC_TCP_SSL_X509_MODE 0 
#endif

const int ASYNC_TCP_SSL_MAX_FEED_LOOPS = 10;  // Prevent infinite loops

#ifndef ASYNC_MAX_ACK_TIME
#define ASYNC_MAX_ACK_TIME 3000
#endif

#ifndef ASYNC_MAX_RX_TIME
#define ASYNC_MAX_RX_TIME 5
#endif

#define ASYNC_WRITE_FLAG_COPY \
  0x01  // will allocate new buffer to hold the data while sending (else will hold reference to the
        // data given)
#define ASYNC_WRITE_FLAG_MORE \
  0x02  // will not send PSH flag, meaning that there should be more data to be sent before the
        // application should react.
        
#ifndef TCP_MSS
// May have been definded as a -DTCP_MSS option on the compile line or not.
// Arduino core 2.3.0 or earlier does not do the -DTCP_MSS option.
// Later versions may set this option with info from board.txt.
// However, Core 2.4.0 and up board.txt does not define TCP_MSS for lwIP v1.4
#define TCP_MSS (1460)
#endif

// #define ASYNC_TCP_DEBUG(...) ets_printf(__VA_ARGS__)
// #define TCP_SSL_DEBUG(...) ets_printf(__VA_ARGS__)
// #define ASYNC_TCP_ASSERT( a ) do{ if(!(a)){ets_printf("ASSERT: %s %u \n",
// __FILE__, __LINE__);}}while(0)

// Starting with Arduino Core 2.4.0 and up the define of DEBUG_ESP_PORT
// can be handled through the Arduino IDE Board options instead of here.
// #define DEBUG_ESP_PORT Serial
// #define DEBUG_ESP_ASYNC_TCP 1
// #define DEBUG_ESP_TCP_SSL 1

#ifndef DEBUG_SKIP__DEBUG_PRINT_MACROS

#include <DebugPrintMacros.h>

#ifndef ASYNC_TCP_ASSERT
#define ASYNC_TCP_ASSERT(...) \
  do {                        \
    (void)0;                  \
  } while (false)
#endif
#ifndef ASYNC_TCP_DEBUG
#define ASYNC_TCP_DEBUG(...) \
  do {                       \
    (void)0;                 \
  } while (false)
#endif
#ifndef TCP_SSL_DEBUG
#define TCP_SSL_DEBUG(...) \
  do {                     \
    (void)0;               \
  } while (false)
#endif

#endif

#endif /* LIBRARIES_ESPASYNCTCP_SRC_ASYNC_CONFIG_H_ */
