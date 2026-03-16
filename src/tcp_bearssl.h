#ifndef TCP_BEARSSL_H
#define TCP_BEARSSL_H

#include <bearssl/bearssl.h>
#include <bearssl/bearssl_ssl.h>
#include <bearssl/bearssl_x509.h>

#include <vector>

// FORWARD DECLARE lwIP types to avoid including lwip/tcp.h in a public header
struct tcp_pcb;
struct pbuf;

// PROVIDE FULL DEFINITION for the dummy SSL struct
// This resolves the "incomplete type" error.
struct SSL {};

// FORWARD DECLARE the main context struct
struct SSL_CTX;

// FIX: Forward-declare class to avoid `using` in a header file.
namespace BearSSL {
class PrivateKey;
}

#ifdef __cplusplus
extern "C" {
#endif

// A wrapper to make BearSSL contexts look like an SSL_CTX
struct BearSSL_SSL_CTX {
  // We will parse the chain into a vector of C structs ourselves
  std::vector<br_x509_certificate> chain_vector;
  BearSSL::PrivateKey* pk = nullptr;
  ~BearSSL_SSL_CTX();
};

// BearSSL doesn't define a true insecure decoder, so we make one ourselves
// from the simple parser.  It generates the issuer and subject hashes and
// the SHA1 fingerprint, only one (or none!) of which will be used to
// "verify" the certificate.
// Private x509 decoder state
typedef struct {
  const br_x509_class *vtable;
  bool done_cert;
  const uint8_t *match_fingerprint;
  br_sha1_context sha1_cert;
  bool allow_self_signed;
  br_sha256_context sha256_subject;
  br_sha256_context sha256_issuer;
  br_x509_decoder_context ctx;
} x509_insecure_context;

struct tcp_ssl_pcb;

typedef void (*tcp_ssl_data_cb_t)(void* arg, struct tcp_pcb* tcp, uint8_t* data, size_t len);
typedef void (*tcp_ssl_handshake_cb_t)(void* arg, struct tcp_pcb* tcp, SSL* ssl);
typedef void (*tcp_ssl_error_cb_t)(void* arg, struct tcp_pcb* tcp, int8_t err);

SSL_CTX* tcp_ssl_new_server_ctx(const char* cert, const char* private_key_file,
                                const char* password);
int tcp_ssl_new_client(struct tcp_pcb* pcb, const char* host,const br_x509_class **x509ctx);
int tcp_ssl_new_server(struct tcp_pcb* pcb, SSL_CTX* ssl_ctx);
int tcp_ssl_free(struct tcp_pcb* pcb);
int tcp_ssl_write(struct tcp_pcb* pcb, const uint8_t* data, size_t len);
int tcp_ssl_read(struct tcp_pcb* pcb, struct pbuf* p);
SSL* tcp_ssl_get_ssl(struct tcp_pcb* pcb);
bool tcp_ssl_has(struct tcp_pcb* pcb);

void tcp_ssl_arg(struct tcp_pcb* pcb, void* arg);
void tcp_ssl_data(struct tcp_pcb* pcb, tcp_ssl_data_cb_t cb);
void tcp_ssl_handshake(struct tcp_pcb* pcb, tcp_ssl_handshake_cb_t cb);
void tcp_ssl_err(struct tcp_pcb* pcb, tcp_ssl_error_cb_t cb);

size_t parse_certificates(const char* pem, std::vector<br_x509_certificate>& certs);

//  Set up the x509 insecure data structures for BearSSL core to use.
void br_x509_insecure_init(x509_insecure_context* ctx, bool use_fingerprint, const uint8_t* fingerprint, bool allow_self_signed);


#ifdef __cplusplus
}
#endif

#endif  // TCP_BEARSSL_H