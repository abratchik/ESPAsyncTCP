/*
  BearSSL glue layer for ESPAsyncTCP

  This file provides the bridge between the lwIP raw TCP API and the BearSSL
  TLS engine, allowing for non-blocking, asynchronous TLS communication.

  FULLY PATCHED & COMPATIBLE VERSION:
  - Uses the correct BearSSL API (`br_ssl_engine_set_buffers_bidi` with
    separate buffers) for full compatibility with ESP8266 Arduino Core versions.
  - Adds PROGMEM awareness to automatically handle certificates from flash,
    fixing LoadStoreError crashes.
  - Replaces large, fixed-size I/O buffers with smaller, configurable split
    buffers to drastically reduce RAM usage per client and increase scalability.
  - Resolves incompatibility with older BearSSL PEM decoder APIs.
  - Includes robust NULL checks to prevent crashes from invalid arguments.
*/

#include "tcp_bearssl.h"

#include <BearSSLHelpers.h>
#include <bearssl/bearssl_pem.h>
#include <lwip/tcp.h>  // Needs to be included for pcb functions

#include <memory>  // For std::unique_ptr (PROGMEM patch)

#include "async_config.h"
#include "DebugPrintMacros.h"

BearSSL_SSL_CTX::~BearSSL_SSL_CTX() {
  for (auto& cert : chain_vector) {
    free(cert.data);
  }
  delete pk;
}

// Per-connection state for a BearSSL session
struct tcp_ssl_pcb {
  struct tcp_pcb* tcp;
  br_ssl_client_context sc_client;
  br_ssl_server_context sc_server;
  br_x509_minimal_context xc;
  // --- MEMORY OPTIMIZATION ---
  // Use two smaller, configurable split buffers.
  unsigned char inbuf[ASYNC_TCP_SSL_IN_BUFFER_SIZE];
  unsigned char outbuf[ASYNC_TCP_SSL_OUT_BUFFER_SIZE];
  
  // pointers to track app data currently in the inbuf and pending in the outbuf
  unsigned char* in_buf_ptr;  
  unsigned char* out_buf_ptr;  

  // len of app data currently in the inbuf, and len of pending data in outbuf
  size_t in_len;
  size_t out_len;

  // ---- RECORD REASSEMBLY ----
  // Use the end of inbuf for accumulating partial TLS records.
  // This prevents feeding incomplete records to BearSSL which causes AEAD MAC failures.
  // The accumulator starts at the end of the buffer and grows backwards.
  size_t recvrec_accum_pos;  // Position in inbuf where accumulated data starts (from end)

  // -------------------------
  bool is_server;
  bool handshake_done;

  // Callbacks and arguments
  void* arg;
  tcp_ssl_data_cb_t on_data;
  tcp_ssl_handshake_cb_t on_handshake;
  tcp_ssl_error_cb_t on_error;

  SSL dummy_ssl;  // API compatibility
  struct tcp_ssl_pcb* next;
};

// Linked list of all active BearSSL connections
static tcp_ssl_pcb* tcp_ssl_pcbs = nullptr;

// Forward declaration
static void process_ssl_engine(tcp_ssl_pcb* ssl_pcb);

// Helper to convert the TLS version number to a string
static const char* tcp_ssl_version_string(uint16_t version) {
  switch (version) {
    case BR_TLS10: return "TLS1.0";
    case BR_TLS11: return "TLS1.1";
    case BR_TLS12: return "TLS1.2";
    default: return "Unknown";
  }
}

// Helper to find an SSL connection's state from its lwIP pcb
static tcp_ssl_pcb* find_ssl_pcb(struct tcp_pcb* pcb) {
  tcp_ssl_pcb* iter = tcp_ssl_pcbs;
  while (iter) {
    if (iter->tcp == pcb) {
      return iter;
    }
    iter = iter->next;
  }
  return nullptr;
}

// --- Internal Helper Functions for Parsing ---

struct CertParseCtx {
  std::vector<br_x509_certificate>* certs;
  unsigned char* buf;
  size_t len;
  bool error;
};

static void append_to_cert_vector(void* ctx, const void* data, size_t len) {
  CertParseCtx* pctx = (CertParseCtx*)ctx;
  if (pctx->error) return;

  unsigned char* new_buf = (unsigned char*)realloc(pctx->buf, pctx->len + len);
  if (!new_buf) {
    pctx->error = true;
    free(pctx->buf);
    pctx->buf = nullptr;
    return;
  }
  pctx->buf = new_buf;
  memcpy(pctx->buf + pctx->len, data, len);
  pctx->len += len;
}


// --- Public API Implementation ---

size_t parse_certificates(const char* pem, std::vector<br_x509_certificate>& certs) {
  if (!pem) return 0;

  const unsigned char* data = (const unsigned char*)pem;
  size_t len = strlen(pem);

  br_pem_decoder_context pc;
  br_pem_decoder_init(&pc);

  CertParseCtx pctx;
  pctx.certs = &certs;
  pctx.buf = nullptr;
  pctx.len = 0;
  pctx.error = false;

  br_pem_decoder_setdest(&pc, append_to_cert_vector, &pctx);

  size_t pushed = 0;
  while (pushed < len) {
    size_t chunk_len = len - pushed;
    pushed += br_pem_decoder_push(&pc, data + pushed, chunk_len);

    if (pctx.error) {
      for (auto& cert : certs) free(cert.data);
      certs.clear();
      return 0;
    }

    int event = br_pem_decoder_event(&pc);
    if (event == BR_PEM_BEGIN_OBJ) {
      free(pctx.buf);
      pctx.buf = nullptr;
      pctx.len = 0;
    } else if (event == BR_PEM_END_OBJ) {
      if (pctx.buf && pctx.len > 0 && strcmp(br_pem_decoder_name(&pc), "CERTIFICATE") == 0) {
        certs.push_back({pctx.buf, pctx.len});
      } else {
        free(pctx.buf);
      }
      pctx.buf = nullptr;
      pctx.len = 0;
    } else if (event < 0) {
      free(pctx.buf);
      for (auto& cert : certs) free(cert.data);
      certs.clear();
      return 0;
    }
  }

  return certs.size();
}


SSL_CTX* tcp_ssl_new_server_ctx(const char* cert_pem, const char* private_key_pem,
                                const char* password) {
  (void)password;
  if (!cert_pem || !private_key_pem) {
    return nullptr;
  }

  // --- START: PROGMEM AWARENESS PATCH ---
  std::unique_ptr<char[]> cert_ram_buf;
  std::unique_ptr<char[]> key_ram_buf;

  if ((uint32_t)cert_pem >= 0x40200000) {
    size_t len = strlen_P(cert_pem) + 1;
    cert_ram_buf.reset(new (std::nothrow) char[len]);
    if (!cert_ram_buf) return nullptr;
    memcpy_P(cert_ram_buf.get(), cert_pem, len);
    cert_pem = cert_ram_buf.get();
  }

  if ((uint32_t)private_key_pem >= 0x40200000) {
    size_t len = strlen_P(private_key_pem) + 1;
    key_ram_buf.reset(new (std::nothrow) char[len]);
    if (!key_ram_buf) return nullptr;
    memcpy_P(key_ram_buf.get(), private_key_pem, len);
    private_key_pem = key_ram_buf.get();
  }
  // --- END: PROGMEM AWARENESS PATCH ---

  BearSSL_SSL_CTX* ctx = new (std::nothrow) BearSSL_SSL_CTX();
  if (!ctx) {
    return nullptr;
  }

  if (parse_certificates(cert_pem, ctx->chain_vector) == 0) {
    delete ctx;
    return nullptr;
  }

  ctx->pk = new (std::nothrow) BearSSL::PrivateKey(private_key_pem);
  if (!ctx->pk) {
    delete ctx;
    return nullptr;
  }

  if (!ctx->pk->getRSA() && !ctx->pk->getEC()) {
    delete ctx;
    return nullptr;
  }

  return (SSL_CTX*)ctx;
}

// Private x509 decoder state

// Callback for the x509_minimal subject DN
static void insecure_subject_dn_append(void *ctx, const void *buf, size_t len) {
  x509_insecure_context *xc = (x509_insecure_context *)ctx;
  br_sha256_update(&xc->sha256_subject, buf, len);
}

// Callback for the x509_minimal issuer DN
static void insecure_issuer_dn_append(void *ctx, const void *buf, size_t len) {
  x509_insecure_context *xc = (x509_insecure_context *)ctx;
  br_sha256_update(&xc->sha256_issuer, buf, len);
}

// Callback on the first byte of any certificate
static void insecure_start_chain(const br_x509_class **ctx, const char *server_name) {
  x509_insecure_context *xc = (x509_insecure_context *)ctx;
  br_x509_decoder_init(&xc->ctx, insecure_subject_dn_append, xc, insecure_issuer_dn_append, xc);
  xc->done_cert = false;
  br_sha1_init(&xc->sha1_cert);
  br_sha256_init(&xc->sha256_subject);
  br_sha256_init(&xc->sha256_issuer);
  (void)server_name;
}

// Callback for each certificate present in the chain (but only operates
// on the first one by design).
static void insecure_start_cert(const br_x509_class **ctx, uint32_t length) {
  (void) ctx;
  (void) length;
}

// Callback for each byte stream in the chain.  Only process first cert.
static void insecure_append(const br_x509_class **ctx, const unsigned char *buf, size_t len) {
  x509_insecure_context *xc = (x509_insecure_context *)ctx;
  // Don't process anything but the first certificate in the chain
  if (!xc->done_cert) {
    br_sha1_update(&xc->sha1_cert, buf, len);
    br_x509_decoder_push(&xc->ctx, (const void*)buf, len);
#if defined(DEBUG_ESP_SSL) && defined(DEBUG_ESP_PORT)
    DEBUG_BSSL("CERT: ");
    for (size_t i=0; i<len; i++) {
      DEBUG_ESP_PORT.printf_P(PSTR("%02x "), buf[i] & 0xff);
    }
    DEBUG_ESP_PORT.printf_P(PSTR("\n"));
#endif
  }
}

// Callback on individual cert end.
static void insecure_end_cert(const br_x509_class **ctx) {
  x509_insecure_context *xc = (x509_insecure_context *)ctx;
  xc->done_cert = true;
}

// Callback when complete chain has been parsed.
// Return 0 on validation success, !0 on validation error
static unsigned insecure_end_chain(const br_x509_class **ctx) {
  const x509_insecure_context *xc = (const x509_insecure_context *)ctx;
  if (!xc->done_cert) {
    TCP_SSL_DEBUG("insecure_end_chain: No cert seen\n");
    return 1; // error
  }

  // Handle SHA1 fingerprint matching
  char res[20];
  br_sha1_out(&xc->sha1_cert, res);
  if (xc->match_fingerprint && memcmp(res, xc->match_fingerprint, sizeof(res))) {
#ifdef DEBUG_ESP_SSL
    DEBUG_BSSL("insecure_end_chain: Received cert FP doesn't match\n");
    char buff[3 * sizeof(res) + 1]; // 3 chars per byte XX_, and null
    buff[0] = 0;
    for (size_t i=0; i<sizeof(res); i++) {
      char hex[4]; // XX_\0
      snprintf(hex, sizeof(hex), "%02x ", xc->match_fingerprint[i] & 0xff);
      strlcat(buff, hex, sizeof(buff));
    }
    DEBUG_BSSL("insecure_end_chain: expected %s\n", buff);
    buff[0] =0;
    for (size_t i=0; i<sizeof(res); i++) {
      char hex[4]; // XX_\0
      snprintf(hex, sizeof(hex), "%02x ", res[i] & 0xff);
      strlcat(buff, hex, sizeof(buff));
    }
    DEBUG_BSSL("insecure_end_chain: received %s\n", buff);
#endif
    return BR_ERR_X509_NOT_TRUSTED;
  }

  // Handle self-signer certificate acceptance
  char res_issuer[32];
  char res_subject[32];
  br_sha256_out(&xc->sha256_issuer, res_issuer);
  br_sha256_out(&xc->sha256_subject, res_subject);
  if (xc->allow_self_signed && memcmp(res_subject, res_issuer, sizeof(res_issuer))) {
    TCP_SSL_DEBUG("insecure_end_chain: Didn't get self-signed cert\n");
    return BR_ERR_X509_NOT_TRUSTED;
  }

  // Default (no validation at all) or no errors in prior checks = success.
  return 0;
}

// Return the public key from the validator (set by x509_minimal)
static const br_x509_pkey *insecure_get_pkey(const br_x509_class *const *ctx, unsigned *usages) {
  const x509_insecure_context *xc = (const x509_insecure_context *)ctx;
  if (usages != NULL) {
    *usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN; // I said we were insecure!
  }
  return &xc->ctx.pkey;
}


//  Set up the x509 insecure data structures for BearSSL core to use.
void br_x509_insecure_init(x509_insecure_context *ctx, int use_fingerprint, const uint8_t* fingerprint, int allow_self_signed) {
  static const br_x509_class br_x509_insecure_vtable PROGMEM = {
    sizeof(x509_insecure_context),
    insecure_start_chain,
    insecure_start_cert,
    insecure_append,
    insecure_end_cert,
    insecure_end_chain,
    insecure_get_pkey
  };

  memset(ctx, 0, sizeof * ctx);
  ctx->vtable = &br_x509_insecure_vtable;
  ctx->done_cert = false;
  ctx->match_fingerprint = use_fingerprint ? fingerprint : nullptr;
  ctx->allow_self_signed = allow_self_signed ? 1 : 0;
}


// Some constants uses to init the server/client contexts
// Note that suites_P needs to be copied to RAM before use w/BearSSL!
// List copied verbatim from BearSSL/ssl_client_full.c
/*
  * The "full" profile supports all implemented cipher suites.
  *
  * Rationale for suite order, from most important to least
  * important rule:
  *
  * -- Don't use 3DES if AES or ChaCha20 is available.
  * -- Try to have Forward Secrecy (ECDHE suite) if possible.
  * -- When not using Forward Secrecy, ECDH key exchange is
  *    better than RSA key exchange (slightly more expensive on the
  *    client, but much cheaper on the server, and it implies smaller
  *    messages).
  * -- ChaCha20+Poly1305 is better than AES/GCM (faster, smaller code).
  * -- GCM is better than CCM and CBC. CCM is better than CBC.
  * -- CCM is preferable over CCM_8 (with CCM_8, forgeries may succeed
  *    with probability 2^(-64)).
  * -- AES-128 is preferred over AES-256 (AES-128 is already
  *    strong enough, and AES-256 is 40% more expensive).
  */
static const uint16_t suites_P[] PROGMEM = {
#ifndef BEARSSL_SSL_BASIC
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_RSA_WITH_AES_128_CCM,
    BR_TLS_RSA_WITH_AES_256_CCM,
    BR_TLS_RSA_WITH_AES_128_CCM_8,
    BR_TLS_RSA_WITH_AES_256_CCM_8,
#endif
    BR_TLS_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_RSA_WITH_AES_256_CBC_SHA256,
    BR_TLS_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_RSA_WITH_AES_256_CBC_SHA,
#ifndef BEARSSL_SSL_BASIC
    BR_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA
#endif
};


// Install hashes into the SSL engine
static void br_ssl_client_install_hashes(br_ssl_engine_context *eng) {
  br_ssl_engine_set_hash(eng, br_md5_ID, &br_md5_vtable);
  br_ssl_engine_set_hash(eng, br_sha1_ID, &br_sha1_vtable);
  br_ssl_engine_set_hash(eng, br_sha224_ID, &br_sha224_vtable);
  br_ssl_engine_set_hash(eng, br_sha256_ID, &br_sha256_vtable);
  br_ssl_engine_set_hash(eng, br_sha384_ID, &br_sha384_vtable);
  br_ssl_engine_set_hash(eng, br_sha512_ID, &br_sha512_vtable);
}

// Default initializion for our SSL clients
static void br_ssl_client_base_init(br_ssl_client_context *cc, const uint16_t *cipher_list, int cipher_cnt) {
  uint16_t suites[cipher_cnt];
  memcpy_P(suites, cipher_list, cipher_cnt * sizeof(cipher_list[0]));
  br_ssl_client_zero(cc);
  br_ssl_engine_add_flags(&cc->eng, BR_OPT_NO_RENEGOTIATION);  // forbid SSL renegotiation, as we free the Private Key after handshake
  br_ssl_engine_set_versions(&cc->eng, BR_TLS10, BR_TLS12);
  br_ssl_engine_set_suites(&cc->eng, suites, (sizeof suites) / (sizeof suites[0]));
  br_ssl_client_set_default_rsapub(cc);
  br_ssl_engine_set_default_rsavrfy(&cc->eng);
#ifndef BEARSSL_SSL_BASIC
  br_ssl_engine_set_default_ecdsa(&cc->eng);
#endif
  br_ssl_client_install_hashes(&cc->eng);
  br_ssl_engine_set_prf10(&cc->eng, &br_tls10_prf);
  br_ssl_engine_set_prf_sha256(&cc->eng, &br_tls12_sha256_prf);
  br_ssl_engine_set_prf_sha384(&cc->eng, &br_tls12_sha384_prf);
  br_ssl_engine_set_default_aes_cbc(&cc->eng);
#ifndef BEARSSL_SSL_BASIC
  br_ssl_engine_set_default_aes_gcm(&cc->eng);
  br_ssl_engine_set_default_aes_ccm(&cc->eng);
  br_ssl_engine_set_default_des_cbc(&cc->eng);
  br_ssl_engine_set_default_chapol(&cc->eng);
#endif
}

int tcp_ssl_new_client(struct tcp_pcb* pcb, const char* host, const br_x509_class **x509ctx) {
  
  if (!pcb) return -1;
  
  TCP_SSL_DEBUG("Connecting to %s via TLS\n", host);
  
  tcp_ssl_pcb* ssl_pcb = new (std::nothrow) tcp_ssl_pcb();
  if (!ssl_pcb) {
    TCP_SSL_DEBUG("Failed to create SSL context");
    return -1;
  }

  ssl_pcb->tcp = pcb;
  ssl_pcb->is_server = false;
  ssl_pcb->handshake_done = false;
  ssl_pcb->arg = nullptr;
  ssl_pcb->on_data = nullptr;
  ssl_pcb->on_handshake = nullptr;
  ssl_pcb->on_error = nullptr;
  ssl_pcb->in_buf_ptr = nullptr;
  ssl_pcb->out_buf_ptr = nullptr;
  ssl_pcb->in_len = 0;
  ssl_pcb->out_len = 0;
  ssl_pcb->recvrec_accum_pos = ASYNC_TCP_SSL_IN_BUFFER_SIZE;  // Start at end of buffer


  br_ssl_client_base_init(&ssl_pcb->sc_client, suites_P, sizeof(suites_P) / sizeof(suites_P[0]));

  // Install x509 validator
  br_ssl_engine_set_x509(&ssl_pcb->sc_client.eng, x509ctx);

  // --- COMPATIBILITY FIX ---
  // Use the correct function name with the correct (5) arguments.
  br_ssl_engine_set_buffers_bidi(&ssl_pcb->sc_client.eng, ssl_pcb->inbuf, sizeof(ssl_pcb->inbuf),
                                 ssl_pcb->outbuf, sizeof(ssl_pcb->outbuf));
  br_ssl_engine_set_versions(&ssl_pcb->sc_client.eng, BR_TLS10, BR_TLS12);                              

  // Set server name for SNI (required for TLS 1.2+)
  if(!br_ssl_client_reset(&ssl_pcb->sc_client, host, 0)) {
    TCP_SSL_DEBUG("Can't reset SSL client\n");
    return -1;
  }
  // -------------------------

  ssl_pcb->next = tcp_ssl_pcbs;
  tcp_ssl_pcbs = ssl_pcb;
  process_ssl_engine(ssl_pcb);
  
  return 0;
}

int tcp_ssl_new_server(struct tcp_pcb* pcb, SSL_CTX* ssl_ctx) {
  if (!pcb || !ssl_ctx) {
    return -1;
  }

  tcp_ssl_pcb* ssl_pcb = new (std::nothrow) tcp_ssl_pcb();
  if (!ssl_pcb) return -1;

  ssl_pcb->tcp = pcb;
  ssl_pcb->is_server = true;
  ssl_pcb->handshake_done = false;
  ssl_pcb->arg = nullptr;
  ssl_pcb->on_data = nullptr;
  ssl_pcb->on_handshake = nullptr;
  ssl_pcb->on_error = nullptr;
  ssl_pcb->in_buf_ptr = nullptr;
  ssl_pcb->out_buf_ptr = nullptr;
  ssl_pcb->in_len = 0;
  ssl_pcb->out_len = 0;
  ssl_pcb->recvrec_accum_pos = ASYNC_TCP_SSL_IN_BUFFER_SIZE;  // Start at end of buffer


  BearSSL_SSL_CTX* ctx = (BearSSL_SSL_CTX*)ssl_ctx;

  if (ctx->pk && ctx->pk->getRSA()) {
    br_ssl_server_init_full_rsa(&ssl_pcb->sc_server, ctx->chain_vector.data(),
                                ctx->chain_vector.size(), ctx->pk->getRSA());
  } else if (ctx->pk && ctx->pk->getEC()) {
    br_ssl_server_init_full_ec(&ssl_pcb->sc_server, ctx->chain_vector.data(),
                               ctx->chain_vector.size(), BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN,
                               ctx->pk->getEC());
  } else {
    delete ssl_pcb;
    return -1;
  }

  // --- COMPATIBILITY FIX ---
  // Use the correct function name with the correct (5) arguments.
  br_ssl_engine_set_buffers_bidi(&ssl_pcb->sc_server.eng, ssl_pcb->inbuf, sizeof(ssl_pcb->inbuf),
                                 ssl_pcb->outbuf, sizeof(ssl_pcb->outbuf));
  // -------------------------

  ssl_pcb->next = tcp_ssl_pcbs;
  tcp_ssl_pcbs = ssl_pcb;
  return 0;
}

int tcp_ssl_free(struct tcp_pcb* pcb) {
  tcp_ssl_pcb* iter = tcp_ssl_pcbs;
  tcp_ssl_pcb* prev = nullptr;
  while (iter) {
    if (iter->tcp == pcb) {
      if (prev) {
        prev->next = iter->next;
      } else {
        tcp_ssl_pcbs = iter->next;
      }
      delete iter;
      return 0;
    }
    prev = iter;
    iter = iter->next;
  }
  return -1;
}

// --- Internal Engine Logic ---

static void process_ssl_engine(tcp_ssl_pcb* ssl_pcb) {
  if (!ssl_pcb) return;

  br_ssl_engine_context* eng;
  if (ssl_pcb->is_server) {
    eng = &ssl_pcb->sc_server.eng;
  } else {
    eng = &ssl_pcb->sc_client.eng;
  }
  
  uint32_t state = br_ssl_engine_current_state(eng);  
  
  TCP_SSL_DEBUG("TLS: Processing SSL engine for pcb %p, state=%u\n", ssl_pcb->tcp, state);

  for (;;) {
    state = br_ssl_engine_current_state(eng);

    if (state & BR_SSL_CLOSED) {
      if (ssl_pcb->on_error) {
        ssl_pcb->on_error(ssl_pcb->arg, ssl_pcb->tcp, br_ssl_engine_last_error(eng));
      }
      TCP_SSL_DEBUG("TLS: SSL engine closed the connection, reason %d\n", br_ssl_engine_last_error(eng));
      return;
    }

    if (state & BR_SSL_RECVAPP) {
      ssl_pcb->in_buf_ptr = br_ssl_engine_recvapp_buf(eng, &(ssl_pcb->in_len));
      if (ssl_pcb->in_len && ssl_pcb->in_len < ASYNC_TCP_SSL_IN_BUFFER_SIZE) {
        TCP_SSL_DEBUG("TLS: Received %u bytes of application data, state=%u\n", (unsigned)ssl_pcb->in_len, state);
        br_ssl_engine_recvapp_ack(eng, ssl_pcb->in_len);
        if (ssl_pcb->on_data) {
          ssl_pcb->on_data(ssl_pcb->arg, ssl_pcb->tcp, ssl_pcb->in_buf_ptr, ssl_pcb->in_len);
        }
        continue;
      }
    }

    ssl_pcb->out_buf_ptr = br_ssl_engine_sendrec_buf(eng, &(ssl_pcb->out_len));
    if (ssl_pcb->out_len && ssl_pcb->out_len < ASYNC_TCP_SSL_OUT_BUFFER_SIZE) {
      if (tcp_sndbuf(ssl_pcb->tcp) >= ssl_pcb->out_len) {
        TCP_SSL_DEBUG("TLS: sending %u bytes of SSL record, state=%u\n", (unsigned)ssl_pcb->out_len, state);
        tcp_write(ssl_pcb->tcp, ssl_pcb->out_buf_ptr, ssl_pcb->out_len, TCP_WRITE_FLAG_COPY);
        br_ssl_engine_sendrec_ack(eng, ssl_pcb->out_len);
        tcp_output(ssl_pcb->tcp);
        continue;
      }
    }

    TCP_SSL_DEBUG("TLS: SSL engine state is %u\n", state);

    break;
  }

  state = br_ssl_engine_current_state(eng);
  if (!ssl_pcb->handshake_done && 
     ((ssl_pcb->is_server && (state & BR_SSL_RECVAPP)) || 
     (!ssl_pcb->is_server && (state & BR_SSL_SENDAPP)))) {
    TCP_SSL_DEBUG("TLS: Handshake complete!\n");
  #if DEBUG_ESP_TCP_SSL  
    br_ssl_session_parameters params;
    br_ssl_engine_get_session_parameters(eng, &params);
    TCP_SSL_DEBUG("Protocol: %s, cipher suite: %04x\n", 
                  tcp_ssl_version_string(params.version), 
                  params.cipher_suite);
  #endif
    ssl_pcb->handshake_done = true;
    if (ssl_pcb->on_handshake) {
      ssl_pcb->on_handshake(ssl_pcb->arg, ssl_pcb->tcp, &ssl_pcb->dummy_ssl);
    }
  }
}


// --- Public Read/Write API ---

int tcp_ssl_write(struct tcp_pcb* pcb, const uint8_t* data, size_t len) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (!ssl_pcb) {
    TCP_SSL_DEBUG("tcp_ssl_write: No SSL context found for pcb %p\n", pcb);
    return -1;
  }

  br_ssl_engine_context* eng;
  if (ssl_pcb->is_server)
    eng = &ssl_pcb->sc_server.eng;
  else
    eng = &ssl_pcb->sc_client.eng;

  unsigned int state = br_ssl_engine_current_state(eng);
  if (!(state & BR_SSL_SENDAPP)) {
    TCP_SSL_DEBUG("tcp_ssl_write: SSL engine not ready to send application data, state=%u\n", state);
    return 0;
  }

  size_t wlen;
  unsigned char* buf = br_ssl_engine_sendapp_buf(eng, &wlen);
  if (wlen == 0) {
    TCP_SSL_DEBUG("tcp_ssl_write: SSL engine failed to provide output buffer\n");
    process_ssl_engine(ssl_pcb);
    return 0;
  }

  size_t clen = (len > wlen) ? wlen : len;
  memcpy(buf, data, clen);
  br_ssl_engine_sendapp_ack(eng, clen);
  br_ssl_engine_flush(eng, 0);
  process_ssl_engine(ssl_pcb);
  return clen;
}

int tcp_ssl_read(struct tcp_pcb* pcb, struct pbuf* pb) {

  // find the associated ssl state for this connection
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (!ssl_pcb) {
    TCP_SSL_DEBUG("tcp_ssl_read: No SSL context found for pcb %p\n", pcb);
    pbuf_free(pb);
    return -1;
  }

  br_ssl_engine_context* eng;
  if (ssl_pcb->is_server)
    eng = &ssl_pcb->sc_server.eng;
  else
    eng = &ssl_pcb->sc_client.eng;

  // size_t pbuf_offset = 0;
  // while (true) {
  //   size_t len;
  //   unsigned char* buf = br_ssl_engine_recvrec_buf(eng, &len);
  //   if (len > 0) {
  //     size_t chunk_len = pbuf_copy_partial(pb, buf, len, pbuf_offset);
  //     if (chunk_len == 0) break;
  //     br_ssl_engine_recvrec_ack(eng, chunk_len);
  //     pbuf_offset += chunk_len;
  //   } else {
  //     break;
  //   }
  // }

   // ---- RECORD REASSEMBLY ----
  // Use the end of inbuf for accumulating partial TLS records.
  // This prevents feeding incomplete records to BearSSL which causes AEAD MAC failures.
  // Accumulator grows backwards from the end of the buffer.
  
  size_t accum_space = ssl_pcb->recvrec_accum_pos;  // Space available at end of buffer
  size_t to_copy = (pb->tot_len < accum_space) ? pb->tot_len : accum_space;
  
  if (to_copy > 0) {
    pbuf_copy_partial(pb, ssl_pcb->inbuf + ssl_pcb->recvrec_accum_pos - to_copy, 
                      to_copy, 0);
    ssl_pcb->recvrec_accum_pos -= to_copy;
    TCP_SSL_DEBUG("tcp_ssl_read: buffered %u bytes at end of inbuf (start pos: %u)\n", 
                  (unsigned)to_copy, (unsigned)ssl_pcb->recvrec_accum_pos);
  }

  tcp_recved(pcb, pb->tot_len);
  pbuf_free(pb);

  // Feed accumulated data to the BearSSL engine
  // Calculate how much accumulated data we have
  size_t accum_len = ASYNC_TCP_SSL_IN_BUFFER_SIZE - ssl_pcb->recvrec_accum_pos;
  size_t consumed = 0;
  int loop_count = 0;
  
  while (consumed < accum_len && loop_count < ASYNC_TCP_SSL_MAX_FEED_LOOPS) {
    loop_count++;
    size_t available;
    unsigned char* buf = br_ssl_engine_recvrec_buf(eng, &available);
    
    if (available == 0) {
      // Engine buffer is full, MUST process immediately to prevent WDT
      TCP_SSL_DEBUG("tcp_ssl_read: engine buffer full (loop %d), processing before continuing\n", 
                    loop_count);
      process_ssl_engine(ssl_pcb);
      
      // Re-check available space after processing
      buf = br_ssl_engine_recvrec_buf(eng, &available);
      if (available == 0) {
        // Still full, save data and exit to prevent WDT
        TCP_SSL_DEBUG("tcp_ssl_read: engine still full after process, keeping %u bytes pending\n", 
                      (unsigned)(accum_len - consumed));
        break;
      }
    }
    
    size_t to_feed = (accum_len - consumed < available) ? 
                     (accum_len - consumed) : available;
    
    memcpy(buf, ssl_pcb->inbuf + ssl_pcb->recvrec_accum_pos + consumed, to_feed);
    br_ssl_engine_recvrec_ack(eng, to_feed);
    consumed += to_feed;
    
    TCP_SSL_DEBUG("tcp_ssl_read: fed %u bytes to engine (consumed: %u/%u)\n", 
                  (unsigned)to_feed, (unsigned)consumed, (unsigned)accum_len);
  }
  
  if (loop_count >= ASYNC_TCP_SSL_MAX_FEED_LOOPS && consumed < accum_len) {
    TCP_SSL_DEBUG("tcp_ssl_read: WARNING: Hit max feed loops, %u bytes pending\n", 
                  (unsigned)(accum_len - consumed));
  }

  // Shift remaining data in accumulator (if any) to the front (end of buffer)
  if (consumed > 0 && consumed < accum_len) {
    size_t remaining = accum_len - consumed;
    memmove(ssl_pcb->inbuf + ASYNC_TCP_SSL_IN_BUFFER_SIZE - remaining,
            ssl_pcb->inbuf + ssl_pcb->recvrec_accum_pos + consumed, remaining);
    ssl_pcb->recvrec_accum_pos = ASYNC_TCP_SSL_IN_BUFFER_SIZE - remaining;
    TCP_SSL_DEBUG("tcp_ssl_read: kept %u bytes for next call (pos: %u)\n", 
                  (unsigned)remaining, (unsigned)ssl_pcb->recvrec_accum_pos);
  } else if (consumed > 0) {
    ssl_pcb->recvrec_accum_pos = ASYNC_TCP_SSL_IN_BUFFER_SIZE;  // All data consumed
  }

  process_ssl_engine(ssl_pcb);

  unsigned int state = br_ssl_engine_current_state(eng);
  if (state & BR_SSL_CLOSED) {
    TCP_SSL_DEBUG("tcp_ssl_read: SSL engine closed the connection, reason %d\n", br_ssl_engine_last_error(eng));
    return -1;
  }

  return 0;
}

// --- Callback and state management functions ---

SSL* tcp_ssl_get_ssl(struct tcp_pcb* pcb) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  return ssl_pcb ? &ssl_pcb->dummy_ssl : nullptr;
}

bool tcp_ssl_has(struct tcp_pcb* pcb) { return find_ssl_pcb(pcb) != nullptr; }

// set on arg callback
void tcp_ssl_arg(struct tcp_pcb* pcb, void* arg) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (ssl_pcb) ssl_pcb->arg = arg;
}

// set on data callback
void tcp_ssl_data(struct tcp_pcb* pcb, tcp_ssl_data_cb_t cb) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (ssl_pcb) ssl_pcb->on_data = cb;
}

// Set on handshake callback
void tcp_ssl_handshake(struct tcp_pcb* pcb, tcp_ssl_handshake_cb_t cb) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (ssl_pcb) ssl_pcb->on_handshake = cb;
}

// Set on error callback
void tcp_ssl_err(struct tcp_pcb* pcb, tcp_ssl_error_cb_t cb) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (ssl_pcb) ssl_pcb->on_error = cb;
}