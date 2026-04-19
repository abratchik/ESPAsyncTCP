#include "ESPAsyncTCPClient.h"

#if DEBUG_ESP_ASYNC_TCP
static size_t _connectionCount = 0;
#endif

#if ASYNC_TCP_SSL_ENABLED
AsyncClient::AsyncClient(tcp_pcb* pcb, SSL_CTX* ssl_ctx)
#else
AsyncClient::AsyncClient(tcp_pcb* pcb)
#endif
    :
      prev(NULL),
      next(NULL),
      _pcb(pcb),
      _connect_cb(0),
      _connect_cb_arg(0),
      _discard_cb(0),
      _discard_cb_arg(0),
      _sent_cb(0),
      _sent_cb_arg(0),
      _error_cb(0),
      _error_cb_arg(0),
      _recv_cb(0),
      _recv_cb_arg(0),
      _pb_cb(0),
      _pb_cb_arg(0),
      _timeout_cb(0),
      _timeout_cb_arg(0),
      _poll_cb(0),
      _poll_cb_arg(0),
      _pcb_busy(false),
      _pcb_sent_at(0),
      _close_pcb(false),
      _ack_pcb(true),
      _tx_unacked_len(0),
      _tx_acked_len(0),
      _rx_ack_len(0),
      _rx_last_packet(0),
      _rx_since_timeout(0),
      _ack_timeout(ASYNC_MAX_ACK_TIME),
      _connect_port(0),
      _recv_pbuf_flags(0),
      _errorTracker(std::make_shared<ACErrorTracker>(this))
#if ASYNC_TCP_SSL_ENABLED
      ,
      _use_tls(false),
      _ssl_auth_mode((AcSSLAuthMode)ASYNC_TCP_SSL_X509_MODE),
      _handshake_done(false)
#endif
  {
    if (_pcb) {
      _rx_last_packet = millis();
      tcp_setprio(_pcb, TCP_PRIO_MIN);
      tcp_arg(_pcb, this);
      tcp_recv(_pcb, &_s_recv);
      tcp_sent(_pcb, &_s_sent);
      tcp_err(_pcb, &_s_error);
      tcp_poll(_pcb, &_s_poll, 1);
#if ASYNC_TCP_SSL_ENABLED
      if (ssl_ctx) {
        if (tcp_ssl_new_server(_pcb, ssl_ctx) < 0) {
          _close();
          return;
        }
        tcp_ssl_arg(_pcb, this);
        tcp_ssl_data(_pcb, &_s_data);
        tcp_ssl_handshake(_pcb, &_s_handshake);
        tcp_ssl_err(_pcb, &_s_ssl_error);
      }
#endif
    }

#if DEBUG_ESP_ASYNC_TCP
    _errorTracker->setConnectionId(++_connectionCount);
#endif
}

AsyncClient::~AsyncClient() {
  if (_pcb) _close();
#if ASYNC_TCP_SSL_ENABLED
  if(_use_tls)
    _errorTracker->clearClient();
#endif
}

inline void clearTcpCallbacks(tcp_pcb* pcb) {
  tcp_arg(pcb, NULL);
  tcp_sent(pcb, NULL);
  tcp_recv(pcb, NULL);
  tcp_err(pcb, NULL);
  tcp_poll(pcb, NULL, 0);
}

#if ASYNC_TCP_SSL_ENABLED
bool AsyncClient::connect(IPAddress ip, uint16_t port, bool use_tls) {
  _use_tls = use_tls;
#else
bool AsyncClient::connect(IPAddress ip, uint16_t port) {
#endif
  if (connected()) { 
    // already connected
    ASYNC_TCP_DEBUG("connect[%u]: Already connected to %s:%u\n", getConnectionId(), ip.toString().c_str(), port);
    return false;
  }
  ASYNC_TCP_DEBUG("connect[%u]: Connecting to %s:%u\n", getConnectionId(), ip.toString().c_str(), port);
  IPAddress addr;
  addr = ip;
#if LWIP_VERSION_MAJOR == 1
  netif* interface = ip_route(&addr);
  if (!interface) {  // no route to host
    ASYNC_TCP_DEBUG("connect[%u]: No route to host %s\n", getConnectionId(), ip.toString().c_str());
    return false;
  }
#endif
  tcp_pcb* pcb = tcp_new();
  if (!pcb) {  // could not allocate pcb
    ASYNC_TCP_DEBUG("connect[%u]: Failed to allocate pcb\n", getConnectionId());
    return false;
  }

  tcp_setprio(pcb, TCP_PRIO_MIN);
#if ASYNC_TCP_SSL_ENABLED
  _handshake_done = false;
#endif
  tcp_arg(pcb, this);
  tcp_err(pcb, &_s_error);
  size_t err = tcp_connect(pcb, addr, port, (tcp_connected_fn)&_s_connected);
  if (ERR_OK == err)
  {
    ASYNC_TCP_DEBUG("connect[%u]: tcp_connect() started to %s:%u\n", getConnectionId(), ip.toString().c_str(), port);
    return true;
  }
  else
  {
    ASYNC_TCP_DEBUG("connect[%u]: tcp_connect() returned err: %s(%ld)\n", getConnectionId(),
                    ACErrorTracker::errorToString(err), err);
    return false;
  }
}

#if ASYNC_TCP_SSL_ENABLED
bool AsyncClient::connect(const char* host, uint16_t port, bool use_tls) {
  _handshake_done = false;
  _host = host;
  _connect_port = port;
  _use_tls = use_tls;
#else
bool AsyncClient::connect(const char* host, uint16_t port) {
  _connect_port = port;
#endif
  IPAddress addr;
  err_t err = dns_gethostbyname(host, addr, (dns_found_callback)&_s_dns_found, this);
  if (err == ERR_OK) {
#if ASYNC_TCP_SSL_ENABLED
    return connect(addr, port, _use_tls);
#else
    return connect(addr, port);
#endif
  } 
  else if (err == ERR_INPROGRESS) {
    return true;
  }
  return false;
}

AsyncClient& AsyncClient::operator=(const AsyncClient& other) {
  if (_pcb) {
    ASYNC_TCP_DEBUG("operator=[%u]: Abandoned _pcb(0x%" PRIXPTR ") forced close.\n",
                    getConnectionId(), uintptr_t(_pcb));
    _close();
  }
  _errorTracker = other._errorTracker;

  // I am confused when "other._pcb" falls out of scope the destructor will
  // close it? TODO: Look to see where this is used and how it might work.
  _pcb = other._pcb;
  if (_pcb) {
    _rx_last_packet = millis();
    tcp_setprio(_pcb, TCP_PRIO_MIN);
    tcp_arg(_pcb, this);
    tcp_recv(_pcb, &_s_recv);
    tcp_sent(_pcb, &_s_sent);
    tcp_err(_pcb, &_s_error);
    tcp_poll(_pcb, &_s_poll, 1);
#if ASYNC_TCP_SSL_ENABLED
    if (tcp_ssl_has(_pcb)) {
      _use_tls = true;
      _handshake_done = false;
      tcp_ssl_arg(_pcb, this);
      tcp_ssl_data(_pcb, &_s_data);
      tcp_ssl_handshake(_pcb, &_s_handshake);
      tcp_ssl_err(_pcb, &_s_ssl_error);
    } 
    else {
      _use_tls = false;
      _handshake_done = true;
    }
#endif
  }
  return *this;
}

bool AsyncClient::operator==(const AsyncClient& other) {
  return (_pcb != NULL && other._pcb != NULL &&
          (IPAddress(_pcb->remote_ip) == IPAddress(other._pcb->remote_ip)) &&
          (_pcb->remote_port == other._pcb->remote_port));
}

void AsyncClient::abort() {
  // Notes:
  // 1) _pcb is set to NULL, so we cannot call tcp_abort() more than once.
  // 2) setCloseError(ERR_ABRT) is only done here!
  // 3) Using this abort() function guarantees only one tcp_abort() call is
  //    made and only one CB returns with ERR_ABORT.
  // 4) After abort() is called from _close(), no callbacks with an err
  //    parameter will be called.  eg. _recv(), _error(), _connected().
  //    _close() will reset there CB handlers before calling.
  // 5) A callback to _error(), will set _pcb to NULL, thus avoiding the
  //    of a 2nd call to tcp_abort().
  // 6) Callbacks to _recv() or _connected() with err set, will result in _pcb
  //    set to NULL. Thus, preventing possible calls later to tcp_abort().
  if (_pcb) {
    tcp_abort(_pcb);
    _pcb = NULL;
    setCloseError(ERR_ABRT);
  }
  return;
}

void AsyncClient::close(bool now) {
  if (_pcb) tcp_recved(_pcb, _rx_ack_len);
  if (now) {
    ASYNC_TCP_DEBUG("close[%u]: AsyncClient 0x%" PRIXPTR "\n", getConnectionId(), uintptr_t(this));
    _close();
  } else {
    _close_pcb = true;
  }
}

size_t AsyncClient::write(const char* data) {
  if (data == NULL) return 0;
  return write(data, strlen(data));
}

size_t AsyncClient::write(const char* data, size_t size, uint8_t apiflags) {
  size_t will_send = add(data, size, apiflags);

  if (!will_send || !send()) return 0;
  return will_send;
}

size_t AsyncClient::add(const char* data, size_t size, uint8_t apiflags) {
  if (!_pcb || size == 0 || data == NULL) {
    ASYNC_TCP_DEBUG("add[%u]: Invalid parameters, _pcb: %s, size: %u, data: %s\n", getConnectionId(),
                    (_pcb ? "valid" : "NULL"), size, (data ? "valid" : "NULL"));
    return 0;
  }
  size_t room = space();
  if (!room) {
    ASYNC_TCP_DEBUG("add[%u]: No space to add data, size: %u\n", getConnectionId(), size);
    return 0;
  }
#if ASYNC_TCP_SSL_ENABLED
  if (_use_tls) {
    int sent = tcp_ssl_write(_pcb, (uint8_t*)data, size);
    if (sent >= 0) {
      _tx_unacked_len += sent;
      return sent;
    }
    _close();
    return 0;
  }
#endif
  size_t will_send = (room < size) ? room : size;
  err_t err = tcp_write(_pcb, data, will_send, apiflags);
  if (err != ERR_OK) {
    ASYNC_TCP_DEBUG("_add[%u]: tcp_write() returned err: %s(%ld)\n", getConnectionId(),
                    ACErrorTracker::errorToString(err), err);
    return 0;
  }
  _tx_unacked_len += will_send;
  return will_send;
}

bool AsyncClient::send() {
#if ASYNC_TCP_SSL_ENABLED
  if (_use_tls) return true;
#endif
  err_t err = tcp_output(_pcb);
  if (err == ERR_OK) {
    _pcb_busy = true;
    _pcb_sent_at = millis();
    return true;
  }

  ASYNC_TCP_DEBUG("send[%u]: tcp_output() returned err: %s(%ld)", getConnectionId(),
                  ACErrorTracker::errorToString(err), err);
  return false;
}

size_t AsyncClient::ack(size_t len) {
  if (len > _rx_ack_len) len = _rx_ack_len;
  if (len) tcp_recved(_pcb, len);
  _rx_ack_len -= len;
  return len;
}

// Private Callbacks

void AsyncClient::_connected(std::shared_ptr<ACErrorTracker>& errorTracker, void* pcb, err_t err) {
  //(void)err; // LWIP v1.4 appears to always call with ERR_OK
  // Documentation for 2.1.0 also says:
  //   "err	- An unused error code, always ERR_OK currently ;-)"
  // https://www.nongnu.org/lwip/2_1_x/tcp_8h.html#a939867106bd492caf2d85852fb7f6ae8
  // Based on that wording and emoji lets just handle it now.
  // After all, the API does allow for an err != ERR_OK.
  if (NULL == pcb || ERR_OK != err) {
    ASYNC_TCP_DEBUG("_connected[%u]:%s err: %s(%ld)\n", errorTracker->getConnectionId(),
                    ((NULL == pcb) ? " NULL == pcb!," : ""), ACErrorTracker::errorToString(err), err);
    errorTracker->setCloseError(err);
    errorTracker->setErrored(EE_CONNECTED_CB);
    _pcb = reinterpret_cast<tcp_pcb*>(pcb);
    if (_pcb) clearTcpCallbacks(_pcb);
    _pcb = NULL;
    _error(err);
    return;
  }

  _pcb = reinterpret_cast<tcp_pcb*>(pcb);
  if (_pcb) {
    _pcb_busy = false;
    _rx_last_packet = millis();
    tcp_setprio(_pcb, TCP_PRIO_MIN);
    tcp_recv(_pcb, &_s_recv);
    tcp_sent(_pcb, &_s_sent);
    tcp_poll(_pcb, &_s_poll, 1);
#if ASYNC_TCP_SSL_ENABLED
    if(_use_tls) {
      int err = ERR_OK;
      if(!_initClientX509Validator()) {
        ASYNC_TCP_DEBUG("Unable to init the x509 validator\n");
        _close();
      }

      if (_ssl_auth_mode & (SSL_AUTH_INSECURE | SSL_AUTH_FINGERPRINT | SSL_AUTH_SELF_SIGNED)) {
        ASYNC_TCP_DEBUG("Connecting %s\n", _ssl_auth_mode & SSL_AUTH_INSECURE? "insecure":
                                      _ssl_auth_mode & SSL_AUTH_FINGERPRINT? "using fingetprint":
                                      _ssl_auth_mode & SSL_AUTH_SELF_SIGNED? "using self-signed certificate":"");
        ASYNC_TCP_DEBUG("Host: %s\n", _host);                    
        err = tcp_ssl_new_client(_pcb, _host, &_x509_insecure->vtable);
      }
      else if(_knownkey && (_ssl_auth_mode & SSL_AUTH_KNOWN_KEY)) {
        ASYNC_TCP_DEBUG("Connecting by known key");
        err = tcp_ssl_new_client(_pcb, _host, &_x509_knownkey->vtable);
      }
      else {
        ASYNC_TCP_DEBUG("Connecting secure");
        err = tcp_ssl_new_client(_pcb, _host, &_x509_minimal->vtable);
      }
        
      if (err != ERR_OK) {
        ASYNC_TCP_DEBUG("_connected[%u]: tcp_ssl_new_client() failed (%d), connection aborted!\n",
                        errorTracker->getConnectionId(), err);
        _close();
        return;
      }

      tcp_ssl_arg(_pcb, this);
      tcp_ssl_data(_pcb, &_s_data);
      tcp_ssl_handshake(_pcb, &_s_handshake);
      tcp_ssl_err(_pcb, &_s_ssl_error);
    }
#endif
  }

  // call the onConnect callback handler
  if (_connect_cb && connected())
    _connect_cb(_connect_cb_arg, this);
  return;
}

void AsyncClient::_close() {
  if (_pcb) {
#if ASYNC_TCP_SSL_ENABLED
    if (_use_tls) {
      tcp_ssl_free(_pcb);
      _x509_minimal = nullptr;
      _x509_insecure = nullptr;
      _x509_knownkey = nullptr;

      // This connection is toast
      _handshake_done = false;
    }
#endif
    clearTcpCallbacks(_pcb);
    err_t err = tcp_close(_pcb);
    if (ERR_OK == err) {
      setCloseError(err);
      ASYNC_TCP_DEBUG("_close[%u]: AsyncClient 0x%" PRIXPTR "\n", getConnectionId(),
                      uintptr_t(this));
    } else {
      ASYNC_TCP_DEBUG("_close[%u]: abort() called for AsyncClient 0x%" PRIXPTR "\n",
                      getConnectionId(), uintptr_t(this));
      abort();
    }
    _pcb = NULL;
    if (_discard_cb) _discard_cb(_discard_cb_arg, this);
  }
  return;
}

void AsyncClient::_error(err_t err) {
  ASYNC_TCP_DEBUG("_error[%u]:%s err: %s(%ld)\n", getConnectionId(),
                  ((NULL == _pcb) ? " NULL == _pcb!," : ""), ACErrorTracker::errorToString(err), err);
  if (_pcb) {
#if ASYNC_TCP_SSL_ENABLED
    if (_use_tls) {
      tcp_ssl_free(_pcb);
    }
#endif
    // At this callback _pcb is possible already freed. Thus, no calls are
    // made to set to NULL other callbacks.
    _pcb = NULL;
  }
  if (_error_cb) _error_cb(_error_cb_arg, this, err);
  if (_discard_cb) _discard_cb(_discard_cb_arg, this);
}


void AsyncClient::_sent(std::shared_ptr<ACErrorTracker>& errorTracker, tcp_pcb* pcb, uint16_t len) {
  (void)pcb;
#if ASYNC_TCP_SSL_ENABLED
  if (_use_tls && !_handshake_done) return;
#endif
  _rx_last_packet = millis();
  _tx_unacked_len -= _tx_unacked_len>len?len:_tx_unacked_len;
  _tx_acked_len += len;
  ASYNC_TCP_DEBUG("_sent[%u]: %4u, unacked=%4u, acked=%4u, space=%4u\n",
                  errorTracker->getConnectionId(), len, _tx_unacked_len, _tx_acked_len, space());
  if (_tx_unacked_len == 0) {
    _pcb_busy = false;
    errorTracker->setCloseError(ERR_OK);
    if (_sent_cb) {
      _sent_cb(_sent_cb_arg, this, _tx_acked_len, (millis() - _pcb_sent_at));
      if (!errorTracker->hasClient()) return;
    }
    _tx_acked_len = 0;
  }
  return;
}

void AsyncClient::_recv(std::shared_ptr<ACErrorTracker>& errorTracker, tcp_pcb* pcb, pbuf* pb,
                        err_t err) {
  // While lwIP v1.4 appears to always call with ERR_OK, 2.x lwIP may present
  // a non-ERR_OK value.
  // https://www.nongnu.org/lwip/2_1_x/tcp_8h.html#a780cfac08b02c66948ab94ea974202e8
  if (NULL == pcb || ERR_OK != err) {
    ASYNC_TCP_DEBUG("_recv[%u]:%s err: %s(%ld)\n", errorTracker->getConnectionId(),
                    ((NULL == pcb) ? " NULL == pcb!," : ""), ACErrorTracker::errorToString(err), err);
    ASYNC_TCP_ASSERT(ERR_ABRT != err);
    errorTracker->setCloseError(err);
    errorTracker->setErrored(EE_RECV_CB);
    _pcb = pcb;
    if (_pcb) clearTcpCallbacks(_pcb);
    _pcb = NULL;
    // I think we are safe from being called from an interrupt context.
    // Best Hint that calling _error() is safe:
    //    https://www.nongnu.org/lwip/2_1_x/group__lwip__nosys.html
    // "Feed incoming packets to netif->input(pbuf, netif) function from
    // mainloop, not from interrupt context. You can allocate a Packet buffers
    // (PBUF) in interrupt context and put them into a queue which is processed
    // from mainloop."
    // And the description of "Mainloop Mode" option 2:
    //    https://www.nongnu.org/lwip/2_1_x/pitfalls.html
    // "2) Run lwIP in a mainloop. ... lwIP is ONLY called from mainloop
    // callstacks here. The ethernet IRQ has to put received telegrams into a
    // queue which is polled in the mainloop. Ensure lwIP is NEVER called from
    // an interrupt, ...!"
    // Based on these comments I am thinking tcp_recv_fn() is called
    // from somebody's mainloop(), which could only have been reached from a
    // delay like function or the Arduino sketch loop() function has returned.
    // What I don't want is for the client sketch to delete the AsyncClient
    // object via _error() while it is in the middle of using it. However,
    // the client sketch must always test that the connection is still up
    // at loop() entry and after the return of any function call, that may
    // have done a delay() or yield().
    _error(err);
    return;
  }

  if (pb == NULL) {
    ASYNC_TCP_DEBUG("_recv[%u]: pb == NULL! Closing... %ld\n", errorTracker->getConnectionId(),
                    err);
    _close();
    return;
  }
  _rx_last_packet = millis();
  errorTracker->setCloseError(ERR_OK);
#if ASYNC_TCP_SSL_ENABLED
  if (_use_tls) {

    ASYNC_TCP_DEBUG("ssl_recv[%u]: %d\n", getConnectionId(), pb->tot_len);
    int read_bytes = tcp_ssl_read(pcb, pb);
    if (read_bytes < 0) {
      ASYNC_TCP_DEBUG("ssl_recv[%u] err: %d\n", getConnectionId(), read_bytes);
      _close();
    }
    return;
  }
#endif
  while (pb != NULL) {
    // IF this callback function returns ERR_OK or ERR_ABRT
    // then it is assummed we freed the pbufs.
    // https://www.nongnu.org/lwip/2_1_x/group__tcp__raw.html#ga8afd0b316a87a5eeff4726dc95006ed0
    if (!errorTracker->hasClient()) {
      while (pb != NULL) {
        pbuf* b = pb;
        pb = b->next;
        b->next = NULL;
        pbuf_free(b);
      }
      return;
    }
    // we should not ack before we assimilate the data
    _ack_pcb = true;
    pbuf* b = pb;
    pb = b->next;
    b->next = NULL;
    ASYNC_TCP_DEBUG("_recv[%u]: %d%s\n", errorTracker->getConnectionId(), b->len,
                    (b->flags & PBUF_FLAG_PUSH) ? ", PBUF_FLAG_PUSH" : "");
    if (_pb_cb) {
      _pb_cb(_pb_cb_arg, this, b);
    } else {
      if (_recv_cb) {
        _recv_pbuf_flags = b->flags;
        _recv_cb(_recv_cb_arg, this, b->payload, b->len);
      }
      if (errorTracker->hasClient()) {
        if (!_ack_pcb)
          _rx_ack_len += b->len;
        else
          tcp_recved(pcb, b->len);
      }
      pbuf_free(b);
    }
  }
  return;
}

void AsyncClient::_poll(std::shared_ptr<ACErrorTracker>& errorTracker, tcp_pcb* pcb) {
  (void)pcb;
  errorTracker->setCloseError(ERR_OK);

  // Close requested
  if (_close_pcb) {
    ASYNC_TCP_DEBUG("_poll[%u]: Process _close_pcb.\n", errorTracker->getConnectionId());
    _close_pcb = false;
    _close();
    return;
  }
  uint32_t now = millis();

  // ACK Timeout
  if (_pcb_busy && _ack_timeout && (now - _pcb_sent_at) >= _ack_timeout) {
    _pcb_busy = false;
    if (_timeout_cb) _timeout_cb(_timeout_cb_arg, this, (now - _pcb_sent_at));
    return;
  }
  // RX Timeout
  if (_rx_since_timeout && (now - _rx_last_packet) >= (_rx_since_timeout * 1000)) {
    ASYNC_TCP_DEBUG("_poll[%u]: RX Timeout.\n", errorTracker->getConnectionId());
    _close();
    return;
  }
#if ASYNC_TCP_SSL_ENABLED
  // SSL Handshake Timeout
  if (_use_tls && !_handshake_done && (now - _rx_last_packet) >= TCP_SSL_HANDSHAKE_TIMEOUT) {
    ASYNC_TCP_DEBUG("_poll[%u]: SSL Handshake Timeout.\n", errorTracker->getConnectionId());
    _close();
    return;
  }
#endif
  // Everything is fine
  if (_poll_cb) _poll_cb(_poll_cb_arg, this);
  return;
}

#if LWIP_VERSION_MAJOR == 1
void AsyncClient::_dns_found(struct ip_addr* ipaddr) {
#else
void AsyncClient::_dns_found(const ip_addr* ipaddr) {
#endif
  if (ipaddr) {
#if ASYNC_TCP_SSL_ENABLED
    connect(ipaddr, _connect_port, _use_tls);
#else
    connect(ipaddr, _connect_port);
#endif
  } else {
    if (_error_cb) _error_cb(_error_cb_arg, this, -55);
    if (_discard_cb) _discard_cb(_discard_cb_arg, this);
  }
}

// lwIP Callbacks
#if LWIP_VERSION_MAJOR == 1
void AsyncClient::_s_dns_found(const char* name, ip_addr_t* ipaddr, void* arg) {
#else
void AsyncClient::_s_dns_found(const char* name, const ip_addr* ipaddr, void* arg) {
#endif
  (void)name;
  reinterpret_cast<AsyncClient*>(arg)->_dns_found(ipaddr);
}

err_t AsyncClient::_s_poll(void* arg, struct tcp_pcb* tpcb) {
  AsyncClient* c = reinterpret_cast<AsyncClient*>(arg);
  std::shared_ptr<ACErrorTracker> errorTracker = c->getACErrorTracker();
  c->_poll(errorTracker, tpcb);
  return errorTracker->getCallbackCloseError();
}

err_t AsyncClient::_s_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* pb, err_t err) {
  AsyncClient* c = reinterpret_cast<AsyncClient*>(arg);
  auto errorTracker = c->getACErrorTracker();
  c->_recv(errorTracker, tpcb, pb, err);
  return errorTracker->getCallbackCloseError();
}

void AsyncClient::_s_error(void* arg, err_t err) {
  AsyncClient* c = reinterpret_cast<AsyncClient*>(arg);
  auto errorTracker = c->getACErrorTracker();
  errorTracker->setCloseError(err);
  errorTracker->setErrored(EE_ERROR_CB);
  c->_error(err);
}

err_t AsyncClient::_s_sent(void* arg, struct tcp_pcb* tpcb, uint16_t len) {
  AsyncClient* c = reinterpret_cast<AsyncClient*>(arg);
  auto errorTracker = c->getACErrorTracker();
  c->_sent(errorTracker, tpcb, len);
  return errorTracker->getCallbackCloseError();
}

err_t AsyncClient::_s_connected(void* arg, void* tpcb, err_t err) {
  AsyncClient* c = reinterpret_cast<AsyncClient*>(arg);
  auto errorTracker = c->getACErrorTracker();
  c->_connected(errorTracker, tpcb, err);
  return errorTracker->getCallbackCloseError();
}

#if ASYNC_TCP_SSL_ENABLED
void AsyncClient::_s_data(void* arg, struct tcp_pcb* tcp, uint8_t* data, size_t len) {
  (void)tcp;
  AsyncClient* c = reinterpret_cast<AsyncClient*>(arg);
  if (c->_recv_cb) c->_recv_cb(c->_recv_cb_arg, c, data, len);
}

void AsyncClient::_s_handshake(void* arg, struct tcp_pcb* tcp, SSL* ssl) {
  (void)tcp;
  (void)ssl;
  AsyncClient* c = reinterpret_cast<AsyncClient*>(arg);
  c->_handshake_done = true;
  if (c->_connect_cb) c->_connect_cb(c->_connect_cb_arg, c);
}

void AsyncClient::_s_ssl_error(void* arg, struct tcp_pcb* tcp, int8_t err) {
  (void)tcp;
#ifdef DEBUG_ESP_ASYNC_TCP
  AsyncClient* c = reinterpret_cast<AsyncClient*>(arg);
  auto errorTracker = c->getACErrorTracker();
  ASYNC_TCP_DEBUG("_ssl_error[%u] err = %d\n", errorTracker->getConnectionId(), err);
#endif
  reinterpret_cast<AsyncClient*>(arg)->_ssl_error(err);
}
#endif

// Operators

AsyncClient& AsyncClient::operator+=(const AsyncClient& other) {
  if (next == NULL) {
    next = (AsyncClient*)(&other);
    next->prev = this;
  } else {
    AsyncClient* c = next;
    while (c->next != NULL) c = c->next;
    c->next = (AsyncClient*)(&other);
    c->next->prev = c;
  }
  return *this;
}

void AsyncClient::setNoDelay(bool nodelay) {
  if (!_pcb) return;
  if (nodelay)
    tcp_nagle_disable(_pcb);
  else
    tcp_nagle_enable(_pcb);
}


#if ASYNC_TCP_SSL_ENABLED

void AsyncClient::load_ca_certs_from_pem(FS* fs, const char* path ) {
  Serial.printf_P(PSTR("Loading CA certs from PEM file: %s\n"), path);

  File f = fs->open(path, "r");
  if (!f) {
    Serial.println("Failed to open CA certs file");
    return; 
  }

  _ca_certs = new BearSSL::X509List(f);

  if(_ca_certs)
    Serial.printf_P(PSTR("Loaded %d CA cert(s) from PEM file\n"), _ca_certs->getCount());
  else
    Serial.println(F("Failed to load ca_certs from PEM file"));
 
  f.close();
}

// Installs the appropriate X509 cert validation method for a client connection
bool AsyncClient::_initClientX509Validator() {
  if (_ssl_auth_mode & (SSL_AUTH_INSECURE | SSL_AUTH_FINGERPRINT | SSL_AUTH_SELF_SIGNED)) {
    // Use common insecure x509 authenticator
    _x509_insecure = std::make_shared<x509_insecure_context>();
    if (!_x509_insecure) {
      ASYNC_TCP_DEBUG("_initClientX509Validator: OOM for _x509_insecure\n");
      return false;
    }
    br_x509_insecure_init(_x509_insecure.get(), 
                          _ssl_auth_mode & SSL_AUTH_FINGERPRINT, _fingerprint, 
                          _ssl_auth_mode & SSL_AUTH_SELF_SIGNED);
  } else if (_knownkey && (_ssl_auth_mode & SSL_AUTH_KNOWN_KEY)) {
    // Simple, pre-known public key authenticator, ignores cert completely.
    _x509_knownkey = std::make_shared<br_x509_knownkey_context>();
    if (!_x509_knownkey) {
      ASYNC_TCP_DEBUG("_initClientX509Validator: OOM for _x509_knownkey\n");
      return false;
    }
    if (_knownkey->isRSA()) {
      br_x509_knownkey_init_rsa(_x509_knownkey.get(), _knownkey->getRSA(), _knownkey_usages);
    } else if (_knownkey->isEC()) {
#ifndef BEARSSL_SSL_BASIC
      br_x509_knownkey_init_ec(_x509_knownkey.get(), _knownkey->getEC(), _knownkey_usages);
#else
      (void) _knownkey;
      (void) _knownkey_usages;
      ASYNC_TCP_DEBUG("_initClientX509Validator: Attempting to use EC keys in minimal cipher mode (no EC)\n");
      return false;
#endif
    }
  } else {
    // X509 minimal validator.  Checks dates, cert chain for trusted CA, etc.
    _x509_minimal = std::make_shared<br_x509_minimal_context>();
    if (!_x509_minimal) {
      ASYNC_TCP_DEBUG("_initClientX509Validator: OOM for _x509_minimal\n");
      return false;
    }
    if(!_ca_certs || _ca_certs->getCount() == 0 ) {
      ASYNC_TCP_DEBUG("No trust anchors loaded, connection aborted!\n");
      return false;
    }
    br_x509_minimal_init(_x509_minimal.get(), 
                         &br_sha256_vtable, _ca_certs ? _ca_certs->getTrustAnchors() : nullptr, 
                         _ca_certs ? _ca_certs->getCount() : 0);

  }
  return true;
}

void AsyncClient::_clearAuthenticationSettings() {
  _ssl_auth_mode = (AcSSLAuthMode)SSL_AUTH_SECURE;
  _knownkey = nullptr;
}

static uint8_t htoi (unsigned char c)
{
  if (c>='0' && c <='9') return c - '0';
  else if (c>='A' && c<='F') return 10 + c - 'A';
  else if (c>='a' && c<='f') return 10 + c - 'a';
  else return 255;
}

// Set a fingerprint by parsing an ASCII string
bool AsyncClient::setFingerprint(const char *fpStr) {
  int idx = 0;
  uint8_t c, d;
  uint8_t fp[20];

  while (idx < 20) {
    c = pgm_read_byte(fpStr++);
    if (!c) break; // String ended, done processing
    d = pgm_read_byte(fpStr++);
    if (!d) {
      TCP_SSL_DEBUG("setFingerprint: FP too short\n");
      return false; // Only half of the last hex digit, error
    }
    c = htoi(c);
    d = htoi(d);
    if ((c>15) || (d>15)) {
      TCP_SSL_DEBUG("setFingerprint: Invalid char\n");
      return false; // Error in one of the hex characters
    }
    fp[idx++] = (c<<4)|d;

    // Skip 0 or more spaces or colons
    while ( pgm_read_byte(fpStr) && (pgm_read_byte(fpStr)==' ' || pgm_read_byte(fpStr)==':') ) {
      fpStr++;
    }
  }
  if ((idx != 20) || pgm_read_byte(fpStr)) {
    TCP_SSL_DEBUG("setFingerprint: Garbage at end of fp\n");
    return false; // Garbage at EOL or we didn't have enough hex digits
  }
  return setFingerprint(fp);
}

#endif


bool AsyncClient::connected() {
  if (!_pcb) return false;
#if ASYNC_TCP_SSL_ENABLED
  return _pcb->state == ESTABLISHED && (!_use_tls || _handshake_done);
#else
  return _pcb->state == ESTABLISHED;
#endif
}

size_t AsyncClient::space() {
    if (connected()) {
      uint16_t s = tcp_sndbuf(_pcb);
#if ASYNC_TCP_SSL_ENABLED
      if (_use_tls) {
        return (s >= 128)? s-128:0;  // safe approach
      }
#endif  
      return s;
    }
    return 0; // not connected
}

void AsyncClient::ackPacket(struct pbuf* pb) {
  if (!pb) {
    return;
  }
  tcp_recved(_pcb, pb->len);
  pbuf_free(pb);
}


const char* AsyncClient::stateToString() {
  switch (state()) {
    case 0:
      return "Closed";
    case 1:
      return "Listen";
    case 2:
      return "SYN Sent";
    case 3:
      return "SYN Received";
    case 4:
      return "Established";
    case 5:
      return "FIN Wait 1";
    case 6:
      return "FIN Wait 2";
    case 7:
      return "Close Wait";
    case 8:
      return "Closing";
    case 9:
      return "Last ACK";
    case 10:
      return "Time Wait";
    default:
      return "UNKNOWN";
  }
}
