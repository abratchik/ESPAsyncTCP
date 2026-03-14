#include "ESPAsyncTCPServer.h"

/*
  Async TCP Server
*/
struct pending_pcb {
  tcp_pcb* pcb;
  pbuf* pb;
  struct pending_pcb* next;
};

AsyncServer::AsyncServer(IPAddress addr, uint16_t port)
    : _port(port),
      _addr(addr),
      _noDelay(false),
      _pcb(0),
      _connect_cb(0),
      _connect_cb_arg(0)
#if ASYNC_TCP_SSL_ENABLED
      ,
      // _pending(NULL),
      _ssl_ctx(NULL)
// _file_cb(0),
// _file_cb_arg(0)
#endif
{
#ifdef DEBUG_MORE
  for (size_t i = 0; i < EE_MAX; ++i) _event_count[i] = 0;
#endif
}

AsyncServer::AsyncServer(uint16_t port)
    : _port(port),
      _addr(IP_ANY_TYPE),
      _noDelay(false),
      _pcb(0),
      _connect_cb(0),
      _connect_cb_arg(0)
#if ASYNC_TCP_SSL_ENABLED
      ,
      // _pending(NULL),
      _ssl_ctx(NULL)
// _file_cb(0),
// _file_cb_arg(0)
#endif
{
#ifdef DEBUG_MORE
  for (size_t i = 0; i < EE_MAX; ++i) _event_count[i] = 0;
#endif
}

AsyncServer::~AsyncServer() { end(); }

void AsyncServer::onClient(AcConnectHandler cb, void* arg) {
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

// #if ASYNC_TCP_SSL_ENABLED
// void AsyncServer::onSslFileRequest(AcSSlFileHandler cb, void* arg) {
//   _file_cb = cb;
//   _file_cb_arg = arg;
// }
// #endif

void AsyncServer::begin() {
  if (_pcb) return;

  int8_t err;
  tcp_pcb* pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (!pcb) {
    return;
  }

  tcp_setprio(pcb, TCP_PRIO_MIN);
  IPAddress local_addr;
  local_addr = _addr;
  err = tcp_bind(pcb, local_addr, _port);
  // Failures are ERR_ISCONN or ERR_USE
  if (err != ERR_OK) {
    tcp_close(pcb);
    return;
  }

  tcp_pcb* listen_pcb = tcp_listen(pcb);
  if (!listen_pcb) {
    tcp_close(pcb);
    return;
  }
  _pcb = listen_pcb;
  tcp_arg(_pcb, (void*)this);
  tcp_accept(_pcb, &_s_accept);
}

#if ASYNC_TCP_SSL_ENABLED
void AsyncServer::beginSecure(const char* cert, const char* key, const char* password) {
  if (_ssl_ctx) {
    return;
  }
  _ssl_ctx = tcp_ssl_new_server_ctx(cert, key, password);
  if (_ssl_ctx) {
    begin();
  }
}
#endif

void AsyncServer::end() {
  if (_pcb) {
    // cleanup all connections?
    tcp_arg(_pcb, NULL);
    tcp_accept(_pcb, NULL);
    if (tcp_close(_pcb) != ERR_OK) {
      tcp_abort(_pcb);
    }
    _pcb = NULL;
  }
#if ASYNC_TCP_SSL_ENABLED
  if (_ssl_ctx) {
    delete (BearSSL_SSL_CTX*)_ssl_ctx;
    _ssl_ctx = NULL;
  }
#endif
}

void AsyncServer::setNoDelay(bool nodelay) { _noDelay = nodelay; }

bool AsyncServer::getNoDelay() { return _noDelay; }

uint8_t AsyncServer::status() {
  if (!_pcb) return 0;
  return _pcb->state;
}

err_t AsyncServer::_accept(tcp_pcb* pcb, err_t err) {
  // http://savannah.nongnu.org/bugs/?43739
  if (NULL == pcb || ERR_OK != err) {
    ASYNC_TCP_DEBUG("_accept:%s err: %ld\n", ((NULL == pcb) ? " NULL == pcb!," : ""), err);
    ASYNC_TCP_ASSERT(ERR_ABRT != err);
    return ERR_OK;
  }

  if (_connect_cb) {
#if ASYNC_TCP_SSL_ENABLED
    if (_noDelay || _ssl_ctx)
#else
    if (_noDelay)
#endif
      tcp_nagle_disable(pcb);
    else
      tcp_nagle_enable(pcb);

#if ASYNC_TCP_SSL_ENABLED
    if (_ssl_ctx) {
      AsyncClient* c = new (std::nothrow) AsyncClient(pcb, _ssl_ctx);
      if (c) {
        auto errorTracker = c->getACErrorTracker();
        ASYNC_TCP_DEBUG("_accept[%u]: SSL connected\n", errorTracker->getConnectionId());
        _connect_cb(_connect_cb_arg, c);
      } else {
        ASYNC_TCP_DEBUG("_accept[_ssl_ctx]: new AsyncClient() failed, connection aborted!\n");
        if (tcp_close(pcb) != ERR_OK) {
          tcp_abort(pcb);
          return ERR_ABRT;
        }
      }
    } else {
      AsyncClient* c = new (std::nothrow) AsyncClient(pcb);
      if (c) {
        auto errorTracker = c->getACErrorTracker();
        ASYNC_TCP_DEBUG("_accept[%u]: connected\n", errorTracker->getConnectionId());
        _connect_cb(_connect_cb_arg, c);
      } else {
        ASYNC_TCP_DEBUG("_accept: new AsyncClient() failed, connection aborted!\n");
        if (tcp_close(pcb) != ERR_OK) {
          tcp_abort(pcb);
          return ERR_ABRT;
        }
      }
    }
#else
    AsyncClient* c = new (std::nothrow) AsyncClient(pcb);
    if (c) {
      auto errorTracker = c->getACErrorTracker();
      ASYNC_TCP_DEBUG("_accept[%u]: connected\n", errorTracker->getConnectionId());
      _connect_cb(_connect_cb_arg, c);
    } else {
      ASYNC_TCP_DEBUG("_accept: new AsyncClient() failed, connection aborted!\n");
      if (tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
        return ERR_ABRT;
      }
    }
#endif
  } else {
    if (tcp_close(pcb) != ERR_OK) {
      tcp_abort(pcb);
      return ERR_ABRT;
    }
  }

  return ERR_OK;
}

err_t AsyncServer::_s_accept(void* arg, tcp_pcb* pcb, err_t err) {
  return reinterpret_cast<AsyncServer*>(arg)->_accept(pcb, err);
}

// #if ASYNC_TCP_SSL_ENABLED
// err_t AsyncServer::_poll(tcp_pcb* pcb) {
//   err_t err = ERR_OK;
//   if (!tcp_ssl_has_client() && _pending) {
//     struct pending_pcb* p = _pending;
//     if (p->pcb == pcb) {
//       _pending = _pending->next;
//     } else {
//       while (p->next && p->next->pcb != pcb) p = p->next;
//       if (!p->next) return 0;
//       struct pending_pcb* b = p->next;
//       p->next = b->next;
//       p = b;
//     }
//     // 1 ASYNC_TCP_DEBUG("### remove from wait: %d\n", _clients_waiting);
//     AsyncClient* c = new (std::nothrow) AsyncClient(pcb, _ssl_ctx);
//     if (c) {
//       c->onConnect(
//           [this](void* arg, AsyncClient* c) {
//             (void)arg;
//             _connect_cb(_connect_cb_arg, c);
//           },
//           this);
//       if (p->pb) {
//         auto errorTracker = c->getACErrorTracker();
//         c->_recv(errorTracker, pcb, p->pb, 0);
//         err = errorTracker->getCallbackCloseError();
//       }
//     }
//     // Should there be error handling for when "new AsynClient" fails??
//     free(p);
//   }
//   return err;
// }

// err_t AsyncServer::_recv(struct tcp_pcb* pcb, struct pbuf* pb, err_t err) {
//   (void)err;
//   if (!_pending) return ERR_OK;

//   struct pending_pcb* p;

//   if (!pb) {
//     // 1 ASYNC_TCP_DEBUG("### close from wait: %d\n", _clients_waiting);
//     p = _pending;
//     if (p->pcb == pcb) {
//       _pending = _pending->next;
//     } else {
//       while (p->next && p->next->pcb != pcb) p = p->next;
//       if (!p->next) return 0;
//       struct pending_pcb* b = p->next;
//       p->next = b->next;
//       p = b;
//     }
//     if (p->pb) {
//       pbuf_free(p->pb);
//     }
//     free(p);
//     size_t err = tcp_close(pcb);
//     if (err != ERR_OK) {
//       tcp_abort(pcb);
//       return ERR_ABRT;
//     }
//   } else {
//     // 1 ASYNC_TCP_DEBUG("### wait _recv: %u %d\n", pb->tot_len, _clients_waiting);
//     p = _pending;
//     while (p && p->pcb != pcb) p = p->next;
//     if (p) {
//       if (p->pb) {
//         pbuf_chain(p->pb, pb);
//       } else {
//         p->pb = pb;
//       }
//     }
//   }
//   return ERR_OK;
// }

// int AsyncServer::_cert(const char* filename, uint8_t** buf) {
//   if (_file_cb) {
//     return _file_cb(_file_cb_arg, filename, buf);
//   }
//   *buf = 0;
//   return 0;
// }

// int AsyncServer::_s_cert(void* arg, const char* filename, uint8_t** buf) {
//   return reinterpret_cast<AsyncServer*>(arg)->_cert(filename, buf);
// }

// err_t AsyncServer::_s_poll(void* arg, struct tcp_pcb* pcb) {
//   return reinterpret_cast<AsyncServer*>(arg)->_poll(pcb);
// }

// err_t AsyncServer::_s_recv(void* arg, struct tcp_pcb* pcb, struct pbuf* pb, err_t err) {
//   return reinterpret_cast<AsyncServer*>(arg)->_recv(pcb, pb, err);
// }
// #endif
