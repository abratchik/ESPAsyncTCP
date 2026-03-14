#ifndef ESPASYNCTCPERRORTRACKER_H
#define ESPASYNCTCPERRORTRACKER_H


#include "DebugPrintMacros.h"
#include "async_config.h"
#include "async_typedefs.h"

enum error_events {
  EE_OK = 0,
  EE_ABORTED,   // Callback or foreground aborted connections
  EE_ERROR_CB,  // Stack initiated aborts via error Callbacks.
  EE_CONNECTED_CB,
  EE_RECV_CB,
  EE_ACCEPT_CB,
  EE_MAX
};

/**
 * AsyncClient error tracker
 */

class ACErrorTracker {
    public:
        ACErrorTracker(void* c);
        ~ACErrorTracker() {}

        err_t getCloseError(void) const { return _close_error; };

        static const char* errorToString(err_t error);

        void clearClient() { _client = NULL; }
        bool hasClient() const { return (_client != NULL); }

    #ifdef DEBUG_MORE
        void onErrorEvent(AsNotifyHandler cb, void* arg);
    #endif
    #if DEBUG_ESP_ASYNC_TCP
        void setConnectionId(size_t id) { _connectionId = id; }
        size_t getConnectionId(void) { return _connectionId; }
    #endif
        void setCloseError(err_t e);
        void setErrored(size_t errorEvent);
        err_t getCallbackCloseError(void);

    private:
        void* _client;
        err_t _close_error;
        int _errored;
    #if DEBUG_ESP_ASYNC_TCP
        size_t _connectionId;
    #endif
    #ifdef DEBUG_MORE
        AsNotifyHandler _error_event_cb;
        void* _error_event_cb_arg;
    #endif


};


#endif