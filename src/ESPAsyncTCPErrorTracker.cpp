#include "ESPAsyncTCPErrorTracker.h"

/*
  Async Client Error Return Tracker
*/
// Assumption: callbacks are never called with err == ERR_ABRT; however,
// they may return ERR_ABRT.

ACErrorTracker::ACErrorTracker(void* c)
    : _client(c),
      _close_error(ERR_OK),
      _errored(EE_OK)
#ifdef DEBUG_MORE
      ,
      _error_event_cb(NULL),
      _error_event_cb_arg(NULL)
#endif
{
}

const char* ACErrorTracker::errorToString(err_t error) {
  switch (error) {
    case ERR_OK:
      return "No error, everything OK";
    case ERR_MEM:
      return "Out of memory error";
    case ERR_BUF:
      return "Buffer error";
    case ERR_TIMEOUT:
      return "Timeout";
    case ERR_RTE:
      return "Routing problem";
    case ERR_INPROGRESS:
      return "Operation in progress";
    case ERR_VAL:
      return "Illegal value";
    case ERR_WOULDBLOCK:
      return "Operation would block";
    case ERR_ABRT:
      return "Connection aborted";
    case ERR_RST:
      return "Connection reset";
    case ERR_CLSD:
      return "Connection closed";
    case ERR_CONN:
      return "Not connected";
    case ERR_ARG:
      return "Illegal argument";
    case ERR_USE:
      return "Address in use";
#if defined(LWIP_VERSION_MAJOR) && (LWIP_VERSION_MAJOR > 1)
    case ERR_ALREADY:
      return "Already connectioning";
#endif
    case ERR_IF:
      return "Low-level netif error";
    case ERR_ISCONN:
      return "Connection already established";
    case -55:
      return "DNS failed";
    default:
      return "Unknown error";
  }
}

#ifdef DEBUG_MORE
/**
 * This is not necessary, but a start at gathering some statistics on
 * errored out connections. Used from AsyncServer.
 */
void ACErrorTracker::onErrorEvent(AsNotifyHandler cb, void* arg) {
  _error_event_cb = cb;
  _error_event_cb_arg = arg;
}
#endif

void ACErrorTracker::setCloseError(err_t e) {
  if (e != ERR_OK) 
    ASYNC_TCP_DEBUG("setCloseError() to: %s(%ld)\n", errorToString(e), e);
  if (_errored == EE_OK) 
    _close_error = e;
}
/**
 * Called mainly by callback routines, called when err is not ERR_OK.
 * This prevents the possiblity of aborting an already errored out
 * connection.
 */
void ACErrorTracker::setErrored(size_t errorEvent) {
  if (EE_OK == _errored) _errored = errorEvent;
#ifdef DEBUG_MORE
  if (_error_event_cb) _error_event_cb(_error_event_cb_arg, errorEvent);
#endif
}
/**
 * Used by callback functions only. Used for proper ERR_ABRT return value
 * reporting. ERR_ABRT is only reported/returned once; thereafter ERR_OK
 * is always returned.
 */
err_t ACErrorTracker::getCallbackCloseError(void) {
  if (EE_OK != _errored) return ERR_OK;
  if (ERR_ABRT == _close_error) setErrored(EE_ABORTED);
  return _close_error;
}