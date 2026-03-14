#ifndef CONFIG_H
#define CONFIG_H

/*
 * This example demonstrate how to use asynchronous client & server APIs
 * in order to establish tcp socket connections in client server manner.
 * server is running (on port 7050) on one ESP, acts as AP, and other clients running on
 * remaining ESPs acts as STAs. after connection establishment between server and clients
 * there is a simple message transfer in every 2s. clients connect to server via it's host name
 * (in this case 'esp_server') with help of DNS service running on server side.
 *
 * Note: default MSS for ESPAsyncTCP is 536 byte and defualt ACK timeout is 5s.
*/

#ifndef WIFI_SSID
#define WIFI_SSID "ESP-TEST"
#endif

#ifndef WIFI_PASSWORD
#define WIFI_PASSWORD "123456789"
#endif

#ifndef HOST_URL
#define HOST_URL "esp_server"
#endif

#ifndef HOST_PORT
#define HOST_PORT 7050
#endif

#ifndef DNS_PORT
#define DNS_PORT 53
#endif

#endif // CONFIG_H
