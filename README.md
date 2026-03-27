# Modernized ESPAsyncTCP for ESP8266

This is a modernized fork of the  ESPAsyncTCP library modified by @dhimasardinata in order to support TLS based on BearSSL implementation included in the ESP8266  platform. The main objective of the fork is to ensure TLS is supported for the client connections as well. The other goal was to do cleanup and refactoring of the ESPAsyncTCP to ensure better readability and maintenance of the code. 

IMPORTANT! Some of the "orphained" classes like SyncClient and AsyncPrinter have been removed as the main objective of the library is to support async TCP communication. Synchronous TCP connection is already available through other libraries while printer communication is rather related to the Application layer of the OSI while AsyncTCP has to do with Network/Transport layers.

### Key Features & Enhancements

- **Modern TLS/SSL Security:** Upgraded from the outdated `axTLS` to the modern, secure `BearSSL` engine, leveraging the implementation included in the ESP8266 Arduino Core.
- **Drastically Reduced RAM Usage:** The new BearSSL integration uses memory-efficient, configurable I/O buffers, allowing for **significantly more concurrent secure (HTTPS/WSS) clients** on the memory-constrained ESP8266.
- **Enhanced Stability:** Resolves common `LoadStoreError` crashes by safely handling TLS certificates and private keys stored in PROGMEM (flash memory).
- **Fully Asynchronous:** Non-blocking operations for handling multiple simultaneous connections without complex multi-threading or `delay()`.
- **Drop-in Upgrade:** Maintains full API compatibility with the original library. **No changes are required in your application code (`.ino` sketch)** to benefit from these improvements.

This library is the foundation for the powerful [ESPAsyncWebServer](https://github.com/ESP32Async/ESPAsyncWebServer).

---

### Installation

#### PlatformIO

It is recommended to install this library by referencing its Git repository in your `platformio.ini` file to ensure you are using the modernized version.

```ini
lib_deps =
    https://github.com/abratchik/ESPAsyncTCP.git
```
#### Enabling SSL/TLS

In order to enable SSL/TLS support please specify the following:

```
build_flags = 
    -D ASYNC_TCP_SSL_ENABLED=1
```

Additionally once can set the size of the input and output buffers used for secure connections:

```
build_flags =
    -D ASYNC_TCP_SSL_IN_BUFFER_SIZE=1024
    -D ASYNC_TCP_SSL_OUT_BUFFER_SIZE=1024
```

#### Debugging SSL/TLS connections

TCP  and especially TLS layer connectivity are memory-hungry so sometimes all used certificates and ciphers may not fit in memory for all possible scenarios. Debugging messages may help understand better the root cause of the problem using the build options below:

```
build_flags =
    -D DEBUG_ESP_PORT=Serial
    -D DEBUG_ESP_ASYNC_TCP=1
    -D DEBUG_ESP_TCP_SSL=1 
```



### Usage Example: A Secure HTTPS Web Server

This example demonstrates how to set up a secure web server using `ESPAsyncWebServer` and this library.

**1. Generate Self-Signed Certificates**
Run this `openssl` command on your computer to generate a certificate (`cert.pem`) and a private key (`private_key.pem`):

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout private_key.pem -out cert.pem -sha256 -days 3650 -subj "/CN=esp8266.local"
```

**2. Convert Keys to C++ Headers**
Create two header files in your project, `cert.h` and `private_key.h`, and paste the contents of the `.pem` files into them as C-style strings.

`cert.h`:

```cpp
const char cert_pem[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
... (paste contents of cert.pem here) ...
-----END CERTIFICATE-----
)EOF";
```

`private_key.h`:

```cpp
const char key_pem[] PROGMEM = R"EOF(
-----BEGIN PRIVATE KEY-----
... (paste contents of private_key.pem here) ...
-----END PRIVATE KEY-----
)EOF";
```

**3. Your Arduino Sketch (`.ino`)**

```cpp
#include <ESP8266WiFi.h>
#include <ESPAsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include "cert.h"
#include "private_key.h"

const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";

AsyncWebServer server(443); // Create a server on the HTTPS port

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected.");
  Serial.print("IP address: https://");
  Serial.println(WiFi.localIP());

  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request){
    request->send(200, "text/plain", "Hello from ESP8266 HTTPS Server!");
  });

  // Start the secure server
  server.beginSecure(cert_pem, key_pem);
}

void loop() {
  // Loop is empty, everything is handled asynchronously!
}
```

---

### Library Components

- **AsyncClient and AsyncServer:** The powerful, low-level base classes for raw asynchronous TCP communication with TLS encryption.

### Libraries and Projects that use AsyncTCP

This library serves as a core dependency for many popular projects:

- [ESP Async Web Server](https://github.com/ESP32Async/ESPAsyncWebServer)
- [Async MQTT client](https://github.com/marvinroger/async-mqtt-client)
- [arduinoWebSockets](https://github.com/Links2004/arduinoWebSockets)
- [ESP8266 Smart Home](https://github.com/baruch/esp8266_smart_home)

---

### Original Project Context

This project is a fork of the original work which has since moved to the [ESP32Async](https://github.com/ESP32Async) organization.

- Original ESP8266 Repo: [https://github.com/ESP32Async/ESPAsyncTCP](https://github.com/ESP32Async/ESPAsyncTCP)
- Modified ESP8266 Repo with BearSSL support: [https://github.com/dhimasardinata/ESPAsyncTCP-BearSSL](https://github.com/dhimasardinata/ESPAsyncTCP-BearSSL) by @dhimasardinata. 
- ESP32 Version: [https://github.com/ESP32Async/AsyncTCP](https://github.com/ESP32Async/AsyncTCP)
- Discord Server: [https://discord.gg/X7zpGdyUcY](https://discord.gg/X7zpGdyUcY)

