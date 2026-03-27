#include <ESP8266WiFi.h>
#include <ESPAsyncTCP.h>

extern "C" {
#include <osapi.h>
#include <os_type.h>
}

#include "config.h"
const char* TAG = "ino";

static os_timer_t intervalTimer;

static void replyToServer(void* arg) {
	AsyncClient* client = reinterpret_cast<AsyncClient*>(arg);

	// send reply
	if (client->space() > 32 && client->canSend()) {
		char message[32];
		sprintf(message, "this is from %s", WiFi.localIP().toString().c_str());
		client->add(message, strlen(message));
		client->send();
	}
}

/* event callbacks */
static void handleData(void* arg, AsyncClient* client, void *data, size_t len) {
	Serial.printf("Data received from %s \n", client->remoteIP().toString().c_str());
	Serial.write((uint8_t*)data, len);

	os_timer_arm(&intervalTimer, 2000, true); // schedule for reply to server at next 2s
}

void onConnect(void* arg, AsyncClient* client) {
	Serial.printf("Connected to %s on port %d \n", HOST_URL, HOST_PORT);
	replyToServer(client);
}

void onDisconnect(void* arg, AsyncClient* client) {
	Serial.println("Disconnected");
}

void onError(void* arg, AsyncClient* client, err_t err) {
	Serial.printf("Client error: %s\n", client->errorToString(err));
}

void onTimeout(void* arg, AsyncClient* client, uint32_t time) {
	Serial.printf("Timeout: %u\n", time);
}


void setup() {
	Serial.begin(115200);
	delay(20);

	// connects to access point
	WiFi.mode(WIFI_STA);
	WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
	while (WiFi.status() != WL_CONNECTED) {
		Serial.print('.');
		delay(500);
	}

	AsyncClient* client = new AsyncClient;
	client->onData(&handleData, client);
	client->onConnect(&onConnect, client);
	client->onDisconnect(&onDisconnect, client);
	client->onTimeout(&onTimeout, client);
	client->onError(&onError, client);
	
	client->setInsecure();

	client->connect(HOST_URL, HOST_PORT, true);

	os_timer_disarm(&intervalTimer);
	os_timer_setfn(&intervalTimer, &replyToServer, client);
}

void loop() {

}
