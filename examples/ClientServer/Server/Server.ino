/**
 * ESPAsyncTCP test for server side. ESP connects to the local WiFi (needs to be configured in config.h) and 
 * starts a TCP server on port 80. It also registers event handlers for new client connection, 
 * data reception, client disconnection, and ACK timeout. 
 * When a new client connects, it sends a simple HTTP response back to the client. 
 * The server can handle multiple clients simultaneously and will print debug information 
 * about the events occurring with each client. To test this server, you can use a simple 
 * browser to connect to the ESP's IP address on port 80 and request any page (e.g., http://<ESP_IP_ADDRESS>/)
 * to see the response from the server.
 */

#include <ESP8266WiFi.h>
#include <ESPAsyncTCP.h>
#include <vector>

#include "config.h"

static std::vector<AsyncClient*> clients; // a list to hold all clients

 /* clients events */
static void handleError(void* arg, AsyncClient* client, int8_t error) {
	Serial.printf("\n connection error %s from client %s \n", client->errorToString(error), client->remoteIP().toString().c_str());
}

static void handleData(void* arg, AsyncClient* client, void *data, size_t len) {
	Serial.printf("\n data received from client %s \n", client->remoteIP().toString().c_str());
	Serial.write((uint8_t*)data, len);

	// reply to client
	if (client->space() > 32 && client->canSend()) {
		Serial.printf("\n sending data to client %s \n", client->remoteIP().toString().c_str());
		char reply[100];
		sprintf(reply, "this is from %s", SERVER_HOST_NAME);

		// Send complete HTTP response
		String response = "HTTP/1.1 200 OK\r\n";
		response += "Content-Type: text/plain\r\n";
		response += "Content-Length: " + String(strlen(reply)) + "\r\n";
		response += "Connection: close\r\n";
		response += "\r\n";
		response += reply;

		size_t will_send = client->add(response.c_str(), response.length());
		Serial.printf("\n will send %d bytes to client %s \n", will_send, client->remoteIP().toString().c_str());
		client->send();
	}
	else {
		Serial.printf("\n Server not ready or outbuf has no space to send data to client %s \n", client->remoteIP().toString().c_str());
	}
}

static void handleDisconnect(void* arg, AsyncClient* client) {
	Serial.printf("\n client %s disconnected \n", client->remoteIP().toString().c_str());
}

static void handleTimeOut(void* arg, AsyncClient* client, uint32_t time) {
	Serial.printf("\n client ACK timeout ip: %s \n", client->remoteIP().toString().c_str());
}


/* server events */
static void handleNewClient(void* arg, AsyncClient* client) {
	Serial.printf("\n new client has been connected to server, ip: %s\n", client->remoteIP().toString().c_str());

	// add to list
	clients.push_back(client);
	
	// register events
	client->onData(&handleData, NULL);
	client->onError(&handleError, NULL);
	client->onDisconnect(&handleDisconnect, NULL);
	client->onTimeout(&handleTimeOut, NULL);
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

	Serial.println("\nWiFi connected");

	AsyncServer* server = new AsyncServer(TCP_PORT); // start listening on tcp port 7050
	server->onClient(&handleNewClient, server);
	server->begin();

	Serial.printf("Server started on %s:%d\n", WiFi.localIP().toString().c_str(), TCP_PORT);
}

void loop() {
}
