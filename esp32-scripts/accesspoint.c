#include <PicoMQTT.h>

class MQTT: public PicoMQTT::Server {
    protected:
        PicoMQTT::ConnectReturnCode auth(const char * client_id, const char * username, const char * password) override {
            // only accept client IDs which are 3 chars or longer
            if (String(client_id).length() < 3) {    // client_id is never NULL
                return PicoMQTT::CRC_IDENTIFIER_REJECTED;
            }


            // only accept connections if username and password are provided
            if (!username || !password) {  // username and password can be NULL
                // no username or password supplied
                return PicoMQTT::CRC_NOT_AUTHORIZED;
            }


            // accept two user/password combinations
            if (
                ((String(username) == "alice") && (String(password) == "secret"))
                || ((String(username) == "bob") && (String(password) == "password"))) {
                return PicoMQTT::CRC_ACCEPTED;
            }


            // reject all other credentials
            return PicoMQTT::CRC_BAD_USERNAME_OR_PASSWORD;
        }
} mqtt;


void setup() {
  // Setup serial
  Serial.begin(115200);

      // Set up Wi-Fi in Access Point mode
    WiFi.softAP("ESP32_AP", "12345678");  // Replace with your SSID and password

    // Display the IP address of the ESP32
    IPAddress IP = WiFi.softAPIP();
    Serial.print("AP IP address: ");
    Serial.println(IP);

  // Subscribe to a topic pattern and attach a callback
  mqtt.subscribe("#", [](const char* topic, const char* payload) {
    Serial.printf("Received message in topic '%s': %s\n", topic, payload);
  });
  mqtt.begin();
}


void loop() {
  mqtt.loop();
  if (random(1000) == 0){
    mqtt.publish("picomqtt/welcome", "Hello from PicoMQTT!");
  }
}