#include <WiFi.h>
#include <PubSubClient.h>

const char* ssid = "ESP32_AP";
const char* password = "12345678";
const char* mqtt_broker = "192.168.4.4";  // IP of the MQTT broker on the AP network

const char* topics[] = {
  "esp32/temperature",
  "esp32/humidity",
  "esp32/pressure",
  "esp32/altitude"
};

WiFiClient espClient;
PubSubClient client(espClient);

float getRandomTemperature() { return random(200, 350) / 10.0; }
float getRandomHumidity()    { return random(300, 800) / 10.0; }
float getRandomPressure()    { return random(9800, 10500) / 10.0; }
float getRandomAltitude()    { return random(500, 1500) / 10.0; }

float (*sensorFunctions[])() = {
  getRandomTemperature,
  getRandomHumidity,
  getRandomPressure,
  getRandomAltitude
};

void setup_wifi() {
  Serial.print("Connecting to ");
  Serial.println(ssid);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\n✅ WiFi connected");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());
}

void reconnect() {
  while (!client.connected()) {
    Serial.print("Attempting MQTT connection...");
    String clientId = "ESP32Publisher-";
    clientId += String(random(0xffff), HEX);
    if (client.connect(clientId.c_str())) {
      Serial.println("connected ✅");
    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" try again in 2 seconds");
      delay(2000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("🚀 ESP32 Booting...");
  Serial.println("Sketch: publisher_train.ino");
  Serial.println("Normal operation mode for training");

  // Seed random number generator with a combination of analog reads for better entropy
  unsigned long seed = 0;
  for (int i = 0; i < 10; i++) {
    seed += analogRead(0);
    delay(1);
  }
  randomSeed(seed);

  setup_wifi();
  client.setServer(mqtt_broker, 1883);
  espClient.setNoDelay(true);  // Disable Nagle's algorithm
  Serial.println("Setup complete!");
}

void loop() {
  if (!client.connected()) {
    reconnect();
  }
  client.loop();

  // Publish one sensor reading per iteration
  for (int i = 0; i < 4; i++) {
    float value = sensorFunctions[i]();
    String payload = "1" + String(topics[i]) + String(value);

    client.publish(topics[i], payload.c_str(), true);
    client.loop();  // Process any outgoing data
    espClient.flush();  // Ensure the packet is sent immediately

    Serial.print("📡 Published to ");
    Serial.print(topics[i]);
    Serial.print(": ");
    Serial.println(payload);

    delay(1500);  // 1.5 seconds to ensure distinct packets
  }

  delay(5000);  // Wait 5 seconds before the next cycle
}