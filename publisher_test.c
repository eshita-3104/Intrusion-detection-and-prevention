#include <WiFi.h>
#include <PubSubClient.h>

const char* ssid = "ESP32_AP";
const char* password = "12345678";
const char* mqtt_broker = "192.168.4.4";

const char* topics[] = {
  "esp32/temperature",
  "esp32/humidity",
  "esp32/pressure",
  "esp32/altitude"
};

const char* invalidPayloads[] = {
  "1hack",
  "1invalid",
  "1malformed",
  "112.34.56"
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

const int FLOOD_PROBABILITY = 10;  // 10% flooding, 90% normal
const int ANOMALY_PROBABILITY = 10; // 10% chance to send invalid payload
bool isFlooding = false;
int remainingFloodCycles = 0;

void setup_wifi() {
  Serial.print("Connecting to ");
  Serial.println(ssid);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\n✓ WiFi connected ✓");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());
}

void reconnect() {
  while (!client.connected()) {
    Serial.print("Attempting MQTT connection...");
    String clientId = "ESP32Publisher-" + String(random(0xffff), HEX);
    if (client.connect(clientId.c_str())) {
      Serial.println("connected ✓");
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
  Serial.println("*** ESP32 Starting...");
  Serial.println("Sketch: publisher_test_flood_only.ino");
  Serial.println("Test mode: random flooding cycles (10% flooding, 90% normal with slower rate, 10% invalid payloads)");

  unsigned long seed = 0;
  for (int i = 0; i < 10; i++) {
    seed += analogRead(0);
    delay(1);
  }
  randomSeed(seed);

  setup_wifi();
  client.setServer(mqtt_broker, 1883);
  espClient.setNoDelay(true);
  Serial.println("Setup complete!");
}

void loop() {
  if (!client.connected()) {
    reconnect();
  }
  client.loop();

  if (!isFlooding && remainingFloodCycles == 0) {
    if (random(100) < FLOOD_PROBABILITY) {
      isFlooding = true;
      remainingFloodCycles = random(1, 4);
      Serial.print("🔥 Flooding attack started for ");
      Serial.print(remainingFloodCycles);
      Serial.println(" cycles");
    }
  }

  if (isFlooding) {
    Serial.println("🔴 Flooding cycle");
    int publishDelay = 20;  // 20ms for high rate
    int cycleDelay = 1000;

    // Publish six times to each topic
    for (int j = 0; j < 6; j++) {
      for (int i = 0; i < 4; i++) {
        String payload;
        if (random(100) < ANOMALY_PROBABILITY) {
          payload = invalidPayloads[random(0, 4)];
          Serial.println("⚠️ Sending invalid payload");
        } else {
          float value = sensorFunctions[i]();
          payload = "1" + String(topics[i]) + String(value);
        }

        client.publish(topics[i], payload.c_str(), true);
        client.loop();
        espClient.flush();
        delay(5);  // Ensure separate packets

        Serial.print("📡 Published to ");
        Serial.print(topics[i]);
        Serial.print(": ");
        Serial.println(payload);

        delay(publishDelay);
      }
    }

    remainingFloodCycles--;
    if (remainingFloodCycles <= 0) {
      isFlooding = false;
      Serial.println("🔴 Flooding attack ended");
      Serial.println("Delaying 1000ms before next cycle");
    }
    delay(cycleDelay);
  } else {
    Serial.println("🟢 Normal cycle");
    int publishDelay = 1500;  // 1000ms for slower rate
    int cycleDelay = 5000;

    for (int i = 0; i < 4; i++) {
      String payload;
      if (random(100) < ANOMALY_PROBABILITY) {
        payload = invalidPayloads[random(0, 4)];
        Serial.println("⚠️ Sending invalid payload");
      } else {
        float value = sensorFunctions[i]();
        payload = "1" + String(topics[i]) + String(value);
      }

      client.publish(topics[i], payload.c_str(), true);
      client.loop();
      espClient.flush();
      delay(5);  // Ensure separate packets

      Serial.print("📩 Published to ");
      Serial.print(topics[i]);
      Serial.print(": ");
      Serial.println(payload);

      delay(publishDelay);
    }

    delay(cycleDelay);
  }
}