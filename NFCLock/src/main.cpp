#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <ArduinoJson.h>

#include "config.h"
#include "crypto/ecdsa_verifier.h"
#include "crypto/nonce_manager.h"
#include "storage/key_store.h"
#include "util/hex_utils.h"
#include "nfc/nfc_authenticator.h"


// ================== Globals ==================
WebServer server(HTTP_PORT);
NonceManager nonceManager;

unsigned long stats_totalRequests = 0;
unsigned long stats_grantedRequests = 0;
unsigned long stats_deniedRequests = 0;
unsigned long stats_enrollmentsAccepted = 0;

// Enrollment window
unsigned long enrollmentWindowOpenedAt = 0;
bool enrollmentWindowActive = false;

// Rate limit
unsigned long lastGrantedAt = 0;
const unsigned long MIN_INTERVAL_BETWEEN_OPENS_MS = 3000;

// Button monitoring
unsigned long lastButtonCheck = 0;

// ═══ NFC task ═══
struct NfcEvent {
    NfcAuthenticator::Result result;
    char deviceLabel[32];
    uint32_t latencyMs;
    bool consumed; 
};

volatile NfcEvent nfcEvent = {NfcAuthenticator::NO_TAG, "", 0, true};
SemaphoreHandle_t nfcMutex = nullptr;
TaskHandle_t nfcTaskHandle = nullptr;

// ================== Helpers ==================
void openEnrollmentWindow() {
    enrollmentWindowOpenedAt = millis();
    enrollmentWindowActive = true;
    Serial.print("\n┌─ ENROLLMENT WINDOW OPEN (");
    Serial.print(ENROLLMENT_WINDOW_MS / 1000);
    Serial.println("s) ─");
    Serial.print("│ Slot disponibile: ");
    Serial.print(MAX_ENROLLED_DEVICES - keyStore.count());
    Serial.print("/");
    Serial.println(MAX_ENROLLED_DEVICES);
    Serial.println("└─ Apasa \"Inroleaza\" pe telefon acum.\n");
}

// ═══ Task NFC pe Core 1 — scanare continua fara sa blocheze HTTP ═══
void nfcTask(void* parameter) {
    Serial.print("[nfcTask] Pornit pe core ");
    Serial.println(xPortGetCoreID());
    
    char localLabel[32];
    uint32_t localLatency;
    
    while (true) {
        NfcAuthenticator::Result r = nfcAuth.tick(localLabel, sizeof(localLabel), &localLatency);
        
        // Doar evenimentele interesante sunt raportate catre loop()
        if (r == NfcAuthenticator::SUCCESS ||
            r == NfcAuthenticator::SIGNATURE_INVALID ||
            r == NfcAuthenticator::UNKNOWN_DEVICE) {
            
            // Acquire mutex inainte de a scrie evenimentul
            if (xSemaphoreTake(nfcMutex, portMAX_DELAY) == pdTRUE) {
                nfcEvent.result = r;
                strncpy((char*)nfcEvent.deviceLabel, localLabel, 31);
                nfcEvent.deviceLabel[31] = '\0';
                nfcEvent.latencyMs = localLatency;
                nfcEvent.consumed = false;
                xSemaphoreGive(nfcMutex);
            }
            
            // Asteapta sa fie consumat (debouncing simplu)
            uint32_t waitStart = millis();
            while (millis() - waitStart < 3000) {
                vTaskDelay(50 / portTICK_PERIOD_MS);
                if (xSemaphoreTake(nfcMutex, 10 / portTICK_PERIOD_MS) == pdTRUE) {
                    bool consumed = nfcEvent.consumed;
                    xSemaphoreGive(nfcMutex);
                    if (consumed) break;
                }
            }
        } else {
            // NO_TAG / SELECT_FAILED / etc. — yield rapid si reincearca
            vTaskDelay(50 / portTICK_PERIOD_MS);
        }
    }
}

bool isEnrollmentOpen() {
    if (!enrollmentWindowActive) return false;
    if (millis() - enrollmentWindowOpenedAt > ENROLLMENT_WINDOW_MS) {
        enrollmentWindowActive = false;
        Serial.println("\n[!] Enrollment window CLOSED (timeout)\n");
        return false;
    }
    return true;
}

void ledOk(unsigned long durationMs) {
    digitalWrite(LED_DOOR_PIN , HIGH);
    delay(durationMs);
    digitalWrite(LED_DOOR_PIN , LOW);
}

void ledFail(unsigned long durationMs) {
    digitalWrite(LED_DENIED_PIN , HIGH);
    delay(durationMs);
    digitalWrite(LED_DENIED_PIN , LOW);
}

// ================== HTTP: /api/challenge ==================
void handleChallenge() {
    stats_totalRequests++;
    Serial.println("\n┌─ GET /api/challenge ─");

    const uint8_t* nonce = nonceManager.generate();
    String nonceHex = HexUtils::bytesToHex(nonce, 32);

    JsonDocument doc;
    doc["nonce"] = nonceHex;
    doc["expires_in_ms"] = NONCE_VALIDITY_MS;
    doc["door_id"] = DOOR_ID;

    String response;
    serializeJson(doc, response);

    Serial.print("│ Nonce: ");
    Serial.println(nonceHex);
    Serial.println("└─ 200 OK");

    server.send(200, "application/json", response);
}

// ================== HTTP: /api/open ==================
void handleOpen() {
    stats_totalRequests++;
    unsigned long t0 = millis();

    Serial.println("\n┌─ POST /api/open ─");

    if (!server.hasArg("plain")) {
        server.send(400, "application/json", "{\"status\":\"denied\",\"reason\":\"missing_body\"}");
        stats_deniedRequests++;
        return;
    }

    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"status\":\"denied\",\"reason\":\"invalid_json\"}");
        stats_deniedRequests++;
        return;
    }

    const char* keyIdHex = doc["key_id"];
    const char* messageHex = doc["message"];
    const char* signatureHex = doc["signature"];
    if (!keyIdHex || !messageHex || !signatureHex) {
        server.send(400, "application/json", "{\"status\":\"denied\",\"reason\":\"missing_fields\"}");
        stats_deniedRequests++;
        return;
    }

    // Decodare keyId (16 bytes)
    uint8_t keyId[KEY_ID_LEN];
    int keyIdLen = HexUtils::hexToBytes(String(keyIdHex), keyId, sizeof(keyId));
    if (keyIdLen != KEY_ID_LEN) {
        server.send(400, "application/json", "{\"status\":\"denied\",\"reason\":\"invalid_key_id\"}");
        stats_deniedRequests++;
        return;
    }

    // Decodare message + signature
    uint8_t message[64], signature[128];
    int messageLen = HexUtils::hexToBytes(String(messageHex), message, sizeof(message));
    int signatureLen = HexUtils::hexToBytes(String(signatureHex), signature, sizeof(signature));

    if (messageLen != 37 || signatureLen < 0) {
        server.send(400, "application/json", "{\"status\":\"denied\",\"reason\":\"bad_format\"}");
        stats_deniedRequests++;
        ledFail(200);
        return;
    }

    Serial.print("│ KeyId: ");
    Serial.println(keyIdHex);
    Serial.print("│ Msg(");
    Serial.print(messageLen);
    Serial.print("B): ");
    Serial.println(messageHex);

    // Verifica nonce
    if (!nonceManager.check(message, 32)) {
        Serial.println("│ ✗ Nonce invalid/expirat");
        server.send(401, "application/json", "{\"status\":\"denied\",\"reason\":\"nonce_invalid_or_expired\"}");
        stats_deniedRequests++;
        ledFail(200);
        return;
    }

    // Verifica doorId
    uint32_t doorId = ((uint32_t)message[32] << 24) | ((uint32_t)message[33] << 16)
                    | ((uint32_t)message[34] <<  8) | ((uint32_t)message[35]);
    if (doorId != DOOR_ID) {
        server.send(401, "application/json", "{\"status\":\"denied\",\"reason\":\"wrong_door_id\"}");
        stats_deniedRequests++;
        ledFail(200);
        return;
    }

    // Rate limit
    if (lastGrantedAt > 0 && millis() - lastGrantedAt < MIN_INTERVAL_BETWEEN_OPENS_MS) {
        Serial.println("│ ✗ Rate limit");
        server.send(429, "application/json", "{\"status\":\"denied\",\"reason\":\"rate_limit\"}");
        stats_deniedRequests++;
        return;
    }

    // O(1) lookup pe keyId — nu mai iteram prin toate cheile
    const EnrolledDevice* device = keyStore.findByKeyId(keyId);
    if (device == nullptr) {
        Serial.println("│ ✗ KeyId necunoscut — telefon neinrolat");
        server.send(401, "application/json", "{\"status\":\"denied\",\"reason\":\"unknown_device\"}");
        stats_deniedRequests++;
        ledFail(500);
        return;
    }

    Serial.print("│ Gasit device: '");
    Serial.print(device->deviceLabel);
    Serial.println("'");

    // O singura verificare ECDSA
    unsigned long tSig = millis();
    bool valid = EcdsaVerifier::verify(
        device->publicKey, device->publicKeyLen,
        message, messageLen,
        signature, signatureLen
    );
    unsigned long sigTime = millis() - tSig;
    Serial.print("│ ECDSA verify: ");
    Serial.print(sigTime);
    Serial.println(" ms");

    if (!valid) {
        Serial.println("│ ✗ Semnatura invalida pentru keyId-ul dat");
        server.send(401, "application/json", "{\"status\":\"denied\",\"reason\":\"signature_invalid\"}");
        stats_deniedRequests++;
        ledFail(500);
        return;
    }

    nonceManager.consume();
    lastGrantedAt = millis();

    Serial.print("│ ✓ ACCES PERMIS pentru '");
    Serial.print(device->deviceLabel);
    Serial.print("' — total ");
    Serial.print(millis() - t0);
    Serial.println(" ms");
    Serial.println("└─ 200 OK");

    JsonDocument respDoc;
    respDoc["status"] = "granted";
    respDoc["device"] = device->deviceLabel;
    String respStr;
    serializeJson(respDoc, respStr);
    server.send(200, "application/json", respStr);
    stats_grantedRequests++;
    ledOk(2000);
}

// ================== HTTP: /api/enroll ==================
void handleEnroll() {
    stats_totalRequests++;
    Serial.println("\n┌─ POST /api/enroll ─");

    if (!isEnrollmentOpen()) {
        Serial.println("│ ✗ Enrollment closed");
        server.send(403, "application/json", "{\"status\":\"denied\",\"reason\":\"enrollment_closed\"}");
        return;
    }

    if (!server.hasArg("plain")) {
        server.send(400, "application/json", "{\"status\":\"error\",\"reason\":\"missing_body\"}");
        return;
    }

    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"status\":\"error\",\"reason\":\"invalid_json\"}");
        return;
    }

    const char* pubKeyHex = doc["public_key"];
    const char* label = doc["device_label"] | "Unnamed device";
    if (!pubKeyHex) {
        server.send(400, "application/json", "{\"status\":\"error\",\"reason\":\"missing_public_key\"}");
        return;
    }

    uint8_t publicKey[MAX_PUBLIC_KEY_LEN];
    int publicKeyLen = HexUtils::hexToBytes(String(pubKeyHex), publicKey, sizeof(publicKey));
    if (publicKeyLen < 50) { // sanity check: cheile ECDSA P-256 DER au ~91 bytes
        Serial.println("│ ✗ Cheie publica prea scurta");
        server.send(400, "application/json", "{\"status\":\"error\",\"reason\":\"invalid_key\"}");
        return;
    }

    Serial.print("│ Inrolez: '");
    Serial.print(label);
    Serial.print("' (cheie ");
    Serial.print(publicKeyLen);
    Serial.println("B)");

    uint8_t keyId[KEY_ID_LEN];
    bool ok = keyStore.enroll(publicKey, publicKeyLen, label, keyId);
    if (!ok) {
        Serial.println("│ ✗ Enrollment failed (cheie duplicata sau storage plin)");
        server.send(409, "application/json", "{\"status\":\"error\",\"reason\":\"already_enrolled_or_full\"}");
        return;
    }

    String keyIdHex = HexUtils::bytesToHex(keyId, KEY_ID_LEN);
    Serial.print("│ KeyId: ");
    Serial.println(keyIdHex);
    Serial.println("└─ 200 OK");

    stats_enrollmentsAccepted++;

    JsonDocument respDoc;
    respDoc["status"] = "enrolled";
    respDoc["key_id"] = keyIdHex;
    respDoc["device_label"] = label;
    respDoc["total_enrolled"] = keyStore.count();
    respDoc["slots_remaining"] = MAX_ENROLLED_DEVICES - keyStore.count();
    String respStr;
    serializeJson(respDoc, respStr);
    server.send(200, "application/json", respStr);

    // Flash LED OK 3 ori pentru confirmare vizuala
    for (int i = 0; i < 3; i++) {
        digitalWrite(LED_DOOR_PIN , HIGH);
        delay(100);
        digitalWrite(LED_DOOR_PIN , LOW);
        delay(100);
    }
}

// ================== HTTP: /api/admin/revoke ==================
void handleRevoke() {
    stats_totalRequests++;
    Serial.println("\n┌─ POST /api/admin/revoke ─");

    // Operatia de revocare e considerata privilegiata — admin window
    if (!isEnrollmentOpen()) {
        Serial.println("│ ✗ Admin operation requires enrollment window open");
        server.send(403, "application/json", "{\"status\":\"denied\",\"reason\":\"admin_locked\"}");
        return;
    }

    if (!server.hasArg("plain")) {
        server.send(400, "application/json", "{\"status\":\"error\",\"reason\":\"missing_body\"}");
        return;
    }

    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"status\":\"error\",\"reason\":\"invalid_json\"}");
        return;
    }

    const char* keyIdHex = doc["key_id"];
    if (!keyIdHex) {
        server.send(400, "application/json", "{\"status\":\"error\",\"reason\":\"missing_key_id\"}");
        return;
    }

    uint8_t keyId[KEY_ID_LEN];
    int keyIdLen = HexUtils::hexToBytes(String(keyIdHex), keyId, sizeof(keyId));
    if (keyIdLen != KEY_ID_LEN) {
        server.send(400, "application/json", "{\"status\":\"error\",\"reason\":\"invalid_key_id\"}");
        return;
    }

    bool removed = keyStore.revokeByKeyId(keyId);
    if (!removed) {
        Serial.println("│ ✗ KeyId nu exista");
        server.send(404, "application/json", "{\"status\":\"error\",\"reason\":\"not_found\"}");
        return;
    }

    Serial.print("│ ✓ Revocat. Raman ");
    Serial.print(keyStore.count());
    Serial.println(" device-uri.");
    Serial.println("└─ 200 OK");

    JsonDocument respDoc;
    respDoc["status"] = "revoked";
    respDoc["remaining"] = keyStore.count();
    String respStr;
    serializeJson(respDoc, respStr);
    server.send(200, "application/json", respStr);
}

// ================== HTTP: /api/status ==================
void handleStatus() {
    JsonDocument doc;
    doc["uptime_ms"] = millis();
    doc["wifi_rssi"] = WiFi.RSSI();
    doc["door_id"] = DOOR_ID;
    doc["total_requests"] = stats_totalRequests;
    doc["granted_requests"] = stats_grantedRequests;
    doc["denied_requests"] = stats_deniedRequests;
    doc["enrollments_accepted"] = stats_enrollmentsAccepted;
    doc["enrolled_devices"] = keyStore.count();
    doc["max_devices"] = MAX_ENROLLED_DEVICES;
    doc["nfc_available"] = nfcAuth.isAvailable();
    doc["enrollment_open"] = isEnrollmentOpen();
    if (isEnrollmentOpen()) {
        doc["enrollment_remaining_ms"] = ENROLLMENT_WINDOW_MS - (millis() - enrollmentWindowOpenedAt);
    }

    JsonArray devices = doc["devices"].to<JsonArray>();
    for (uint8_t i = 0; i < keyStore.count(); i++) {
        const EnrolledDevice* dev = keyStore.deviceAt(i);
        JsonObject d = devices.add<JsonObject>();
        d["label"] = dev->deviceLabel;
        d["key_id"] = HexUtils::bytesToHex(dev->keyId, KEY_ID_LEN);
    }

    String response;
    serializeJson(doc, response);
    server.send(200, "application/json", response);
}

void handleNotFound() {
    server.send(404, "application/json", "{\"error\":\"not_found\"}");
}

// ================== Setup ==================
void setup() {
    Serial.begin(115200);
    delay(500);

    pinMode(LED_DOOR_PIN, OUTPUT);
    pinMode(LED_DENIED_PIN, OUTPUT);
    pinMode(LED_READY_PIN, OUTPUT);
    pinMode(LED_ENROLLMENT_PIN, OUTPUT);
    pinMode(ENROLLMENT_BUTTON_PIN, INPUT_PULLUP);
    
    digitalWrite(LED_DOOR_PIN, LOW);
    digitalWrite(LED_DENIED_PIN, LOW);
    digitalWrite(LED_READY_PIN, LOW);
    digitalWrite(LED_ENROLLMENT_PIN, LOW);

    Serial.println("\n\n========================================");
    Serial.println("  NFC Access Control — Firmware ESP32");
    Serial.println("  Pasul 9: Enrollment dinamic + NVS");
    Serial.println("========================================\n");

    // Indicator vizual: daca enrollment se deschide automat, vom seta LED galben in loop
    Serial.println("\nLED-uri active:");
    Serial.println("  ALBASTRU (GPIO 25) = sistem online");
    Serial.println("  GALBEN   (GPIO 26) = enrollment mode");
    Serial.println("  VERDE    (GPIO 2)  = door open");
    Serial.println("  ROSU     (GPIO 4)  = access denied");

    // Initializeaza keyStore
    if (!keyStore.init()) {
        Serial.println("✗ KeyStore init failed!");
        while (1) delay(1000);
    }

    // WiFi
    Serial.print("\nConectare WiFi: ");
    Serial.println(WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 40) {
        delay(500);
        Serial.print(".");
        attempts++;
    }
    Serial.println();

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("✗ WiFi failed!");
        while (1) {
            digitalWrite(LED_DENIED_PIN , HIGH);
            delay(200);
            digitalWrite(LED_DENIED_PIN , LOW);
            delay(200);
        }
    }
    Serial.println("✓ WiFi conectat");
    Serial.print("  IP: http://");
    Serial.println(WiFi.localIP());

    // HTTP routes
    server.on("/api/challenge", HTTP_GET, handleChallenge);
    server.on("/api/open", HTTP_POST, handleOpen);
    server.on("/api/enroll", HTTP_POST, handleEnroll);
    server.on("/api/status", HTTP_GET, handleStatus);
    server.on("/api/admin/revoke", HTTP_POST, handleRevoke);
    server.onNotFound(handleNotFound);
    server.begin();

    Serial.println("\n✓ HTTP server pornit\n");
    Serial.println("Endpoints:");
    Serial.print("  GET  /api/status     → http://");
    Serial.print(WiFi.localIP());
    Serial.println("/api/status");
    Serial.print("  GET  /api/challenge  → http://");
    Serial.print(WiFi.localIP());
    Serial.println("/api/challenge");
    Serial.print("  POST /api/open       → http://");
    Serial.print(WiFi.localIP());
    Serial.println("/api/open");
    Serial.print("  POST /api/enroll     → http://");
    Serial.print(WiFi.localIP());
    Serial.println("/api/enroll");

    // Deschide automat fereastra de enrollment la primul boot (cand nu exista telefoane)
    if (keyStore.count() == 0) {
        Serial.println("\n[!] Niciun telefon inrolat. Deschid automat fereastra de enrollment.");
        openEnrollmentWindow();
    } else {
        Serial.println("\nApasa butonul BOOT pentru a deschide fereastra de enrollment.");
    }


// ═══ Initializare PN532 + task NFC pe Core 1 ═══
    Serial.println("\nInitializare modul NFC...");
    if (nfcAuth.init()) {
        Serial.println("NFC reader gata");
        
        nfcMutex = xSemaphoreCreateMutex();
        if (nfcMutex != nullptr) {
            xTaskCreatePinnedToCore(
                nfcTask,           // functie
                "nfcTask",         // nume
                8192,              // stack size (bytes)
                nullptr,           // parametru
                1,                 // prioritate (1 = scazuta, sub HTTP)
                &nfcTaskHandle,    // handle
                1                  // Core 1 (APP_CPU)
            );
            Serial.println("NFC task pornit pe Core 1");
        } else {
            Serial.println("Mutex creation failed!");
        }
    } else {
        Serial.println("NFC indisponibil — sistemul functioneaza doar pe HTTP");
    }

    // System is online — turn on ready LED
    digitalWrite(LED_READY_PIN, HIGH);

    // Brief startup sequence — flash all LEDs once
    digitalWrite(LED_DOOR_PIN, HIGH);
    digitalWrite(LED_DENIED_PIN, HIGH);
    digitalWrite(LED_ENROLLMENT_PIN, HIGH);
    delay(200);
    digitalWrite(LED_DOOR_PIN, LOW);
    digitalWrite(LED_DENIED_PIN, LOW);
    digitalWrite(LED_ENROLLMENT_PIN, LOW);
}

void loop() {
    server.handleClient();

    // ═══ Consuma evenimente NFC (raportate de task-ul de pe Core 1) ═══
    if (nfcMutex != nullptr && xSemaphoreTake(nfcMutex, 5 / portTICK_PERIOD_MS) == pdTRUE) {
        if (!nfcEvent.consumed) {
            NfcAuthenticator::Result r = nfcEvent.result;
            char label[32];
            strncpy(label, (char*)nfcEvent.deviceLabel, 31);
            label[31] = '\0';
            uint32_t latencyMs = nfcEvent.latencyMs;
            nfcEvent.consumed = true;
            xSemaphoreGive(nfcMutex);
            
            // Procesare in afara mutexului (operatiile lungi nu blocheaza task-ul NFC)
            if (r == NfcAuthenticator::SUCCESS) {
                if (lastGrantedAt > 0 && millis() - lastGrantedAt < MIN_INTERVAL_BETWEEN_OPENS_MS) {
                    Serial.println("[NFC] ✗ Rate limit");
                    stats_deniedRequests++;
                    ledFail(500);
                } else {
                    Serial.print("[NFC] ✓✓✓ ACCES PERMIS pentru '");
                    Serial.print(label);
                    Serial.print("' in ");
                    Serial.print(latencyMs);
                    Serial.println(" ms");
                    stats_grantedRequests++;
                    lastGrantedAt = millis();
                    ledOk(2000);
                }
            } else if (r == NfcAuthenticator::SIGNATURE_INVALID ||
                       r == NfcAuthenticator::UNKNOWN_DEVICE) {
                Serial.println("[NFC] ✗ Acces respins");
                stats_deniedRequests++;
                ledFail(500);
            }
        } else {
            xSemaphoreGive(nfcMutex);
        }
    }

    // ═══ Check button BOOT pentru enrollment window ═══
    if (millis() - lastButtonCheck > 100) {
        lastButtonCheck = millis();
        if (digitalRead(ENROLLMENT_BUTTON_PIN) == LOW) {
            if (!enrollmentWindowActive) {
                openEnrollmentWindow();
            }
            // wait release ca sa nu re-trigger
            while (digitalRead(ENROLLMENT_BUTTON_PIN) == LOW) {
                server.handleClient();
                delay(20);
            }
        }
    }

    // ═══ LED enrollment — clipeste 1Hz cand fereastra e deschisa ═══
    if (isEnrollmentOpen()) {
        static unsigned long lastBlink = 0;
        if (millis() - lastBlink > 500) {
            lastBlink = millis();
            digitalWrite(LED_ENROLLMENT_PIN, !digitalRead(LED_ENROLLMENT_PIN));
        }
    } else {
        digitalWrite(LED_ENROLLMENT_PIN, LOW);
    }

    delay(2);
}