#include "storage/key_store.h"
#include "config.h"
#include <Preferences.h>
#include "mbedtls/sha256.h"

// Singleton global
KeyStore keyStore;

static const char* NVS_NAMESPACE = "nfcaccess";
static const char* NVS_KEY_COUNT = "count";
static const char* NVS_KEY_PREFIX = "dev_"; // dev_0, dev_1, ...

static Preferences prefs;

bool KeyStore::init() {
    if (!prefs.begin(NVS_NAMESPACE, false)) {
        Serial.println("[KeyStore] ✗ NVS init failed");
        return false;
    }

    deviceCount = prefs.getUChar(NVS_KEY_COUNT, 0);
    if (deviceCount > MAX_ENROLLED_DEVICES) {
        Serial.print("[KeyStore] count corupt in NVS (");
        Serial.print(deviceCount);
        Serial.println("), reset la 0");
        deviceCount = 0;
        prefs.putUChar(NVS_KEY_COUNT, 0);
    }

    Serial.print("[KeyStore] Incarc ");
    Serial.print(deviceCount);
    Serial.println(" device(s) inrolate");

    for (uint8_t i = 0; i < deviceCount; i++) {
        char key[16];
        snprintf(key, sizeof(key), "%s%d", NVS_KEY_PREFIX, i);
        size_t len = prefs.getBytesLength(key);
        if (len != sizeof(EnrolledDevice)) {
            Serial.print("[KeyStore] Device #");
            Serial.print(i);
            Serial.println(" corupt, ignor");
            continue;
        }
        prefs.getBytes(key, &devices[i], sizeof(EnrolledDevice));
        Serial.print("  [");
        Serial.print(i);
        Serial.print("] ");
        Serial.print(devices[i].deviceLabel);
        Serial.print(" (keyId: ");
        for (int b = 0; b < 4; b++) {
            if (devices[i].keyId[b] < 0x10) Serial.print("0");
            Serial.print(devices[i].keyId[b], HEX);
        }
        Serial.println("...)");
    }

    return true;
}

void KeyStore::computeKeyId(const uint8_t* publicKey, size_t publicKeyLen, uint8_t* outKeyId) {
    uint8_t hash[32];
    mbedtls_sha256_ret(publicKey, publicKeyLen, hash, 0);
    memcpy(outKeyId, hash, KEY_ID_LEN); // primii 16 bytes
}

bool KeyStore::enroll(const uint8_t* publicKey, size_t publicKeyLen,
                       const char* deviceLabel,
                       uint8_t* outKeyId) {
    if (publicKeyLen > MAX_PUBLIC_KEY_LEN) {
        Serial.println("[KeyStore] Cheia e prea mare");
        return false;
    }
    if (deviceCount >= MAX_ENROLLED_DEVICES) {
        Serial.println("[KeyStore] Lista plina (5/5)");
        return false;
    }

    uint8_t keyId[KEY_ID_LEN];
    computeKeyId(publicKey, publicKeyLen, keyId);

    // Check duplicate
    if (findByKeyId(keyId) != nullptr) {
        Serial.println("[KeyStore] Cheia e deja inrolata");
        return false;
    }

    EnrolledDevice& dev = devices[deviceCount];
    memcpy(dev.keyId, keyId, KEY_ID_LEN);
    memcpy(dev.publicKey, publicKey, publicKeyLen);
    dev.publicKeyLen = publicKeyLen;
    strncpy(dev.deviceLabel, deviceLabel, MAX_DEVICE_LABEL_LEN - 1);
    dev.deviceLabel[MAX_DEVICE_LABEL_LEN - 1] = '\0';
    dev.enrolledAt = millis();

    deviceCount++;
    bool ok = persist();
    if (!ok) {
        deviceCount--; // rollback
        Serial.println("[KeyStore] Persist failed, rollback");
        return false;
    }

    if (outKeyId) memcpy(outKeyId, keyId, KEY_ID_LEN);
    
    Serial.print("[KeyStore] ✓ Inrolat '");
    Serial.print(dev.deviceLabel);
    Serial.print("' (total: ");
    Serial.print(deviceCount);
    Serial.println(")");
    return true;
}

const EnrolledDevice* KeyStore::findByKeyId(const uint8_t* keyId) {
    for (uint8_t i = 0; i < deviceCount; i++) {
        if (memcmp(devices[i].keyId, keyId, KEY_ID_LEN) == 0) {
            return &devices[i];
        }
    }
    return nullptr;
}

bool KeyStore::persist() {
    if (!prefs.putUChar(NVS_KEY_COUNT, deviceCount)) return false;
    
    for (uint8_t i = 0; i < deviceCount; i++) {
        char key[16];
        snprintf(key, sizeof(key), "%s%d", NVS_KEY_PREFIX, i);
        size_t written = prefs.putBytes(key, &devices[i], sizeof(EnrolledDevice));
        if (written != sizeof(EnrolledDevice)) {
            Serial.print("[KeyStore] persist failed at index ");
            Serial.println(i);
            return false;
        }
    }
    return true;
}

void KeyStore::clearAll() {
    prefs.clear();
    deviceCount = 0;
    Serial.println("[KeyStore] Toate inrolarile au fost sterse");
}

bool KeyStore::revokeByKeyId(const uint8_t* keyId) {
    int foundIndex = -1;
    for (uint8_t i = 0; i < deviceCount; i++) {
        if (memcmp(devices[i].keyId, keyId, KEY_ID_LEN) == 0) {
            foundIndex = i;
            break;
        }
    }
    if (foundIndex < 0) return false;

    // Shift-uieste in jos device-urile ramase
    for (uint8_t i = foundIndex; i < deviceCount - 1; i++) {
        devices[i] = devices[i + 1];
    }
    deviceCount--;

    // Re-persista vectorul curat
    prefs.putUChar(NVS_KEY_COUNT, deviceCount);
    for (uint8_t i = 0; i < deviceCount; i++) {
        char key[16];
        snprintf(key, sizeof(key), "%s%d", NVS_KEY_PREFIX, i);
        prefs.putBytes(key, &devices[i], sizeof(EnrolledDevice));
    }
    // Sterge slotul ramas (vechiul ultimul)
    char oldKey[16];
    snprintf(oldKey, sizeof(oldKey), "%s%d", NVS_KEY_PREFIX, deviceCount);
    prefs.remove(oldKey);

    Serial.print("[KeyStore] ✓ Revocat device la index ");
    Serial.println(foundIndex);
    return true;
}