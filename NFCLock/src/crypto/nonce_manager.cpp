#include "crypto/nonce_manager.h"
#include "config.h"
#include <Arduino.h>
#include <esp_random.h>

const uint8_t* NonceManager::generate() {
    // esp_random foloseste RNG-ul hardware al ESP32, calitate criptografica
    for (size_t i = 0; i < 32; i += 4) {
        uint32_t r = esp_random();
        currentNonce[i]     = (r >>  0) & 0xFF;
        currentNonce[i + 1] = (r >>  8) & 0xFF;
        currentNonce[i + 2] = (r >> 16) & 0xFF;
        currentNonce[i + 3] = (r >> 24) & 0xFF;
    }
    generatedAt = millis();
    active = true;
    return currentNonce;
}

bool NonceManager::check(const uint8_t* candidate, size_t candidateLen) {
    if (!active) return false;
    if (candidateLen != 32) return false;
    if (millis() - generatedAt > NONCE_VALIDITY_MS) {
        active = false;
        return false;
    }
    // Comparatie constanta in timp (rezistenta la timing attacks)
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; i++) {
        diff |= currentNonce[i] ^ candidate[i];
    }
    return diff == 0;
}

void NonceManager::consume() {
    active = false;
}

uint32_t NonceManager::remainingMs() const {
    if (!active) return 0;
    uint32_t elapsed = millis() - generatedAt;
    if (elapsed >= NONCE_VALIDITY_MS) return 0;
    return NONCE_VALIDITY_MS - elapsed;
}