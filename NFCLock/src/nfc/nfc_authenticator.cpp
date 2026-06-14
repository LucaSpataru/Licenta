#include "nfc/nfc_authenticator.h"
#include "config.h"
#include "crypto/ecdsa_verifier.h"
#include "crypto/nonce_manager.h"
#include "storage/key_store.h"

#include <SPI.h>
#include <PN532_SPI.h>
#include <PN532.h>

// Singleton
NfcAuthenticator nfcAuth;

// PN532 prin libraria elechouse
static PN532_SPI pn532spi(SPI, 5);
static PN532 nfcChip(pn532spi);

// Buffer pentru APDU-uri
#define APDU_BUF_SIZE 255
static uint8_t apduBuf[APDU_BUF_SIZE];
static uint8_t apduResp[APDU_BUF_SIZE];

// Helper: printHex local
static void logHex(const char* prefix, const uint8_t* data, size_t len) {
    Serial.print(prefix);
    for (size_t i = 0; i < len; i++) {
        Serial.print(" ");
        if (data[i] < 0x10) Serial.print("0");
        Serial.print(data[i], HEX);
    }
    Serial.println();
}

bool NfcAuthenticator::init() {
    nfcChip.begin();
    
    uint32_t version = nfcChip.getFirmwareVersion();
    if (!version) {
        Serial.println("[NFC] ✗ PN532 NU raspunde");
        available = false;
        return false;
    }
    
    Serial.print("[NFC] ✓ PN532 firmware: ");
    Serial.print((version >> 16) & 0xFF);
    Serial.print(".");
    Serial.println((version >> 8) & 0xFF);
    
    nfcChip.SAMConfig();
    available = true;
    return true;
}

void NfcAuthenticator::getLastDetectedUid(uint8_t* outUid, uint8_t* outLen, uint32_t* outAgoMs) {
    if (lastUidLen == 0) {
        *outLen = 0;
        *outAgoMs = 0;
        return;
    }
    memcpy(outUid, lastUid, lastUidLen);
    *outLen = lastUidLen;
    *outAgoMs = millis() - lastDetectedAt;
}

NfcAuthenticator::Result NfcAuthenticator::tick(char* outDeviceLabel, size_t labelBufSize, uint32_t* outLatencyMs) {
    if (!available) return NO_TAG;

    // 1. Detectare tag (timeout intern al librariei)
    if (!nfcChip.inListPassiveTarget()) {
        return NO_TAG;
    }
    
    uint32_t t0 = millis();
    *outLatencyMs = 0;
    
    Serial.println("\n[NFC] ─── Tag detectat ───");

    // 2. SELECT AID
    static const uint8_t APP_AID[] = APP_AID_HEX;
    apduBuf[0] = 0x00; apduBuf[1] = 0xA4; apduBuf[2] = 0x04; apduBuf[3] = 0x00;
    apduBuf[4] = APP_AID_LEN;
    memcpy(&apduBuf[5], APP_AID, APP_AID_LEN);
    apduBuf[5 + APP_AID_LEN] = 0x00;
    uint8_t selectLen = 6 + APP_AID_LEN;
    
    uint8_t respLen = APDU_BUF_SIZE;
    bool ok = nfcChip.inDataExchange(apduBuf, selectLen, apduResp, &respLen);
    
    if (!ok) {
        // SELECT a esuat — verificam daca e cartela MIFARE backup
        // Adafruit avea readPassiveTargetID care intoarcea UID-ul; elechouse
        // are inListPassiveTarget care nu-l expune direct, deci verificarea
        // MIFARE backup o vom face printr-un workflow usor diferit.
        // Pentru moment, raportam SELECT_FAILED.
        Serial.println("[NFC] SELECT AID esuat — telefon non-HCE sau MIFARE pasiv");
        return SELECT_FAILED;
    }
    
    if (respLen < 2 || apduResp[respLen-2] != 0x90 || apduResp[respLen-1] != 0x00) {
        Serial.print("[NFC] SELECT AID raspuns neasteptat: SW=");
        if (respLen >= 2) {
            Serial.print(apduResp[respLen-2], HEX);
            Serial.println(apduResp[respLen-1], HEX);
        } else Serial.println("(empty)");
        return SELECT_FAILED;
    }
    Serial.println("[NFC] ✓ SELECT AID → 9000");

    // 3. GET CHALLENGE
    const uint8_t* nonce = nonceManager.generate();
    
    apduBuf[0] = APDU_CLA_PROPRIETARY;
    apduBuf[1] = APDU_INS_GET_CHALLENGE;
    apduBuf[2] = 0x00;
    apduBuf[3] = 0x00;
    apduBuf[4] = 32; // Lc = 32 bytes nonce
    memcpy(&apduBuf[5], nonce, 32);
    
    respLen = APDU_BUF_SIZE;
    ok = nfcChip.inDataExchange(apduBuf, 37, apduResp, &respLen);
    
    if (!ok) {
        Serial.println("[NFC] GET CHALLENGE esuat (telefon miscat?)");
        return FLOW_INCOMPLETE;
    }
    
    // Raspunsul ar trebui sa fie: keyId (16B) + SW (9000)
    if (respLen != 18 || apduResp[16] != 0x90 || apduResp[17] != 0x00) {
        Serial.print("[NFC] GET CHALLENGE raspuns neasteptat: len=");
        Serial.println(respLen);
        return FLOW_INCOMPLETE;
    }
    
    uint8_t keyId[KEY_ID_LEN];
    memcpy(keyId, apduResp, KEY_ID_LEN);
    
    Serial.print("[NFC] ✓ GET CHALLENGE → keyId:");
    logHex("", keyId, KEY_ID_LEN);

    // 4. Verifica device in storage
    const EnrolledDevice* device = keyStore.findByKeyId(keyId);
    if (device == nullptr) {
        Serial.println("[NFC] ✗ KeyId necunoscut — telefon neinrolat");
        return UNKNOWN_DEVICE;
    }
    Serial.print("[NFC] Device recunoscut: ");
    Serial.println(device->deviceLabel);

    // 5. SIGN CHALLENGE
    // Construim mesajul (nonce 32 + doorId 4 + action 1 = 37B)
    uint8_t message[37];
    memcpy(message, nonce, 32);
    message[32] = (DOOR_ID >> 24) & 0xFF;
    message[33] = (DOOR_ID >> 16) & 0xFF;
    message[34] = (DOOR_ID >> 8) & 0xFF;
    message[35] = DOOR_ID & 0xFF;
    message[36] = ACTION_OPEN_DOOR;
    
    apduBuf[0] = APDU_CLA_PROPRIETARY;
    apduBuf[1] = APDU_INS_SIGN_CHALLENGE;
    apduBuf[2] = 0x00;
    apduBuf[3] = 0x00;
    apduBuf[4] = 37;
    memcpy(&apduBuf[5], message, 37);
    
    respLen = APDU_BUF_SIZE;
    ok = nfcChip.inDataExchange(apduBuf, 42, apduResp, &respLen);
    
    if (!ok) {
        Serial.println("[NFC] SIGN CHALLENGE esuat (telefon miscat?)");
        return FLOW_INCOMPLETE;
    }
    
    // Raspunsul: semnatura DER (~70-72B) + SW (9000)
    if (respLen < 4 || apduResp[respLen-2] != 0x90 || apduResp[respLen-1] != 0x00) {
        Serial.print("[NFC] SIGN CHALLENGE raspuns neasteptat, len=");
        Serial.println(respLen);
        return FLOW_INCOMPLETE;
    }
    
    uint8_t signatureLen = respLen - 2;
    Serial.print("[NFC] ✓ SIGN CHALLENGE → semnatura ");
    Serial.print(signatureLen);
    Serial.println("B");

    // 6. Verificare ECDSA cu cheia publica
    bool valid = EcdsaVerifier::verify(
        device->publicKey, device->publicKeyLen,
        message, 37,
        apduResp, signatureLen
    );
    
    if (!valid) {
        Serial.println("[NFC] ✗ Semnatura INVALIDA");
        return SIGNATURE_INVALID;
    }
    
    // 7. Anti-replay: consuma nonce-ul
    nonceManager.consume();
    
    *outLatencyMs = millis() - t0;
    strncpy(outDeviceLabel, device->deviceLabel, labelBufSize - 1);
    outDeviceLabel[labelBufSize - 1] = '\0';
    
    Serial.print("[NFC] ✓✓✓ ACCES PERMIS (");
    Serial.print(*outLatencyMs);
    Serial.println(" ms)");
    
    return SUCCESS;
}