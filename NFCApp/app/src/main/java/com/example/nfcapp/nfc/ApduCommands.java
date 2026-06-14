package com.example.nfcapp.nfc;

import com.example.nfcapp.util.HexUtils;

/**
 * Constante pentru protocolul APDU custom intre telefon (HCE) si ESP32 (PN532).
 *
 * AID-ul aplicatiei: F0010203040506 (7 bytes, range proprietar 0xF0)
 * Trebuie sa fie identic cu cel din res/xml/apduservice.xml si cu cel din firmware-ul ESP32.
 *
 * Comenzi suportate:
 *   SELECT AID         — comanda standard ISO 7816-4
 *   GET CHALLENGE      — telefonul primeste un nonce de 32B (Lc=32) si raspunde cu KeyId
 *   SIGN CHALLENGE     — telefonul primeste mesaj (37B) si raspunde cu semnatura DER
 *
 * Status words returnate:
 *   9000 — success
 *   6A82 — AID not found / file not found
 *   6985 — conditions not satisfied (ex: cheia nu e generata)
 *   6700 — wrong length
 *   6F00 — internal error
 */
public class ApduCommands {

    /** AID-ul aplicatiei, ca string hex (pentru comparatii/logging). */
    public static final String AID_HEX = "F0010203040506";

    /** AID-ul ca byte array. */
    public static final byte[] AID = HexUtils.hexToBytes(AID_HEX);

    // ===== CLA bytes =====
    public static final byte CLA_ISO = 0x00;        // ISO standard
    public static final byte CLA_PROPRIETARY = (byte) 0x80; // comenzile noastre custom

    // ===== INS bytes =====
    public static final byte INS_SELECT = (byte) 0xA4;   // SELECT AID (ISO)
    public static final byte INS_GET_CHALLENGE = (byte) 0x10; // proprietar: primeste nonce, returneaza KeyId
    public static final byte INS_SIGN_CHALLENGE = (byte) 0x20; // proprietar: primeste mesaj, returneaza semnatura

    // ===== Status words =====
    public static final byte[] SW_SUCCESS = {(byte) 0x90, (byte) 0x00};
    public static final byte[] SW_AID_NOT_FOUND = {(byte) 0x6A, (byte) 0x82};
    public static final byte[] SW_CONDITIONS_NOT_SATISFIED = {(byte) 0x69, (byte) 0x85};
    public static final byte[] SW_WRONG_LENGTH = {(byte) 0x67, (byte) 0x00};
    public static final byte[] SW_INS_NOT_SUPPORTED = {(byte) 0x6D, (byte) 0x00};
    public static final byte[] SW_INTERNAL_ERROR = {(byte) 0x6F, (byte) 0x00};

    /**
     * Concateneaza un payload cu un status word, returnand raspunsul APDU complet.
     */
    public static byte[] response(byte[] payload, byte[] sw) {
        if (payload == null || payload.length == 0) return sw;
        byte[] result = new byte[payload.length + sw.length];
        System.arraycopy(payload, 0, result, 0, payload.length);
        System.arraycopy(sw, 0, result, payload.length, sw.length);
        return result;
    }
}