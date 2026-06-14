#include "util/hex_utils.h"

namespace HexUtils {

static int charToHex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int hexToBytes(const String& hex, uint8_t* out, size_t maxOutLen) {
    size_t outIdx = 0;
    int nibble = -1; // -1 = asteptam primul nibble; altfel = primul nibble citit

    for (size_t i = 0; i < hex.length(); i++) {
        char c = hex.charAt(i);
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ':') continue;

        int n = charToHex(c);
        if (n < 0) return -1; // caracter invalid

        if (nibble < 0) {
            nibble = n;
        } else {
            if (outIdx >= maxOutLen) return -1; // overflow
            out[outIdx++] = (nibble << 4) | n;
            nibble = -1;
        }
    }

    if (nibble >= 0) return -1; // nibble impar la sfarsit
    return (int)outIdx;
}

String bytesToHex(const uint8_t* data, size_t len) {
    String result;
    result.reserve(len * 2);
    static const char hexChars[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        result += hexChars[(data[i] >> 4) & 0x0F];
        result += hexChars[data[i] & 0x0F];
    }
    return result;
}

void printHex(const char* prefix, const uint8_t* data, size_t len) {
    Serial.print(prefix);
    Serial.print(" (");
    Serial.print(len);
    Serial.print("B): ");
    for (size_t i = 0; i < len; i++) {
        if (data[i] < 0x10) Serial.print("0");
        Serial.print(data[i], HEX);
        if (i < len - 1 && (i + 1) % 16 != 0) Serial.print(" ");
        if ((i + 1) % 16 == 0 && i < len - 1) {
            Serial.println();
            Serial.print("              ");
        }
    }
    Serial.println();
}

} // namespace HexUtils