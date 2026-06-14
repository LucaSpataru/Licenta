#ifndef HEX_UTILS_H
#define HEX_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <Arduino.h>

namespace HexUtils {

/**
 * Converteste un string hex in byte array.
 * Accepta spatii in input (le ignora). Litere mari sau mici.
 * 
 * @param hex   String-ul hex de intrare (ex: "AB CD EF" sau "abcdef")
 * @param out   Buffer-ul de output (alocat de apelant)
 * @param maxOutLen Capacitatea maxima a buffer-ului
 * @return Numarul de bytes scrisi, sau -1 la eroare
 */
int hexToBytes(const String& hex, uint8_t* out, size_t maxOutLen);

/**
 * Converteste un byte array in string hex (litere mari, fara separatori).
 */
String bytesToHex(const uint8_t* data, size_t len);

/**
 * Printeaza un byte array in Serial, cu prefix si separatori de spatiu.
 */
void printHex(const char* prefix, const uint8_t* data, size_t len);

} // namespace HexUtils

#endif // HEX_UTILS_H