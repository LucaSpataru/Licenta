package com.example.nfcapp.util;

/**
 * Utilitare pentru conversie intre byte arrays si reprezentare hexazecimala.
 */
public class HexUtils {

    private static final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();

    /**
     * Converteste byte array in string hex, fara separatori.
     * Ex: [0xAB, 0xCD] → "ABCD"
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        char[] result = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            result[i * 2] = HEX_CHARS[v >>> 4];
            result[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(result);
    }

    /**
     * Converteste byte array in string hex grupat pe cate 16 bytes pe linie,
     * cu spatii intre bytes — pentru afisare lizibila in UI.
     */
    public static String bytesToHexPretty(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0 && i % 16 == 0) sb.append("\n");
            else if (i > 0) sb.append(" ");
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Converteste string hex in byte array.
     * Ex: "ABCD" → [0xAB, 0xCD]
     * Accepta litere mari sau mici. Nu accepta separatori.
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null) throw new IllegalArgumentException("hex e null");
        hex = hex.replaceAll("\\s+", ""); // toleram spatii
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("String hex cu lungime impara: " + hex.length());
        }
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("Caracter non-hex in pozitia " + (i * 2));
            }
            result[i] = (byte) ((hi << 4) | lo);
        }
        return result;
    }
}
