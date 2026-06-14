package com.example.nfcapp.util;

/**
 conversie byte arrays - hexadecimal
 */
public class HexUtils {

    private static final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();

    /**
     converteste byte array in string hex
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
     converteste hex in byte array
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null) throw new IllegalArgumentException("hex e null");
        hex = hex.replaceAll("\\s+", "");
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("lungime impara: " + hex.length());
        }
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("caracter non-hex in pozitia " + (i * 2));
            }
            result[i] = (byte) ((hi << 4) | lo);
        }
        return result;
    }
}
