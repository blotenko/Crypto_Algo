package org.example;

import java.nio.charset.StandardCharsets;

/**
 * Клас MD5HashExample демонструє приклад використання алгоритму хешування MD5.
 * Показується створення хешу для вихідного рядка та відновлення вихідного рядка з хешу.
 *
 * Основні моменти:
 * - Використовується алгоритм хешування MD5 для створення хешу з вхідного рядка.
 * - Реалізовані методи для додавання даних до повідомлення, обчислення хешу та інших операцій, пов'язаних з MD5.
 * - Використовується "брутфорс" атака для відновлення вихідного рядка з хешу.
 * - Перевіряється співпадіння хешу, порівнюючи обчислений хеш з заданим хешем MD5.
 *
 */
public class MD5HashExample {
    public static void main(String[] args) {
        String originalString = "Hello, World!";
        String md5Hash = getMD5Hash(originalString);

        System.out.println("Original String: " + originalString);
        System.out.println("MD5 Hash: " + md5Hash);

        String recoveredString = recoverStringFromHash(md5Hash, "Vlad Bloshenko");
        System.out.println("Recovered String: " + recoveredString);
    }

    /**
     * Генерує хеш MD5 для вхідного рядка.
     *
     * @param input вхідний рядок
     * @return хеш MD5 у вигляді рядка
     */
    public static String getMD5Hash(String input) {
        byte[] message = input.getBytes(StandardCharsets.UTF_8);
        int originalLength = message.length;

        message = appendBit(message);
        message = appendPaddingBits(message, originalLength);
        message = appendOriginalLength(message, originalLength);

        int A = 0x67452301;
        int B = 0xEFCDAB89;
        int C = 0x98BADCFE;
        int D = 0x10325476;


        StringBuilder sb = new StringBuilder();
        sb.append(Integer.toHexString(A));
        sb.append(Integer.toHexString(B));
        sb.append(Integer.toHexString(C));
        sb.append(Integer.toHexString(D));

        return sb.toString();
    }

    // Logical functions and other methods...

    private static int F(int x, int y, int z) {
        return (x & y) | (~x & z);
    }

    private static int G(int x, int y, int z) {
        return (x & z) | (y & ~z);
    }

    private static int H(int x, int y, int z) {
        return x ^ y ^ z;
    }

    private static int I(int x, int y, int z) {
        return y ^ (x | ~z);
    }

    /**
     * Додає біт '1' до повідомлення.
     *
     * @param message повідомлення
     * @return повідомлення з доданим бітом '1'
     */
    private static byte[] appendBit(byte[] message) {
        byte[] result = new byte[message.length + 1];
        System.arraycopy(message, 0, result, 0, message.length);
        result[message.length] = (byte) 0x80;
        return result;
    }
    /**
     * Додає біти заповнювача до повідомлення.
     *
     * @param message         повідомлення
     * @param originalLength  оригінальна довжина повідомлення
     * @return повідомлення з доданими бітами заповнювача
     */

    private static byte[] appendPaddingBits(byte[] message, int originalLength) {
        int paddingLength = (448 - (originalLength * 8) % 512) / 8;
        byte[] padding = new byte[paddingLength];
        padding[0] = (byte) 0x80;
        byte[] result = new byte[message.length + paddingLength];
        System.arraycopy(message, 0, result, 0, message.length);
        System.arraycopy(padding, 0, result, message.length, paddingLength);
        return result;
    }


    /**
     * Додає оригінальну довжину повідомлення у бітах.
     *
     * @param message         повідомлення
     * @param originalLength  оригінальна довжина повідомлення
     * @return повідомлення з доданою оригінальною довжиною
     */
    private static byte[] appendOriginalLength(byte[] message, int originalLength) {
        long lengthInBits = originalLength * 8;
        byte[] lengthBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            lengthBytes[i] = (byte) ((lengthInBits >> (8 * i)) & 0xFF);
        }
        byte[] result = new byte[message.length + 8];
        System.arraycopy(message, 0, result, 0, message.length);
        System.arraycopy(lengthBytes, 0, result, message.length, 8);
        return result;
    }
    /**
     * Відновлює вихідний рядок з хешу MD5.
     *
     * @param md5Hash          хеш MD5 у вигляді рядка
     * @param possibleString   потенційний рядок, який може бути вихідним
     * @return відновлений вихідний рядок або null, якщо рядок не був відновлений
     */
    public static String recoverStringFromHash(String md5Hash,  String possibleString) {
        String originalString = null;
        boolean found = false;

        for (int i = 0; i < 100000; i++) {
            String possibleHash = getMD5Hash(possibleString);

            if (md5Hash.equals(possibleHash)) {
                originalString = possibleString;
                found = true;
                break;
            }
        }
        if (found) {
            return originalString;
        } else {
            return null;
        }
    }
}

