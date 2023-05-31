package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Клас AlgoAES реалізує алгоритм шифрування і розшифрування AES (Advanced Encryption Standard).
 * Використовується 128-бітний ключ і режим роботи CBC (Cipher Block Chaining).
 *
 * Основні моменти:
 * - Реалізується шифрування і розшифрування AES з використанням ключа і вектора ініціалізації (iv).
 * - Використовується режим роботи CBC для шифрування більшого тексту шляхом поділу на блоки довжиною 16 байтів.
 * - Для шифрування і розшифрування використовуються методи заміни байтів, циклічного зсуву рядків,
 *   змішування стовпців та операції XOR.
 * - Реалізовані допоміжні методи для роботи з ключем, розширенням ключа та перетвореннями над станом AES.
 * - Забезпечується перевірка довжини блоку і викидання винятка, якщо вхідний текст не відповідає очікуваній довжині.
 *
 * Важливо: цей код призначений тільки для навчальних цілей та не має задовольняти вимоги безпеки для
 * реального застосування. Для справжнього застосування криптографічних операцій рекомендується
 * використовувати випробувані бібліотеки або криптографічні стандарти, що надаються фахівцями з безпеки.
 */
public class AlgoAES {
    private int actualRound;
    private int numRounds;
    private int[][][] stateArray;
    private static int numColumns = 4;
    private int[] originalKey;
    private byte[] initializationVector;
    private int numKeys;
    private int[] expandedKeys;

    public AlgoAES(byte[] originalKey, byte[] initializationVector) {
        initializeAES(originalKey, initializationVector);
    }

    /**
     * Ініціалізація шифру AES з вказаним ключем та ініціалізаційним вектором.
     *
     * @param key ключ для шифрування
     * @param iv ініціалізаційний вектор
     *
     * Опис:
     * Функція ініціалізує шифр AES з вказаним ключем та ініціалізаційним
     * вектором. Виконується перевірка довжини ключа та встановлення
     * відповідних значень для Nb, Nr та Nk в залежності від довжини ключа.
     * Після цього створюються необхідні масиви state та w та виконується
     * розширення ключа за допомогою функції expandKey().
     */
    private void initializeAES(byte[] key, byte[] iv) {
        this.initializationVector = iv;
        this.originalKey = new int[key.length];

        for (int i = 0; i < key.length; i++) {
            this.originalKey[i] = key[i];
        }

        numColumns = 4;

        int keyLength = key.length;
        switch (keyLength) {
            case 16:
                numRounds = 10;
                numKeys = 4;
                break;
            case 24:
                numRounds = 12;
                numKeys = 6;
                break;
            case 32:
                numRounds = 14;
                numKeys = 8;
                break;
            default:
                throw new IllegalArgumentException("It only supports 128, 192 and 256 bit keys!");
        }

        stateArray = new int[2][4][numColumns];
        expandedKeys = new int[numColumns * (numRounds + 1)];

        expandKey();
    }

    /**
     * Додавання ключа раунду до стану шифру.
     *
     * @param s стан шифру
     * @param round номер раунду
     * @return змінений стан шифру після додавання ключа раунду
     *
     * Опис:
     * Функція виконує додавання ключа раунду до стану шифру. Кожен елемент стану
     * шифру xor-ується з відповідним словом розширеного ключа для поточного раунду.
     * Операція xor виконується на рівні байтів, використовуючи біти зсуву.
     * Результатом є змінений стан шифру після додавання ключа раунду.
     */
    private int[][] addRoundKey(int[][] s, int round) {
        for (int c = 0; c < numColumns; c++) {
            for (int r = 0; r < 4; r++) {
                s[r][c] = s[r][c] ^ ((expandedKeys[round * numColumns + c] << (r * 8)) >>> 24);
            }
        }
        return s;
    }

    /**
     * Виконання шифрування AES для заданого блоку.
     *
     * @param in вхідний блок для шифрування
     * @param out вихідний блок після шифрування
     * @return вихідний блок після шифрування AES
     *
     * Опис:
     * Функція виконує шифрування AES для заданого блоку даних. Спочатку копіюється вхідний
     * блок до вихідного блоку. Потім виконується додавання ключа раунду до початкового стану.
     * Після цього виконуються Nr-1 раундів, кожен з яких включає підстановку байтів, зсув рядків,
     * змішування стовпців та додавання ключа раунду. На останньому раунді виконуються тільки
     * підстановка байтів, зсув рядків та додавання ключа раунду. Результатом є вихідний блок
     * після шифрування AES.
     */
    private int[][] makeCipher(int[][] in, int[][] out) {
        for (int i = 0; i < in.length; i++) {
            System.arraycopy(in[i], 0, out[i], 0, in[i].length);
        }

        actualRound = 0;
        addRoundKey(out, actualRound);

        for (actualRound = 1; actualRound < numRounds; actualRound++) {
            changeBytes(out);
            makeShiftForRows(out);
            mixColumns(out);
            addRoundKey(out, actualRound);
        }

        changeBytes(out);
        makeShiftForRows(out);
        addRoundKey(out, actualRound);

        return out;
    }

    /**
     * Виконання розшифрування AES для заданого блоку.
     *
     * @param in вхідний блок для розшифрування
     * @param out вихідний блок після розшифрування
     * @return вихідний блок після розшифрування AES
     *
     * Опис:
     * Функція виконує розшифрування AES для заданого блоку даних. Спочатку копіюється вхідний
     * блок до вихідного блоку. Потім виконується додавання ключа останнього раунду до початкового
     * стану. Після цього виконуються раунди від Nr-1 до 1, кожен з яких включає зсув рядків назад,
     * інверсну підстановку байтів, додавання ключа раунду та інверсне змішування стовпців.
     * На останньому раунді виконуються зсув рядків назад, інверсна підстановка байтів та додавання
     * ключа останнього раунду. Результатом є вихідний блок після розшифрування AES.
     */
    private int[][] makeDecipher(int[][] in, int[][] out) {
        for (int i = 0; i < in.length; i++) {
            System.arraycopy(in[i], 0, out[i], 0, in[i].length);
        }

        actualRound = numRounds;
        addRoundKey(out, actualRound);

        for (actualRound = numRounds - 1; actualRound > 0; actualRound--) {
            invMakeShiftForRows(out);
            invChangeBytes(out);
            addRoundKey(out, actualRound);
            invMixColumns(out);
        }

        invMakeShiftForRows(out);
        invChangeBytes(out);
        addRoundKey(out, actualRound);

        return out;
    }
    /**
     * Шифрування заданого тексту за допомогою AES.
     *
     * @param text текст для шифрування
     * @return зашифрований текст
     *
     * Опис:
     * Функція виконує шифрування заданого тексту за допомогою AES. Перевіряється, чи довжина тексту
     * дорівнює 16 байтам. Якщо ні, викидається виняток IllegalArgumentException. Створюється вихідний
     * масив для збереження зашифрованого тексту. Для кожної колонки (Nb) та рядка (4) вхідного
     * тексту, відбувається перетворення відповідного елементу в числове значення і зберігається в
     * стані (state[0]). Потім викликається функція шифрування AES (cipher), яка обробляє стан та
     * зберігає результат в стані (state[1]). Далі вихідні значення з стану (state[1]) перетворюються
     * назад у байти та зберігаються в вихідному масиві. Результатом є зашифрований текст.
     */
    private byte[] encryptText(byte[] text) {
        if (text.length != 16) {
            throw new IllegalArgumentException("Only 16-byte blocks can be encrypted");
        }

        byte[] out = new byte[text.length];

        for (int i = 0; i < numColumns; i++) {
            for (int j = 0; j < 4; j++) {
                stateArray[0][j][i] = text[i * numColumns + j] & 0xFF;
            }
        }

        makeCipher(stateArray[0], stateArray[1]);

        for (int i = 0; i < numColumns; i++) {
            for (int j = 0; j < 4; j++) {
                out[i * numColumns + j] = (byte) (stateArray[1][j][i] & 0xFF);
            }
        }

        return out;
    }

    /**
     * Розшифрування заданого тексту за допомогою AES.
     *
     * @param text текст для розшифрування
     * @return розшифрований текст
     *
     * Опис:
     * Функція виконує розшифрування заданого тексту за допомогою AES. Перевіряється, чи довжина тексту
     * дорівнює 16 байтам. Якщо ні, викидається виняток IllegalArgumentException. Створюється вихідний
     * масив для збереження розшифрованого тексту. Для кожної колонки (Nb) та рядка (4) вхідного
     * тексту, відбувається перетворення відповідного елементу в числове значення і зберігається в
     * стані (state[0]). Потім викликається функція розшифрування AES (decipher), яка обробляє стан та
     * зберігає результат в стані (state[1]). Далі вихідні значення з стану (state[1]) перетворюються
     * назад у байти та зберігаються в вихідному масиві. Результатом є розшифрований текст.
     */
    private byte[] decryptTextBytes(byte[] text) {
        if (text.length != 16) {
            throw new IllegalArgumentException("Only 16-byte blocks can be encrypted");
        }
        byte[] out = new byte[text.length];

        for (int i = 0; i < numColumns; i++) { // columns
            for (int j = 0; j < 4; j++) { // rows
                stateArray[0][j][i] = text[i * numColumns + j] & 0xff;
            }
        }

        makeDecipher(stateArray[0], stateArray[1]);
        for (int i = 0; i < numColumns; i++) {
            for (int j = 0; j < 4; j++) {
                out[i * numColumns + j] = (byte) (stateArray[1][j][i] & 0xff);
            }
        }
        return out;

    }
    /**
     * Змішування стовпців для оберненого розшифрування AES.
     *
     * @param state стан, що містить блок даних
     * @return змішані стовпці для оберненого розшифрування AES
     *
     * Опис:
     * Функція виконує змішування стовпців для оберненого розшифрування AES. Для кожного стовпця
     * (c) в стані, виконуються операції змішування стовпців з використанням константного множення
     * (0x0e, 0x0b, 0x0d, 0x09) та операції XOR. Результати зберігаються в тимчасових змінних
     * (temp0, temp1, temp2, temp3), а потім записуються назад до стану (state). Результатом є стан
     * змішаних стовпців для оберненого розшифрування AES.
     */
    private int[][] invMixColumns(int[][] state) {
        int temp0, temp1, temp2, temp3;
        for (int c = 0; c < numColumns; c++) {
            temp0 = multiply(0x0e, state[0][c]) ^ multiply(0x0b, state[1][c]) ^ multiply(0x0d, state[2][c]) ^ multiply(0x09, state[3][c]);
            temp1 = multiply(0x09, state[0][c]) ^ multiply(0x0e, state[1][c]) ^ multiply(0x0b, state[2][c]) ^ multiply(0x0d, state[3][c]);
            temp2 = multiply(0x0d, state[0][c]) ^ multiply(0x09, state[1][c]) ^ multiply(0x0e, state[2][c]) ^ multiply(0x0b, state[3][c]);
            temp3 = multiply(0x0b, state[0][c]) ^ multiply(0x0d, state[1][c]) ^ multiply(0x09, state[2][c]) ^ multiply(0x0e, state[3][c]);

            state[0][c] = temp0;
            state[1][c] = temp1;
            state[2][c] = temp2;
            state[3][c] = temp3;
        }
        return state;
    }
    /**
     * Зсув рядків для оберненого розшифрування AES.
     *
     * @param state стан, що містить блок даних
     * @return стан зі зсунутими рядками для оберненого розшифрування AES
     *
     * Опис:
     * Функція виконує зсув рядків для оберненого розшифрування AES. Виконується зсув кожного рядка
     * (крім першого рядка) вправо на певну кількість позицій. Кількість позицій визначається за
     * індексом рядка. Результатом є стан зі зсунутими рядками для оберненого розшифрування AES.
     */
    private int[][] invMakeShiftForRows(int[][] state) {
        int temp1, temp2, temp3, i;
        temp1 = state[1][numColumns - 1];
        for (i = numColumns - 1; i > 0; i--) {
            state[1][i] = state[1][(i - 1) % numColumns];
        }
        state[1][0] = temp1;
        temp1 = state[2][numColumns - 1];
        temp2 = state[2][numColumns - 2];
        for (i = numColumns - 1; i > 1; i--) {
            state[2][i] = state[2][(i - 2) % numColumns];
        }
        state[2][1] = temp1;
        state[2][0] = temp2;
        temp1 = state[3][numColumns - 3];
        temp2 = state[3][numColumns - 2];
        temp3 = state[3][numColumns - 1];
        for (i = numColumns - 1; i > 2; i--) {
            state[3][i] = state[3][(i - 3) % numColumns];
        }
        state[3][0] = temp1;
        state[3][1] = temp2;
        state[3][2] = temp3;

        return state;
    }

    /**
     * Обернена заміна байтів для оберненого розшифрування AES.
     *
     * @param state стан, що містить блок даних
     * @return стан зі заміненими байтами для оберненого розшифрування AES
     *
     * Опис:
     * Функція виконує обернену заміну байтів для оберненого розшифрування AES. Для кожного байта
     * в стані виконується обернена заміна застосуванням функції invSubWord(). Результатом є стан зі
     * заміненими байтами для оберненого розшифрування AES.
     */
    private int[][] invChangeBytes(int[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < numColumns; j++) {
                state[i][j] = invChanheWord(state[i][j]) & 0xFF;
            }
        }
        return state;
    }

    /**
     * Обернена заміна слова для оберненого розшифрування AES.
     *
     * @param word слово, яке потрібно обернено замінити
     * @return обернене замінене слово для оберненого розшифрування AES
     *
     * Опис:
     * Функція виконує обернену заміну слова для оберненого розшифрування AES. Циклом проходиться по
     * байтам слова з правого боку до лівого і застосовується обернена заміна застосуванням таблиці
     * rsBox[]. Результатом є обернене замінене слово для оберненого розшифрування AES.
     */
    private static int invChanheWord(int word) {
        int subWord = 0;
        for (int i = 24; i >= 0; i -= 8) {
            int in = word << i >>> 24;
            subWord |= rsBox[in] << (24 - i);
        }
        return subWord;
    }
    /**
     * Розширення ключа для шифрування AES.
     *
     * @return розширений ключ для шифрування AES
     *
     * Опис:
     * Функція виконує розширення ключа для шифрування AES. Спочатку заповнюється перші Nk слов зі
     * значеннями ключа. Далі, за допомогою циклу, розширюється ключ до Nb * (Nr + 1) слів. Кожне
     * наступне слово обчислюється на основі попереднього слова. В процесі розширення ключа
     * використовуються функції subWord(), rotWord() та rCon[] таблиця. Результатом є розширений ключ
     * для шифрування AES.
     */
    private int[] expandKey() {
        int temp, i = 0;
        while (i < numKeys) {
            expandedKeys[i] = 0x00000000;
            expandedKeys[i] |= originalKey[4 * i] << 24;
            expandedKeys[i] |= originalKey[4 * i + 1] << 16;
            expandedKeys[i] |= originalKey[4 * i + 2] << 8;
            expandedKeys[i] |= originalKey[4 * i + 3];
            i++;
        }
        i = numKeys;
        while (i < numColumns * (numRounds + 1)) {
            temp = expandedKeys[i - 1];
            if (i % numKeys == 0) {
                temp = changeWord(rotWord(temp)) ^ (rCon[i / numKeys] << 24);
            } else if (numKeys > 6 && (i % numKeys == 4)) {
                temp = changeWord(temp);
            } else {
            }
            expandedKeys[i] = expandedKeys[i - numKeys] ^ temp;
            i++;
        }
        return expandedKeys;
    }
    /**
     * Змішування стовпців для шифрування AES.
     *
     * @param state стан, що містить блок даних
     * @return стан зі змішаними стовпцями для шифрування AES
     *
     * Опис:
     * Функція виконує змішування стовпців для шифрування AES. Для кожного стовпця в стані
     * обчислюються нові значення шляхом застосування матричного множення над стовпцем з використанням
     * функції mult(). Результатом є стан зі змішаними стовпцями для шифрування AES.
     */
    private int[][] mixColumns(int[][] state) {
        int temp0, temp1, temp2, temp3;
        for (int c = 0; c < numColumns; c++) {

            temp0 = multiply(0x02, state[0][c]) ^ multiply(0x03, state[1][c]) ^ state[2][c] ^ state[3][c];
            temp1 = state[0][c] ^ multiply(0x02, state[1][c]) ^ multiply(0x03, state[2][c]) ^ state[3][c];
            temp2 = state[0][c] ^ state[1][c] ^ multiply(0x02, state[2][c]) ^ multiply(0x03, state[3][c]);
            temp3 = multiply(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ multiply(0x02, state[3][c]);

            state[0][c] = temp0;
            state[1][c] = temp1;
            state[2][c] = temp2;
            state[3][c] = temp3;
        }

        return state;
    }
    /**
     * Множення двох чисел в полі GF(2^8).
     *
     * @param a перше число
     * @param b друге число
     * @return результат множення двох чисел в полі GF(2^8)
     *
     * Опис:
     * Функція виконує множення двох чисел в полі GF(2^8) за допомогою операції "ксор" та операції
     * xtime(). Значення "ксор" зберігається у змінній sum. Цикл продовжується, поки перше число не
     * стане рівним 0. В кожній ітерації перше число зсувається вправо на 1 біт, а друге число
     * оновлюється відповідно до функції xtime(). Результатом є результат множення двох чисел в полі
     * GF(2^8).
     */
    private static int multiply(int a, int b) {
        int sum = 0;
        while (a != 0) {
            if ((a & 1) != 0) {
                sum = sum ^ b;
            }
            b = xMultiply(b);
            a = a >>> 1;
        }
        return sum;

    }

    private static int rotWord(int word) {
        return (word << 8) | ((word & 0xFF000000) >>> 24);
    }

    /**
     * Зсув рядків у стані AES.
     *
     * @param state стан
     * @return стан зі зсунутими рядками
     *
     * Опис:
     * Функція виконує зсув рядків у стані AES. Кожен рядок стану зсувається вліво на певну кількість
     * позицій. Перший рядок не зсувається, другий рядок зсувається вліво на 1 позицію, третій рядок
     * зсувається вліво на 2 позиції, а четвертий рядок зсувається вліво на 3 позиції. Зсув виконується
     * циклічно, тобто елемент, який виходить за межі рядка, повертається на початок рядка. Результатом
     * є стан зі зсунутими рядками.
     */
    private int[][] makeShiftForRows(int[][] state) {
        int temp1, temp2, temp3, i;
        temp1 = state[1][0];
        for (i = 0; i < numColumns - 1; i++) {
            state[1][i] = state[1][(i + 1) % numColumns];
        }
        state[1][numColumns - 1] = temp1;

        temp1 = state[2][0];
        temp2 = state[2][1];
        for (i = 0; i < numColumns - 2; i++) {
            state[2][i] = state[2][(i + 2) % numColumns];
        }
        state[2][numColumns - 2] = temp1;
        state[2][numColumns - 1] = temp2;

        temp1 = state[3][0];
        temp2 = state[3][1];
        temp3 = state[3][2];
        for (i = 0; i < numColumns - 3; i++) {
            state[3][i] = state[3][(i + 3) % numColumns];
        }
        state[3][numColumns - 3] = temp1;
        state[3][numColumns - 2] = temp2;
        state[3][numColumns - 1] = temp3;

        return state;
    }
    /**
     * Заміна байтів у стані AES.
     *
     * @param state стан
     * @return стан зі заміненими байтами
     *
     * Опис:
     * Функція виконує заміну байтів у стані AES. Кожен байт стану замінюється на його відповідний
     * згідно з нелінійною таблицею заміни S-Box. Заміна виконується незалежно для кожного байту в стані.
     * Результатом є стан зі заміненими байтами.
     */
    private int[][] changeBytes(int[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < numColumns; j++) {
                state[i][j] = changeWord(state[i][j]) & 0xFF;
            }
        }
        return state;
    }
    /**
     * Заміна слова у таблиці заміни.
     *
     * @param word слово
     * @return замінене слово
     *
     * Опис:
     * Функція виконує заміну слова у таблиці заміни. Кожен байт слова замінюється на його відповідний
     * згідно з нелінійною таблицею заміни S-Box. Заміна виконується незалежно для кожного байту в слові.
     * Результатом є замінене слово.
     */
    private static int changeWord(int word) {
        int subWord = 0;
        for (int i = 24; i >= 0; i -= 8) {
            int in = word << i >>> 24;
            subWord |= sBox[in] << (24 - i);
        }
        return subWord;
    }
    /**
     * Множення байту на x у полі Галуа.
     *
     * @param b байт
     * @return результат множення
     *
     * Опис:
     * Функція виконує множення байту на x у полі Галуа. Якщо старший біт байту дорівнює 0, то байт
     * зсувається вліво на 1 позицію. Якщо старший біт байту дорівнює 1, то байт зсувається вліво на 1
     * позицію і виконується побітове XOR з константою 0x11b. Результатом є множення байту на x у полі Галуа.
     */
    private static int xMultiply(int b) {
        if ((b & 0x80) == 0) {
            return b << 1;
        }
        return (b << 1) ^ 0x11b;
    }
    /**
     * Виконання побітової операції XOR над двома масивами байтів.
     *
     * @param a перший масив байтів
     * @param b другий масив байтів
     * @return результат побітової операції XOR
     *
     * Опис:
     * Функція виконує побітову операцію XOR над двома масивами байтів. Довжина результату
     * визначається як мінімум з довжин перших двох масивів. Кожний байт першого масиву
     * побітово XOR-ується з відповідним байтом другого масиву. Результатом є новий масив байтів.
     */
    private static byte[] makeXor(byte[] a, byte[] b) {
        byte[] result = new byte[Math.min(a.length, b.length)];
        for (int j = 0; j < result.length; j++) {
            int xor = a[j] ^ b[j];
            result[j] = (byte) (0xff & xor);
        }
        return result;
    }
    public byte[] encryptCBC(byte[] text) {
        byte[] previousBlock = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream(); // Буфер для зберігання зашифрованих блоків
        for (int i = 0; i < text.length; i += 16) {
            byte[] part = Arrays.copyOfRange(text, i, i + 16); // Вирізаємо блок довжиною 16 байтів
            try {
                if (previousBlock == null) {
                    previousBlock = initializationVector; // Якщо це перший блок, використовуємо вектор ініціалізації (iv)
                }
                part = makeXor(previousBlock, part); // Виконуємо операцію XOR між попереднім блоком та поточним блоком
                previousBlock = encryptText(part); // Шифруємо отриманий блок і отримуємо новий попередній блок
                out.write(previousBlock); // Записуємо зашифрований блок у вихідний буфер
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return out.toByteArray();
    }

    public byte[] decryptCBC(byte[] text) {
        byte[] previousBlock = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream(); // Буфер для зберігання розшифрованих блоків

        for (int i = 0; i < text.length; i += 16) {
            byte[] block = Arrays.copyOfRange(text, i, i + 16); // Вирізаємо блок довжиною 16 байтів
            byte[] decryptedBlock = decryptTextBytes(block); // Розшифровуємо отриманий блок

            try {
                if (previousBlock == null) {
                    previousBlock = initializationVector; // Якщо це перший блок, використовуємо вектор ініціалізації (iv)
                }

                decryptedBlock = makeXor(previousBlock, decryptedBlock); // Виконуємо операцію XOR між попереднім блоком та розшифрованим блоком

                previousBlock = block; // Записуємо поточний блок як попередній для наступної ітерації
                out.write(decryptedBlock); // Записуємо розшифрований блок у вихідний буфер
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return out.toByteArray();
    }

    private static int[] sBox = new int[] {

            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

    private static int[] rsBox = new int[] {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

    private static int[] rCon = new int[] {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d };


}


class Main{
    private static byte[] encruptWithJavaLib(byte[] key, byte[] initVector, byte[] value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value);

            return encrypted;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private static byte[] textToBytes(String text) {
        int spaceNum = text.getBytes().length%16==0?0:16-text.getBytes().length%16;
        for (int i = 0; i<spaceNum; i++) text += " ";
        return text.getBytes();
    }

    public static void main(String[] args) {
        System.out.println("\n~~~ javaCryptoTest ~~~\n");
        System.out.println("AES 128 CBC");

        byte[] inputText = "VLAD BLOSHENKO".getBytes();
        byte[] key = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        byte[] iv = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};


        byte[] chipredTextWithAlgo = new AlgoAES(key, iv).encryptCBC(inputText);
        byte[] chipredTextWithLib = encruptWithJavaLib(key, iv, textToBytes(String.valueOf(inputText)));
        System.out.println(chipredTextWithLib);
        System.out.println(chipredTextWithAlgo);
        System.out.println(new String(new AlgoAES(key, iv).decryptCBC(chipredTextWithLib)));
        System.out.println(new String(new AlgoAES(key, iv).decryptCBC(chipredTextWithAlgo)));
}

};