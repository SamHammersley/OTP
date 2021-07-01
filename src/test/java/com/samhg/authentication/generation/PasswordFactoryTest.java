package com.samhg.authentication.generation;

import com.google.common.primitives.Longs;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * All expected values generated using FreeOTP by Red Hat
 */
public final class PasswordFactoryTest {

    @Test
    public void testGeneratePassword_HmacSHA1_6() {
        testGeneratePassword(HmacAlgorithm.SHA1, 6, 0, "257225");
        testGeneratePassword(HmacAlgorithm.SHA1, 6, 1, "299396");
        testGeneratePassword(HmacAlgorithm.SHA1, 6, 2, "538728");
    }

    @Test
    public void testGeneratePassword_HmacSHA1_8() {
        testGeneratePassword(HmacAlgorithm.SHA1, 8, 3, "47975654");
        testGeneratePassword(HmacAlgorithm.SHA1, 8, 4, "56886874");
        testGeneratePassword(HmacAlgorithm.SHA1, 8, 5, "36361366");
    }

    @Test
    public void testGeneratePassword_HmacSHA256_6() {
        testGeneratePassword(HmacAlgorithm.SHA256, 6, 6, "768910");
        testGeneratePassword(HmacAlgorithm.SHA256, 6, 7, "620107");
        testGeneratePassword(HmacAlgorithm.SHA256, 6, 8, "666127");
    }

    @Test
    public void testGeneratePassword_HmacSHA256_8() {
        testGeneratePassword(HmacAlgorithm.SHA256, 8, 9, "94313931");
        testGeneratePassword(HmacAlgorithm.SHA256, 8, 10, "95873947");
        testGeneratePassword(HmacAlgorithm.SHA256, 8, 11, "40584582");
    }

    @Test
    public void testGeneratePassword_HmacSHA512_6() {
        testGeneratePassword(HmacAlgorithm.SHA512, 6, 12, "064583");
        testGeneratePassword(HmacAlgorithm.SHA512, 6, 13, "304443");
        testGeneratePassword(HmacAlgorithm.SHA512, 6, 14, "995816");
    }

    @Test
    public void testGeneratePassword_HmacSHA512_8() {
        testGeneratePassword(HmacAlgorithm.SHA512, 8, 15, "62749084");
        testGeneratePassword(HmacAlgorithm.SHA512, 8, 16, "58980423");
        testGeneratePassword(HmacAlgorithm.SHA512, 8, 17, "77809971");
    }

    private static final byte[] SECRET_KEY = { 20, -37, 28, 73, -53, 23, -2, -59, 70, 89 };

    private void testGeneratePassword(HmacAlgorithm algorithm, int digits, long counter, String expectedValue) {
        byte[] movingFactor = Longs.toByteArray(counter);

        PasswordFactory factory = new PasswordFactory();
        String actualValue = factory.generatePassword(SECRET_KEY, movingFactor, algorithm, digits);

        assertEquals(expectedValue, actualValue);
    }

}