package com.samhg.authentication.generation;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.samhg.authentication.key.SharedSecret;

/**
 * Generates One Time Passwords as outlined in RFC 4226.
 */
public final class PasswordFactory {

	/**
	 * Bit mask to truncate the most significant bit of the 32-bit password.
	 */
	private static final int TRUNCATION_BIT_MASK = ~(1 << 31);

	/**
	 * The number of bytes the {@link #extractPassword(byte[], int)} should take from the generated HMAC.
	 */
	private static final int DYNAMIC_TRUNCATION_LENGTH = 4;

	/**
	 * Generates HMAC and then extracts one-time password from said HMAC.
	 *
	 * @param rawSecret randomly generated raw data, shared privately, that makes up the {@link SharedSecret}.
	 * @param movingFactor he data, dependent on authentication implementation (time step or counter).
	 * @param algorithm the hashing algorithm used to create a HMAC.
	 * @param digits the number of digits the password should be, this value should be between 6 and 8.
	 * @return a (6-digit) one time password.
	 */
	public String generatePassword(byte[] rawSecret, byte[] movingFactor, HmacAlgorithm algorithm, int digits) {
		try {
			byte[] hmac = createHMAC(algorithm, rawSecret, movingFactor);
			int dt = extractPassword(hmac, digits);

			return pad(dt, digits);

		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			throw new RuntimeException("Failed to create HMAC!", e);
		}
	}

	/**
	 * Left pads truncated passwords with 0s.
	 *
	 * @param number the number to pad.
	 * @param digits the desired length of the password.
	 * @return the number parameter as a string with 0s at the start, if necessary.
	 */
	private String pad(int number, int digits) {
		String password = Integer.toString(number);
		int padSize = digits - password.length();

		return "0".repeat(padSize) + password;
	}

	/**
	 * This function selects 4 bytes of data from the given hash-based message
	 * authentication code and combines them in a 32-bit integer (as defined
	 * in RFC 4226).
	 *
	 * Due to primitive data types being signed, the most significant bit of
	 * the resulting integer is truncated.
	 *
	 * To limit the result to 6 figures, we do some modular arithmetic where
	 * the divisor is <code>1_000_000</code>. This means that one-time passwords are limited
	 * to <code>999_999</code>.
	 *
	 * This is referred to as dynamic truncation in the RFC documentation.
	 *
	 * @param hmac the hash-based message authentication code to pull the password from.
	 * @param digits the password length.
	 * @return the password extracted from the specified HMAC.
	 */
	private int extractPassword(byte[] hmac, int digits) {
		int offset = hmac[hmac.length - 1] & 0xF;
		int divisor = (int) Math.pow(10, digits);
		int password = 0;

		for (int i = offset; i < offset + DYNAMIC_TRUNCATION_LENGTH; ++i) {
			password <<= Byte.BYTES * 8;
			password += (hmac[i] & 0xFF);
		}

		return (password & TRUNCATION_BIT_MASK) % divisor;
	}

	/**
	 * Creates a (Hash-based) Message Authentication Code using the specified hash function,
	 * key and message.
	 *
	 * @param key the key that is combined with the moving factor.
	 * @param movingFactor the data that is combined with the key.
	 * @return a hash-based message authentication code created by hashing the key and message.
	 */
	private byte[] createHMAC(HmacAlgorithm algorithm, byte[] key, byte[] movingFactor)
			throws NoSuchAlgorithmException, InvalidKeyException {

		String algorithmName = algorithm.getName();
		Mac mac = Mac.getInstance(algorithmName);
		mac.init(new SecretKeySpec(key, algorithmName));

		return mac.doFinal(movingFactor);
	}

}