package com.samhg.authentication;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.samhg.authentication.key.SharedSecret;

public final class PasswordFactory {
	
	/**
	 * Hash algorithm used to create HMACs.
	 */
	private static final String HMAC_ALGORITHM = "HmacSHA1";

	/**
	 * This constant is the divisor of the modulus operation to limit passwords
	 * to 6 figures.
	 */
	private static final int PASSWORD_MODULUS_DIVISOR = (int) Math.pow(10, 6);
	
	/**
	 * Size of the Hash-based message authentication code, in bytes.
	 */
	private static final int HMAC_SIZE = 20;
	
	/**
	 * Bit mask to truncate the most significant bit of the 32-bit password.
	 */
	private static final int TRUNCATION_BIT_MASK = ~(1 << 31);
	
	/**
	 * {@link Logger} instance for logging output.
	 */
	private static final Logger LOGGER = Logger.getLogger(PasswordFactory.class.getName());
	
	/**
	 * Creates HMAC and then extracts one-time password from said HMAC.
	 *
	 * @param rawSecret randomly generated raw data, shared privately, that makes up
	 *            the {@link SharedSecret}.
	 * @param message the data, dependent on authentication implementation.
	 * 
	 * @return a (6-digit) one time password.
	 */
	public int createPassword(byte[] rawSecret, byte[] message) {
		byte[] hash = new byte[HMAC_SIZE];
		try {
			hash = createHMAC(rawSecret, message);
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			LOGGER.log(Level.SEVERE, "Failed to create HMAC", e);
		}
		return extractPassword(hash);
	}

	/**
	 * This function selects 4 bytes of data from the given hash-based message
	 * authentication code and combines them in a 32-bit integer.
	 * 
	 * Due to primitive data types being signed, the most significant bit of
	 * the resulting integer is truncated.
	 * 
	 * To limit the result to 6 figures, we do some modular arithmetic where
	 * the divisor is <code>1_000_000</code>. This means that one-time passwords are limited
	 * to <code>999_999</code>.
	 * 
	 * @param hmac the hash-based message authentication code to pull the password from.
	 * This is, essentially, random data combined with the current Unix time.
	 * 
	 * @return the password extracted from the specified HMAC.
	 */
	private int extractPassword(byte[] hmac) {	
		int offset = hmac[hmac.length - 1] & 0xF;
		int password = 0;
		
		for (int i = offset; i < offset + 4; ++i) {
			password <<= 8;
			password += (hmac[i] & 0xFF);
		}
		
		password &= TRUNCATION_BIT_MASK;
		return password %= PASSWORD_MODULUS_DIVISOR;
	}

	/**
	 * Creates a (Hash-based) Message Authentication Code using the specified hash function,
	 * key and message.
	 * 
	 * @param key the key that is combined with the message.
	 * @param message the data that is combined with the key.
	 * 
	 * @return a hash-based message authentication code created by hashing the key and message.
	 */
	private byte[] createHMAC(byte[] key, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance(HMAC_ALGORITHM);
		mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
		
		return mac.doFinal(message);
	}

}