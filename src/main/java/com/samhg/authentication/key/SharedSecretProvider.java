package com.samhg.authentication.key;

import java.security.SecureRandom;

import com.google.common.io.BaseEncoding;

public final class SharedSecretProvider {
	
	/**
	 * {@link SecureRandom} instance that is periodically re-seeded.
	 */
	private final ReseedingSecureRandom random = new ReseedingSecureRandom();

	/**
	 * The encoding scheme used for encoding the secret key.
	 * 
	 * As specified by RFC 4226, base32 is used to encode secret keys.
	 */
	private static final BaseEncoding ENCODING_SCHEME = BaseEncoding.base32();
	
	/**
	 * The size of the raw key in bytes.
	 */
	private static final int KEY_SIZE = 10;
	
	/**
	 * Factory method for creating {@link SharedSecret}s.
	 * 
	 * @return a {@link SharedSecret} instance.
	 */
	public SharedSecret createKey() {
		byte[] key = random.getNextBytes(KEY_SIZE);
		return new SharedSecret(key, ENCODING_SCHEME.encode(key));
	}
	
}