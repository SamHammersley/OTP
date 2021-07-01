package com.samhg.authentication.key;

import java.security.SecureRandom;

public final class SharedSecretProvider {
	
	/**
	 * {@link SecureRandom} instance that is periodically re-seeded.
	 */
	private final ReseedingSecureRandom random = new ReseedingSecureRandom();
	
	/**
	 * Factory method for creating {@link SharedSecret}s.
	 * 
	 * @return a {@link SharedSecret} instance.
	 */
	public SharedSecret createKey() {
		byte[] key = random.getNextBytes(KeyConstants.KEY_SIZE);

		return new SharedSecret(key, KeyConstants.ENCODING_SCHEME.encode(key));
	}

}