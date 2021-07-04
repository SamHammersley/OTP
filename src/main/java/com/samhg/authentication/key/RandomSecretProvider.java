package com.samhg.authentication.key;

import java.security.SecureRandom;

public final class RandomSecretProvider implements SharedSecretProvider {

	/**
	 * {@link SecureRandom} instance that is periodically re-seeded.
	 */
	private final ReseedingSecureRandom random = new ReseedingSecureRandom();
	
	@Override
	public SharedSecret createSecret() {
		byte[] key = random.getNextBytes(KeyConstants.KEY_SIZE);

		return new SharedSecret(key, KeyConstants.KEY_ENCODING_SCHEME.encode(key));
	}

}