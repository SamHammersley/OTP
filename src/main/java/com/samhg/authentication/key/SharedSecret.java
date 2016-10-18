package com.samhg.authentication.key;

/**
 * Represents a secret, privately shared (between the user and the supplier).
 */
public final class SharedSecret {
	
	/**
	 * The raw secret data.
	 */
	private final byte[] secret;
	
	/**
	 * {@link #secret} encoded using base32.
	 */
	private final String encodedSecret;
	
	/**
	 * Constructs a new instance.
	 * 
	 * @param secret the raw secret data
	 * @param encodedSecret a human-readable string representation encoded using base32.
	 */
	public SharedSecret(byte[] secret, String encodedSecret) {
		this.secret = secret;
		this.encodedSecret = encodedSecret;
	}
	
	/**
	 * Gets the secret.
	 * 
	 * @return the secret data in a byte array.
	 */
	public byte[] getSecret() {
		return secret;
	}
	
	/**
	 * Gets a human-readable string representation, encoded using base32, of the secret.
	 * 
	 * @return
	 */
	public String getEncodedSecret() {
		return encodedSecret;
	}
	
}