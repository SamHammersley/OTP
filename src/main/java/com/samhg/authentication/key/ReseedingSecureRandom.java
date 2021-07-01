package com.samhg.authentication.key;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

public final class ReseedingSecureRandom {

	/**
	 * A {@link SecureRandom} for PRNG.
	 */
	private final SecureRandom random = getInstance();
	
	/**
	 * The amount of times {@link #random} has been used.
	 */
	private int callCount;
	
	/**
	 * The time at which {@link #random} was previously updated.
	 */
	private long lastUpdate;
	
	/**
	 * Maximum amount of calls before {@link #random} should be re-seeded.
	 */
	private static final int MAXIMUM_CALLS = 1_000_000;
	
	/**
	 * Maximum amount of time before re-seeding is required.
	 */
	private static final long MAXIMUM_TIME_DELTA = TimeUnit.MINUTES.toMillis(10);

	/**
	 * Algorithm name and provider used by {@link #random} for PRNG.
	 */
	private static final String ALGORITHM = "SHA1PRNG", PROVIDER = "SUN";
	
	/**
	 * Checks if random requires reseeding. This is the case when there have been either {@link #MAXIMUM_CALLS} or
	 * {@link #MAXIMUM_TIME_DELTA} has elapsed between calls to the random.
	 * 
	 * This method should be called before any use of {@link #random} to assure that
	 * it is re-seeded periodically.
	 */
	private void updateRandom() {
		if (callCount++ >= MAXIMUM_CALLS || System.nanoTime() - lastUpdate >= MAXIMUM_TIME_DELTA) {
			return;
		}

		random.reseed();
		lastUpdate = System.nanoTime();
	}

	/**
	 * Gets an instance of {@link SecureRandom} using {@link #ALGORITHM} and {@link #PROVIDER} as the
	 * algorithm and provider parameters respectively.
	 *
	 * @return a {@link SecureRandom} instance.
	 */
	private SecureRandom getInstance() {
		try {
			return SecureRandom.getInstance(ALGORITHM, PROVIDER);

		} catch (GeneralSecurityException e) {
			throw new RuntimeException("Failed to get SecureRandom instance.");
		}
	}

	/**
	 * Gets the next bytes from {@link #random} and stores them in an array.
	 * 
	 * @param size the size of the array.
	 * @return an array of random bytes.
	 */
	public byte[] getNextBytes(int size) {
		updateRandom();

		byte[] bytes = new byte[size];
		random.nextBytes(bytes);

		return bytes;
	}
	
	/**
	 * Gets {@link #random} and calls {@link #updateRandom}
	 * 
	 * @return
	 */
	public SecureRandom getSecureRandom() {
		updateRandom();
		
		return random;
	}
	
}