package com.samhg.authentication.key;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

public final class ReseedingSecureRandom {

	/**
	 * A {@link SecureRandom} for PRNG.
	 */
	private SecureRandom random;
	
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
	 * Checks if random needs to be re-instantiated {@link #random} in order to
	 * re-seed and does so if needs be.
	 * 
	 * This method should be called before any use of {@link #random} to assure that
	 * it is re-seeded periodically.
	 */
	private void updateRandom() {
		if (random == null || callCount++ >= MAXIMUM_CALLS || System.nanoTime() - lastUpdate >= MAXIMUM_TIME_DELTA) {
			try {
				random = SecureRandom.getInstance(ALGORITHM, PROVIDER);
				lastUpdate = System.nanoTime();
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				// Shouldn't ever really happen.
				throw new RuntimeException("Failed getting SecureRandom instance.", e);
			}
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