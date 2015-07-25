package authentication.keys;

import com.google.common.cache.Cache;

/**
 * A class that gets, caches and stores secret keys for a given identifier.
 * 
 * @author Sam
 */
public abstract class KeyCache {

	/**
	 * A {@link Cache} that holds entries for specific amount of time before
	 * they expire.
	 */
	private final Cache<String, String> cache;

	/**
	 * Constructs a new {@link KeyCache}.
	 */
	public KeyCache(Cache<String, String> cache) {
		this.cache = cache;
	}

	/**
	 * Gets the secret key for the specified identifier. It will first check
	 * the cache before invoking {@link #load}, if the cache does not contain
	 * a key for the specified identifier, it will call the {@link #load} method.
	 * 
	 * @param identifier the identifier that is associated with the secret key
	 * 	to get. This parameter acts as an identifier for the secret key.
	 * @return the secret key for the specified identifier.
	 * @throws Exception when loading the secret key.
	 */
	public String get(String identifier) throws Exception {
		String secretKey = cache.getIfPresent(identifier);
		if (secretKey == null) {
			secretKey = load(identifier);
		}
		return secretKey;
	}

	/**
	 * Loads the secret key for the specified identifier.
	 * 
	 * <p>This method should be grabbing data from an external
	 * file or database.</p>
	 *
	 * @param identifier the identifier.
	 * @return the secret key.
	 * @throws Exception may or may not throw exception.
	 */
	protected abstract String load(String identifier) throws Exception;
	
	/**
	 * Puts the secret key associated with the identifier in the cache.
	 * It will check that the key is cached, if it's not it will cache the
	 * key and then invoke {@link #store} method.
	 * 
	 * @param identifier the identifier that is associated with the secret key
	 * 	to get. This parameter acts as an identifier for the secret key.
	 * @param secretKey the secretKey that is actually going to be stored.
	 * @throws Exception when storing the key. (this may be an IOException or SQLException, depending on implementation.)
	 */
	public void put(String identifier, String secretKey) throws Exception {
		String cached = cache.getIfPresent(identifier);
		if (cached == null) {
			cache.put(identifier, secretKey);
		}
		store(identifier, secretKey);
	}

	/**
	 * Stores a secret key value assigned to an identifier.
	 * 
	 * <p>The data passed to this method should be stored in an
	 * external file or database.</p>
	 * 
	 * @param identifier the identifier that is assigned to the secret key.
	 * @param secretKey the Base32 encoded secret key.
	 * @throws Exception when storing the secret key.
	 */
	protected abstract void store(String identifier, String secretKey) throws Exception;

}