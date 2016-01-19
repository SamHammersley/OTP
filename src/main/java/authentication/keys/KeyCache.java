package authentication.keys;

import java.util.Map;
import java.util.Optional;

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
	private final Map<String, String> cache;

	/**
	 * Constructs a new {@link KeyCache}.
	 */
	public KeyCache(Map<String, String> cache) {
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
	 */
	public Optional<String> get(String identifier) {
		String secretKey = cache.getOrDefault(identifier, deserialize(identifier));
		
		return Optional.ofNullable(secretKey);
	}

	/**
	 * Loads the secret key for the specified identifier.
	 *
	 * @param identifier the identifier.
	 * @return the secret key.
	 */
	protected abstract String deserialize(String identifier);
	
	/**
	 * Puts the secret key associated with the identifier in the cache.
	 * It will check that the key is cached, if it's not it will cache the
	 * key and then invoke {@link #store} method.
	 * 
	 * @param identifier the identifier that is associated with the secret key
	 * 	to get. This parameter acts as an identifier for the secret key.
	 * @param secretKey the secretKey that is actually going to be stored.
	 */
	public void put(String identifier, String secretKey) {
		cache.putIfAbsent(identifier, secretKey);
		
		serialize(identifier, secretKey);
	}

	/**
	 * Stores a secret key value assigned to an identifier.
	 * 
	 * <p>This method may or may not involve persistence of
	 * data depending on the implementation.</p>
	 * 
	 * @param identifier the identifier that is assigned to the secret key.
	 * @param secretKey the Base32 encoded secret key.
	 */
	protected abstract void serialize(String identifier, String secretKey);

}