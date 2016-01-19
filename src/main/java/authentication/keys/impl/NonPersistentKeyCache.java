package authentication.keys.impl;

import java.util.HashMap;

import authentication.keys.KeyCache;

/**
 * A {@link KeyCache} that does not store the passwords in any external location.
 * Passwords are only stored in and read from a {@link HashMap}.
 * 
 * @author Sam
 */
public class NonPersistentKeyCache extends KeyCache {
	
	public NonPersistentKeyCache() {
		super(new HashMap<String, String>());
	}
	
	@Override
	protected String deserialize(String identifier) {
		return null; // do nothing since this is not a persistent implementation.
	}

	@Override
	protected void serialize(String identifier, String secretKey) {
		// do nothing since this is not a persistent implementation.
	}

}
