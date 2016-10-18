package com.samhg.authentication.key.repository;

import java.util.Map;
import java.util.Optional;

import com.samhg.authentication.key.SharedSecret;

public abstract class SecretRepository {

	/**
	 * A local repository keeping track of cached {@link SharedSecret}s.
	 */
	private final Map<String, SharedSecret> cache;
	
	public SecretRepository(Map<String, SharedSecret> cache) {
		this.cache = cache;
	}

	public Optional<SharedSecret> get(String identifier) {
		return Optional.ofNullable(cache.get(identifier));
	}
	
	public void put(String identifier, SharedSecret value) {
		cache.put(identifier, value);
	}
	
	public abstract void persist();
	
}