package authentication.keys.impl;

import java.util.HashMap;
import java.util.Map;

import authentication.keys.KeyCache;

import com.google.common.cache.Cache;

public class LocalKeyCache extends KeyCache {

	private final Map<String, String> keys;
	
	public LocalKeyCache(Cache<String, String> cache) {
		super(cache);
		this.keys = new HashMap<>();
	}

	@Override
	protected String load(String identifier) {
		return keys.get(identifier);
	}

	@Override
	protected void store(String identifier, String secretKey) {
		keys.put(identifier, secretKey);
	}

}
