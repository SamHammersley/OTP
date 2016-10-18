package com.samhg.authentication.key.repository;

import java.util.HashMap;

public class NonPersistentSecretRepository extends SecretRepository {

	public NonPersistentSecretRepository() {
		super(new HashMap<>());
	}

	@Override
	public void persist() {
		throw new UnsupportedOperationException();
	}

}