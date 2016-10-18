package com.samhg.authentication;

import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import com.samhg.authentication.key.SharedSecret;
import com.samhg.authentication.key.repository.SecretRepository;

public abstract class PasswordValidation {
	
	/**
	 * {@link SecretRepository} holding {@link SharedSecret}s.
	 */
	protected final Optional<SecretRepository> repository;
	
	/**
	 * Constructs a {@link PasswordValidation} instance with the given repository.
	 * 
	 * @param repository the {@link SecretRepository} that holds keys.
	 */
	public PasswordValidation(Optional<SecretRepository> repository) {
		this.repository = repository;
	}
	
	/**
	 * Attempts to validate the specified password by getting the
	 * {@link SharedSecret} that is mapped to the given identifier from
	 * {@link #repository}.
	 * 
	 * This function requires a {@link SecretRepository}, if not present an
	 * {@link UnsupportedOperationException} is thrown.
	 * 
	 * @param identifier 
	 * @param password 
	 * @return <code>true</code> if the specified password is valid.
	 */
	public boolean validateForIdentifier(String identifier, int password) {
		SecretRepository r = repository.orElseThrow(SUPPLIER);
		Optional<SharedSecret> key = r.get(identifier);
		return key.map(k -> validate(k, password)).get();
	}

	private static final Supplier<UnsupportedOperationException> SUPPLIER =
			() -> new UnsupportedOperationException("Non-null KeyRepository required");

	/**
	 * Checks {@link #validPasswords} for the specified passwords.
	 * 
	 * @param secret the privately shared secret.
	 * @param password the input being validated.
	 * 
	 * @return {@code true} if the password is valid.
	 */
	public boolean validate(SharedSecret secret, int password) {
		return validPasswords(secret.getSecret()).contains(password);
	}
	
	/**
	 * Produces a fixed {@link Set} of integers which are valid passwords for
	 * this moment in time.
	 * 
	 * @param rawSecret the raw data of a {@link SharedSecret}.
	 * @return a fixed {@link Set} of valid passwords.
	 */
	protected abstract Set<Integer> validPasswords(byte[] rawSecret);

}