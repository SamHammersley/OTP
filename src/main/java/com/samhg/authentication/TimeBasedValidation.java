package com.samhg.authentication;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.function.IntUnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.google.common.primitives.Longs;
import com.samhg.authentication.key.repository.SecretRepository;

public class TimeBasedValidation extends PasswordValidation {
	
	/**
	 * The size of one step in seconds.
	 */
	private static final int STEP_SIZE = 30;
	
	/**
	 * The size of the authentication "window" (in time steps).
	 */
	private static final int WINDOW_SIZE = 3;
	
	/**
	 * {@link PasswordFactory} for creating passwords to check with input password.
	 */
	private final PasswordFactory passwordFactory;
	
	public TimeBasedValidation(Optional<SecretRepository> repository, PasswordFactory passwordFactory) {
		super(repository);
		this.passwordFactory = passwordFactory;
	}
	
	public TimeBasedValidation(PasswordFactory passwordFactory) {
		this(Optional.empty(), passwordFactory);
	}

	@Override
	protected Set<Integer> validPasswords(byte[] rawSecret) {
		long currentTime = Instant.now().getEpochSecond();
		long currentTimeStep = currentTime / STEP_SIZE;
		
		IntStream window = IntStream.range(-(WINDOW_SIZE - 1) / 2, WINDOW_SIZE / 2 + 1);
		IntUnaryOperator mapper = i -> passwordFactory.createPassword(rawSecret, Longs.toByteArray(currentTimeStep + i));

		return window.map(mapper).boxed().collect(Collectors.toSet());
	}

}