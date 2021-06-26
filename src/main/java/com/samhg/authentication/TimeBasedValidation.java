package com.samhg.authentication;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.function.IntFunction;
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
	protected Set<String> validPasswords(byte[] rawSecret, int digits) {
		long currentTime = Instant.now().getEpochSecond();
		long currentTimeStep = currentTime / STEP_SIZE;
		
		IntStream window = IntStream.range(-(WINDOW_SIZE - 1) / 2, WINDOW_SIZE / 2 + 1);

		IntFunction<String> mapper = i -> {
			byte[] movingFactorBytes = Longs.toByteArray(currentTimeStep + i);

			return passwordFactory.generatePassword(rawSecret, movingFactorBytes, HmacAlgorithm.SHA1, digits);
		};

		return window.mapToObj(mapper).collect(Collectors.toSet());
	}

}