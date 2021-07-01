package com.samhg.authentication.validation;

import com.google.common.primitives.Longs;
import com.samhg.authentication.PasswordFactory;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.LongStream;

/**
 * Validates One Time Passwords using the {@link PasswordFactory} class to create passwords.
 */
public final class PasswordValidator {

    private final PasswordFactory factory;

    /**
     * Constructs a {@link PasswordValidator} instance with the given password factory.
     *
     * @param factory used to create passwords to validate against.
     */
    public PasswordValidator(PasswordFactory factory) {
        this.factory = factory;
    }

    /**
     * Checks if the password enclosed in the specified request is valid and then invokes the
     * each of the appropriate observers.
     *
     * When the generated passwords, for the given request, does not contain the password enclosed
     * in the request, it is assumed that the password is invalid. This holds true for both the
     * event-based implementation and the time-based implementation but may not hold for future implementations.
     *
     * @param request the request to validate the password for, this contains the password and other parameters.
     * @param observers observers that should be invoked upon validating a request
     */
    public void validate(PasswordValidationRequest request, Collection<ValidityObserver> observers) {
        PasswordType passwordType = request.getType();

        WindowStrategy windowStrategy = passwordType.getWindowStrategy();
        LongStream window = windowStrategy.window(passwordType.getWindowSize());

        List<String> passwords = generatePasswords(request, window);
        int index = passwords.indexOf(request.getPassword());

        observers.forEach(o -> o.onValidation(request, index));
    }

    /**
     * Generates a {@link List} of {@link String} passwords for the given window, using the given
     * {@link PasswordValidationRequest} request.
     *
     * @param request the request to generate the passwords for.
     * @param window a stream of longs, each of which are an offset from the
     *                request's {@link PasswordValidationRequest#getMovingFactor()}.
     * @return a {@link List} of passwords for the given window.
     */
    private List<String> generatePasswords(PasswordValidationRequest request, LongStream window) {
        return window
                .map(offset -> offset + request.getMovingFactor())
                .mapToObj(Longs::toByteArray)
                .map(b -> factory.generatePassword(request.getSecret(), b, request.getAlgorithm(), request.getDigits()))
                .collect(Collectors.toList());
    }

}