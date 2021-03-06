package com.samhg.authentication.validation;

import com.samhg.authentication.generation.HmacAlgorithm;

public final class PasswordValidationRequest {

    private final String identifier;

    private final String password;

    private final byte[] secret;

    private final int digits;

    private final HmacAlgorithm algorithm;

    private final long movingFactor;

    private final PasswordType type;

    public PasswordValidationRequest(String identifier, String password, byte[] secret, int digits, HmacAlgorithm algorithm,
                                     long movingFactor, PasswordType type) {
        this.identifier = identifier;
        this.password = password;
        this.secret = secret;
        this.digits = digits;
        this.algorithm = algorithm;
        this.movingFactor = movingFactor;
        this.type = type;
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getPassword() {
        return password;
    }

    public byte[] getSecret() {
        return secret;
    }

    public int getDigits() {
        return digits;
    }

    public HmacAlgorithm getAlgorithm() {
        return algorithm;
    }

    public long getMovingFactor() {
        return movingFactor;
    }

    public PasswordType getType() {
        return type;
    }

}