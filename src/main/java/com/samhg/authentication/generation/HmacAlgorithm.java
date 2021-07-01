package com.samhg.authentication.generation;

/**
 * An enumeration of the available HMAC algorithms used in generation of passwords.
 */
public enum HmacAlgorithm {

    SHA1,

    SHA256,

    SHA512;

    /**
     * Gets the name of this algorithm, this is prefixed by the string "Hmac" since that is what the
     * {@link javax.crypto} library expects.
     *
     * @return the name of this algorithm, for use with the {@link javax.crypto} library.
     */
    public String getName() {
        return "Hmac" + name();
    }

}