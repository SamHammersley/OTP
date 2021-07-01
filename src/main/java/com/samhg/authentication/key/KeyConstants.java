package com.samhg.authentication.key;

import com.google.common.io.BaseEncoding;

import java.util.concurrent.TimeUnit;

public final class KeyConstants {

    private KeyConstants() {
        // prevent instantiation.
    }

    /**
     * Default value for the number of generated bytes before reseeding a {@link ReseedingSecureRandom}.
     */
    public static final int DEFAULT_RESEED_BYTES = 100_000;

    /**
     * Default value for the amount of time between reseeding a {@link ReseedingSecureRandom}.
     */
    public static final long DEFAULT_RESEED_INTERVAL = TimeUnit.MINUTES.toMillis(1);

    /**
     * Algorithm name and provider used by for PRNG.
     */
    public static final String ALGORITHM = "SHA1PRNG", PROVIDER = "SUN";

    /**
     * The size of a secret key in bytes.
     */
    public static final int KEY_SIZE = 10;

    /**
     * The encoding scheme used for encoding the secret key.
     *
     * As specified by RFC 4226, base32 is used to encode secret keys.
     */
    public static final BaseEncoding ENCODING_SCHEME = BaseEncoding.base32();

}