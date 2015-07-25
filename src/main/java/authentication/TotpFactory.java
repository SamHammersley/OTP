package authentication;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.stream.IntStream;

import authentication.keys.KeyCache;
import authentication.specifications.TotpSpecification;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Longs;

/**
 * This class is a one-time password factory class.
 * It provides creation and validation of one-time passwords.
 *
 * Implementation of Time-based One Time Password.
 * This implementation adheres to the Internet Engineering Task
 * Force standard <a href="http://tools.ietf.org/html/rfc6238">RFC6238</a>.
 * 
 * <p>
 * The time-based one time password algorithm uses the current UNIX time
 * and a 16-bit key to create a Message Authentication Code.
 * </p>
 */
public final class TotpFactory extends OneTimePasswordFactory<TotpSpecification> {
	
	/**
	 * Constructs a new {@link TotpFactory} with the specified repository, window size and time step size.
	 *
	 * @param cache this is the repository where the secret keys are stored at runtime.
	 * @param specification containing information about this specific implementation.
	 */
	public TotpFactory(KeyCache cache, TotpSpecification specification) {
		super(specification, cache, new SecureRandom());
	}
	
	/**
	 * Validates the specified password by calculating the password for the
	 * current time window and surrounding time windows determined by the windowSize.
	 * We check the passwords for surrounding windows to compensate for any 
	 * delays or network latencies.
	 *
	 * @param encodedKey the encoded key
	 * @param password the password
	 * @return <code>true</code> if the specified password is successfully validated.
	 */
	@Override
	protected boolean validatePassword(String encodedKey, int password) {
		byte[] decodedKey = BaseEncoding.base32().decode(encodedKey);
		int stepSize = specification.getStepSize();
		int windowSize = specification.getWindowSize();
		long currentTime = Instant.now().getEpochSecond();
		long currentTimeStep = currentTime / stepSize;
		return IntStream.range(-(windowSize - 1) / 2, windowSize / 2 + 1)
				.mapToLong(i -> createPassword(decodedKey, Longs.toByteArray(currentTimeStep + i)))
				.anyMatch(p -> p == password);
	}
	
}