package authentication.specifications;

import authentication.SecureHashAlgorithm;

public class TotpSpecification extends OtpGeneratorSpecification {

	/**
	 * The window size, this is to allow for any networking latencies, 
	 * when checking the password we calculate the password for surrounding 
	 * time windows. For example, if we specify a time window size of 3 (google default)
	 * we calculate a password for the current window, the window before and the window after.
	 */
	private final int timeWindowSize;
	
	/**
	 * The size of the time step (30 second intervals as of Google's defaults).
	 */
	private final int timeStepSize;
	
	public TotpSpecification(int passwordLength, int keyLength, SecureHashAlgorithm algorithm, int windowSize, int stepSize) {
		super(passwordLength, keyLength, algorithm);
		this.timeWindowSize = windowSize;
		this.timeStepSize = stepSize;
	}
	
	public int getWindowSize() {
		return timeWindowSize;
	}
	
	public int getStepSize() {
		return timeStepSize;
	}
	
}
