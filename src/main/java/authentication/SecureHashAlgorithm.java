package authentication;

/**
 * Provides names of different SHA variations using SHA-1 and SHA-2
 * algorithms. SHA-1 has only one implementation however SHA-2 has many
 * different implementations, of which two are available here (SHA-256,
 * SHA-512). This is only used Hash-based message authentication.
 * 
 * @author Sam
 */
public enum SecureHashAlgorithm {
	/**
	 * SHA-1, produces 160 bit hash.
	 */
	SHA_1("HmacSHA1"),

	/**
	 * SHA-256 (SHA-2 algorithm) produces 256 bit hash.
	 */
	SHA_256("HmacSHA256"),

	/**
	 * SHA-512 (SHA-2 algorithm) produces 512 bit hash.
	 */
	SHA_512("HmacSHA512");

	/**
	 * This is used to get an instance of MAC from JCE.
	 */
	private String algorithmName;

	/**
	 * Instantiates a new secure hash algorithm.
	 *
	 * @param algorithmName the algorithm name
	 */
	SecureHashAlgorithm(String algorithmName) {
		this.algorithmName = algorithmName;
	}

	/**
	 * Gets the name of the algorithm.
	 * 
	 * @return algorithm's name.
	 */
	public String getAlgorithmName() {
		return algorithmName;
	}
}