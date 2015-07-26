package authentication.specifications;

import authentication.SecureHashAlgorithm;

public abstract class OtpGeneratorSpecification {

	private final int passwordLength;
	
	private final int keyLength;
	
	private final SecureHashAlgorithm algorithm;
	
	public OtpGeneratorSpecification(int passwordLength, int keyLength, SecureHashAlgorithm algorithm) {
		this.passwordLength = passwordLength;
		this.keyLength = keyLength;
		this.algorithm = algorithm;
	}
	
	public int getPasswordLength() {
		return passwordLength;
	}
	
	public int getKeyLength() {
		return keyLength;
	}
	
	public SecureHashAlgorithm getAlgorithm() {
		return algorithm;
	}
	
}