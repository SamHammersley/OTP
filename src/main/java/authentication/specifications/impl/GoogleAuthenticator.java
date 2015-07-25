package authentication.specifications.impl;

import authentication.SecureHashAlgorithm;
import authentication.specifications.TotpSpecification;

public final class GoogleAuthenticator extends TotpSpecification {

	public GoogleAuthenticator() {
		super(6, 10, SecureHashAlgorithm.SHA_1, 3, 30);
	}

}