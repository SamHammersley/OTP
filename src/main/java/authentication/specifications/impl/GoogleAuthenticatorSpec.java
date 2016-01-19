package authentication.specifications.impl;

import authentication.SecureHashAlgorithm;
import authentication.specifications.TotpSpecification;

public final class GoogleAuthenticatorSpec extends TotpSpecification {

	public GoogleAuthenticatorSpec() {
		super(6, 10, SecureHashAlgorithm.SHA_1, 3, 30);
	}

}