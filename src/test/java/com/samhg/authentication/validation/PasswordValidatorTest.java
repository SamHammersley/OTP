package com.samhg.authentication.validation;

import com.samhg.authentication.generation.HmacAlgorithm;
import com.samhg.authentication.generation.PasswordFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Collections;

public final class PasswordValidatorTest {

    private static final byte[] SECRET_KEY = { 20, -37, 28, 73, -53, 23, -2, -59, 70, 89 };

    @Test
    public void testValidate() {
        PasswordValidationRequest request = new PasswordValidationRequest("257225", SECRET_KEY, 6,
                HmacAlgorithm.SHA1, 0, PasswordType.EVENT_BASED);

        PasswordFactory factory = new PasswordFactory();
        PasswordValidator validator = new PasswordValidator(factory);

        validator.validate(request, Collections.singleton((request1, index) -> assertEquals(index, 0)));
    }

}