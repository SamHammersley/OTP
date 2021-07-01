package com.samhg.authentication.validation;

public interface ValidityObserver {

    void onValidation(PasswordValidationRequest request, int index);

}