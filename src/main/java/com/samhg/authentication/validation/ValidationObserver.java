package com.samhg.authentication.validation;

public interface ValidationObserver {

    void onValidation(PasswordValidationRequest request, int index);

}