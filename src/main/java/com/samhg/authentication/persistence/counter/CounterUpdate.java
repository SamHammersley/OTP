package com.samhg.authentication.persistence.counter;

import com.samhg.authentication.validation.PasswordValidationRequest;

public final class CounterUpdate {

    /**
     * The request that ultimately caused the counter to change.
     */
    private final PasswordValidationRequest request;

    /**
     * The new value of the counter.
     */
    private final long newCounter;

    public CounterUpdate(PasswordValidationRequest request, long newCounter) {
        this.request = request;
        this.newCounter = newCounter;
    }

    public PasswordValidationRequest getRequest() {
        return request;
    }

    public long getNewCounter() {
        return newCounter;
    }

}