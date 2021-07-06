package com.samhg.authentication.validation.event;

import com.samhg.authentication.persistence.counter.CounterPersistenceStrategy;
import com.samhg.authentication.persistence.counter.CounterUpdate;
import com.samhg.authentication.validation.PasswordValidationRequest;
import com.samhg.authentication.validation.ValidationObserver;

public final class EventBasedValidationObserver implements ValidationObserver {

    private final CounterPersistenceStrategy persistenceStrategy;

    public EventBasedValidationObserver(CounterPersistenceStrategy persistenceStrategy) {
        this.persistenceStrategy = persistenceStrategy;
    }

    @Override
    public void onValidation(PasswordValidationRequest request, int index) {
        if (index >= 0) {
            persistenceStrategy.persist(new CounterUpdate(request, request.getMovingFactor()));
        }
    }
}