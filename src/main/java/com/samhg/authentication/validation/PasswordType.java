package com.samhg.authentication.validation;

import com.samhg.authentication.validation.event.EventBasedWindowStrategy;
import com.samhg.authentication.validation.time.TimeBasedWindowStrategy;

public enum PasswordType {

    TIME_BASED(3, new TimeBasedWindowStrategy()),

    EVENT_BASED(15, new EventBasedWindowStrategy());

    private final WindowStrategy windowStrategy;

    private final int windowSize;

    PasswordType(int windowSize, WindowStrategy windowStrategy) {
        this.windowSize = windowSize;
        this.windowStrategy = windowStrategy;
    }

    public int getWindowSize() {
        return windowSize;
    }

    public WindowStrategy getWindowStrategy() {
        return windowStrategy;
    }

}