package com.samhg.authentication.validation.event;

import com.samhg.authentication.validation.WindowStrategy;

import java.util.stream.LongStream;

public final class EventBasedWindowStrategy implements WindowStrategy {

    @Override
    public LongStream window(int windowSize) {
        return LongStream.range(0, windowSize);
    }

}