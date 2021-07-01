package com.samhg.authentication.validation.time;

import com.samhg.authentication.validation.WindowStrategy;

import java.util.stream.LongStream;

public final class TimeBasedWindowStrategy implements WindowStrategy {

    @Override
    public LongStream window(int windowSize) {
        return LongStream.rangeClosed(-(windowSize - 1) / 2, windowSize / 2);
    }

}