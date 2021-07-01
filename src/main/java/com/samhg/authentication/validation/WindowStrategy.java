package com.samhg.authentication.validation;

import java.util.stream.LongStream;

public interface WindowStrategy {

    LongStream window(int windowSize);

}