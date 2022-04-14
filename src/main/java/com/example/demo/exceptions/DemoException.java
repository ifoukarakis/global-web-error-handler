package com.example.demo.exceptions;

import lombok.Getter;

/**
 * Base exception for all expected errors.
 */
@Getter
public class DemoException extends RuntimeException {
    private final int status;


    public DemoException(final String message, final int status) {
        super(message);
        this.status = status;
    }
}
