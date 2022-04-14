package com.example.demo.exceptions;

/**
 * Exception thrown whenever there are no results.
 */
public class NotFoundException extends DemoException {
    public NotFoundException(final String message) {
        super(message, 404);
    }
}
