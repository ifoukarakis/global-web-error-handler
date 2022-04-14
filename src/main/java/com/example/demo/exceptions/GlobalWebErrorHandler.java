package com.example.demo.exceptions;

import com.example.demo.dto.ErrorCode;
import com.example.demo.dto.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.lang.Nullable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintViolationException;
import javax.validation.Validation;
import javax.validation.Validator;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static java.util.Comparator.comparing;
import static java.util.Locale.ENGLISH;
import static java.util.Optional.ofNullable;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

/**
 * Handles exceptions thrown by the application.
 */
@Slf4j
@ControllerAdvice
@RequiredArgsConstructor
public final class GlobalWebErrorHandler {

    private static final String INVALID_REQUEST_CODE = "INVALID_REQUEST";

    private final Clock clock;
    private final ObjectMapper mapper;
    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    /**
     * Generic exception handler, handles unexpected exceptions.
     */
    @ExceptionHandler(Exception.class)
    public final ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final Exception exception) {
        final ErrorResponse response = createResponse(500, request, new ErrorCode("INTERNAL_SERVER_ERROR", exception.getMessage()));
        log.error("Handle unexpected exception {}", singletonMap("response", response), exception);
        return ResponseEntity.status(response.getStatus()).body(response);
    }

    /**
     * Application-specific exception
     */
    @ExceptionHandler(DemoException.class)
    public final ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final DemoException exception) {
        final ErrorResponse response =
                createResponse(exception.getStatus(), request, new ErrorCode("INVALID_STATE", exception.getMessage()));
        log.error("Handle expected exception {}", Collections.singletonMap("response", response), exception);
        return ResponseEntity.status(response.getStatus()).body(response);
    }

    /**
     * Handle unknown paths
     */
    @ExceptionHandler(NoHandlerFoundException.class)
    public final ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final NoHandlerFoundException exception) {
        final ErrorResponse errorResponse = createResponse(404, request,
                new ErrorCode("PATH_NOT_FOUND", format(ENGLISH, "Path '%s' does not exist", exception.getRequestURL())));
        log.warn("Handle no handler found exception {}", singletonMap("response", errorResponse), exception);
        return ResponseEntity.status(errorResponse.getStatus()).body(errorResponse);
    }

    /**
     * Handle deserialization errors
     */
    @ExceptionHandler(BindException.class)
    private ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final BindException e) {
        final ErrorResponse response = createResponse(400, request, getErrorCodes(e.getBindingResult()));
        log.warn("Handle invalid request exception {}", singletonMap("response", response), e);

        return ResponseEntity.status(BAD_REQUEST).body(response);
    }

    /**
     * Handle invalid request due to bad method arguments
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    private ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final MethodArgumentNotValidException e) {
        ErrorResponse response = createResponse(400, request, getErrorCodes(e.getBindingResult()));
        log.warn("Handle invalid request exception {}", singletonMap("response", response), e);

        return ResponseEntity.status(response.getStatus()).body(response);
    }

    /**
     * Handle invalid request due to invalid format (i.e. dates not in ISO format)
     */
    @ExceptionHandler(InvalidFormatException.class)
    private ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final InvalidFormatException e) {
        String message = format(ENGLISH, "Value '%s' does not have a valid format", e.getValue());
        ErrorResponse response = createResponse(400, request, new ErrorCode(INVALID_REQUEST_CODE, message));

        log.warn("Handle invalid format exception {}", singletonMap("response", response), e);

        return ResponseEntity.status(response.getStatus()).body(response);
    }

    /**
     * Handle invalid request due to invalid payload (i.e. body not valid json)
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    private ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final HttpMessageNotReadableException e) {
        if (e.getCause() instanceof InvalidFormatException) {
            return handle(request, (InvalidFormatException) e.getCause());
        }
        ErrorResponse response = createResponse(400, request, new ErrorCode(INVALID_REQUEST_CODE, "The body is not readable"));
        log.warn("Handle invalid request exception {}", singletonMap("response", response), e);

        return ResponseEntity.status(response.getStatus()).body(response);
    }

    /**
     * Handle invalid request due to missing HTTP headers.
     */
    @ExceptionHandler(MissingRequestHeaderException.class)
    private ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final MissingRequestHeaderException e) {
        String message = format(ENGLISH, "Missing request header '%s'", e.getHeaderName());
        ErrorResponse response = createResponse(400, request, new ErrorCode("MISSING_REQUEST_HEADER", message));
        log.warn("Handle missing header exception {}", singletonMap("response", response), e);

        return ResponseEntity.status(response.getStatus()).body(response);
    }

    /**
     * Handle invalid request due to missing query parameter.
     */
    @ExceptionHandler(MissingServletRequestParameterException.class)
    private ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final MissingServletRequestParameterException e) {
        String message = format(ENGLISH, "Missing query param '%s'", e.getParameterName());
        ErrorResponse response = createResponse(400, request, new ErrorCode("MISSING_QUERY_PARAM", message));
        log.warn("Handle missing query param exception {}", singletonMap("response", response), e);

        return ResponseEntity.status(response.getStatus()).body(response);
    }

    /**
     * Handle invalid request due to invalid HTTP method.
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    private ResponseEntity<ErrorResponse> handle(HttpServletRequest request, HttpRequestMethodNotSupportedException e) {
        String message = format(ENGLISH, "Method '%s' not allowed for path '%s'", e.getMethod(), getPath(request));
        ErrorResponse response = createResponse(405, request, new ErrorCode("METHOD_NOT_ALLOWED", message));
        log.warn("Handle method not supported exception {}", singletonMap("response", response), e);

        return ResponseEntity.status(response.getStatus()).body(response);
    }

    /**
     * Handle invalid request due to method argument type mismatch
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    private ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final MethodArgumentTypeMismatchException e) {
        String message = format(ENGLISH, "Request value type mismatch on field '%s'", e.getName());
        ErrorResponse response = createResponse(400, request, new ErrorCode("REQUEST_VALUE_TYPE_MISMATCH", message));

        log.warn("Handle method argument type mismatch exception {}", Collections.singletonMap("response", response), e);

        return ResponseEntity.status(response.getStatus()).body(response);
    }

    /**
     * Handle invalid request due to validation constraint violation.
     */
    @ExceptionHandler(ConstraintViolationException.class)
    private ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final ConstraintViolationException e) {
        ErrorResponse response = createResponse(400, request, getErrorCodes(e));
        log.warn("Handle constraint violation exception {}", Collections.singletonMap("response", response), e);
        return ResponseEntity.status(response.getStatus()).body(response);
    }

    /**
     * Handle invalid request due to bad credentials.
     */
    @ExceptionHandler(BadCredentialsException.class)
    private ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final BadCredentialsException e) {
        ErrorResponse response = createResponse(401, request, ErrorCode.builder().code("UNAUTHORIZED").message("Invalid credentials").build());
        return ResponseEntity.status(response.getStatus()).body(response);
    }

    /**
     * Handle invalid request due to unauthorized access.
     */
    @ExceptionHandler(AccessDeniedException.class)
    private ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final AccessDeniedException e) {
        final String message = SecurityContextHolder.getContext().getAuthentication().getName() + " not authorized";
        ErrorResponse response = createResponse(401, request, ErrorCode.builder().code("UNAUTHORIZED").message(message).build());
        return ResponseEntity.status(response.getStatus()).body(response);
    }

    /**
     * Handle invalid request due to illegal arguments.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    private ResponseEntity<ErrorResponse> handle(final HttpServletRequest request, final IllegalArgumentException e) {
        ErrorResponse response = createResponse(400, request, ErrorCode.builder().code("BAD_REQUEST").message(e.getMessage()).build());
        return ResponseEntity.status(response.getStatus()).body(response);
    }

    private static String getPath(HttpServletRequest request) {
        final String path = toOptional(request.getServletPath()).orElse(request.getRequestURI());
        return ofNullable(path).orElse(request.getPathInfo());
    }

    private static Optional<String> toOptional(@Nullable String value) {
        return ofNullable(value).filter(s -> !s.isEmpty());
    }

    private List<ErrorCode> getErrorCodes(ConstraintViolationException exception) {
        return exception.getConstraintViolations()
                .stream()
                .sorted(Comparator.comparing(violation -> violation.getPropertyPath().toString()))
                .map(violation -> {
                    String message =
                            format(ENGLISH, "Field '%s' %s. Value: '%s'", violation.getPropertyPath().toString(), violation.getMessage(),
                                    violation.getInvalidValue());
                    return new ErrorCode(INVALID_REQUEST_CODE, message);
                })
                .collect(Collectors.toList());
    }

    private List<ErrorCode> getErrorCodes(BindingResult bindingResult) {
        final Stream<ErrorCode> fieldErrors =
                bindingResult.getFieldErrors().stream().sorted(comparing(FieldError::getField)).map(violation -> {
                    String message = format(ENGLISH, "Field '%s' %s. Value: '%s'", violation.getField(), violation.getDefaultMessage(),
                            violation.getRejectedValue());
                    return ErrorCode.builder().code(INVALID_REQUEST_CODE).message(message).build();
                });

        final Stream<ErrorCode> globalErrors =
                bindingResult.getGlobalErrors().stream().sorted(comparing(ObjectError::getObjectName)).map(violation -> {
                    String message = format(ENGLISH, "Error in '%s'; %s.", violation.getObjectName(), violation.getDefaultMessage());
                    return ErrorCode.builder().code(INVALID_REQUEST_CODE).message(message).build();
                });

        return Stream.concat(fieldErrors, globalErrors).collect(Collectors.toList());
    }

    private ErrorResponse createResponse(final int status, final HttpServletRequest request, final ErrorCode error) {
        return createResponse(status, request, singletonList(error));
    }

    private ErrorResponse createResponse(final int status, final HttpServletRequest request, final Collection<ErrorCode> errors) {
        return ErrorResponse.builder().status(status).path(getPath(request)).time(LocalDateTime.now(clock)).errors(errors).build();
    }
}
