package com.example.demo.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Builder;
import lombok.Value;

import java.time.LocalDateTime;
import java.util.Collection;

@Value
@Builder
public class ErrorResponse {
    private int status;
    private String path;
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", shape = JsonFormat.Shape.STRING)

    private LocalDateTime time;

    private Collection<ErrorCode> errors;
}
