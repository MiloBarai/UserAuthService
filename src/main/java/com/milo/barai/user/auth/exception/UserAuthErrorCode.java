package com.milo.barai.user.auth.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum UserAuthErrorCode {
    BAD_REQUEST(400),
    UNAUTHORIZED(401),
    FORBIDDEN(403),
    NOT_FOUND(404),
    INTERNAL_ERROR(500);
    private final int httpErrorCode;
}
