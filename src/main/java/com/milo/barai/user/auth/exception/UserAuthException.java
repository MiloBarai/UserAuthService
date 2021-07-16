package com.milo.barai.user.auth.exception;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class UserAuthException extends RuntimeException {

    private final UserAuthErrorCode errorCode;

    public UserAuthException(UserAuthErrorCode errorCode, String message, Exception previousException) {
        super(String.format("%d, %s", errorCode.getHttpErrorCode(), message), previousException);
        this.errorCode = errorCode;
    }

    public UserAuthException(UserAuthErrorCode errorCode, String message) {
        super(String.format("%d, %s", errorCode.getHttpErrorCode(), message));
        this.errorCode = errorCode;
    }
}
