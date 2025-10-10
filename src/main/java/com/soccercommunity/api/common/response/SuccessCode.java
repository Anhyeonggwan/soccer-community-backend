package com.soccercommunity.api.common.response;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum SuccessCode {

    OK(HttpStatus.OK, "요청에 성공했습니다."),
    CREATED(HttpStatus.CREATED, "리소스가 성공적으로 생성되었습니다."),
    SIGN_UP_SUCCESS(HttpStatus.CREATED, "회원가입이 성공적으로 완료되었습니다."),
    ACCOUNT_LINK_SUCCESS(HttpStatus.OK, "계정이 성공적으로 연동되었습니다."),
    LOGIN_SUCCESS(HttpStatus.OK, "로그인에 성공했습니다."),
    TOKEN_REISSUED(HttpStatus.OK, "토큰이 성공적으로 재발급되었습니다.");

    private final HttpStatus status;
    private final String message;
}
