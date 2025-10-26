package com.soccercommunity.api.common.response;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    // Common
    INVALID_PARAMETER(HttpStatus.BAD_REQUEST, "유효하지 않은 파라미터입니다."),
    EMAIL_ALREADY_EXISTS(HttpStatus.CONFLICT, "이미 사용 중인 이메일입니다."),
    NICKNAME_ALREADY_EXISTS(HttpStatus.CONFLICT, "이미 사용 중인 닉네임입니다."),
    USER_ALREADY_EXISTS(HttpStatus.CONFLICT, "이미 존재하는 사용자입니다."),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "인증되지 않은 사용자입니다."),
    FORBIDDEN(HttpStatus.FORBIDDEN, "접근 권한이 없습니다."),
    NOT_FOUND(HttpStatus.NOT_FOUND, "리소스를 찾을 수 없습니다."),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다."),
    INVALID_VERIFICATION_CODE(HttpStatus.BAD_REQUEST, "유효하지 않은 인증 코드입니다."),

    // Token
    INVALID_REFRESH_TOKEN(HttpStatus.BAD_REQUEST, "유효하지 않은 리프레시 토큰입니다."),
    REFRESH_TOKEN_NOT_FOUND(HttpStatus.UNAUTHORIZED, "리프레시 토큰을 찾을 수 없습니다."),
    REFRESH_TOKEN_MISMATCH(HttpStatus.BAD_REQUEST, "리프레시 토큰이 일치하지 않습니다."),
    INVALID_ACCESS_TOKEN(HttpStatus.BAD_REQUEST, "유효하지 않은 액세스 토큰입니다."),
    INVALID_GOOGLE_TOKEN(HttpStatus.UNAUTHORIZED, "유효하지 않은 구글 토큰입니다."),
    EMAIL_MISMATCH(HttpStatus.BAD_REQUEST, "계정 연동을 위한 이메일이 일치하지 않습니다."),

    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "서버에 오류가 발생했습니다."),
    INVALID_SOCIAL_LOGIN_TYPE(HttpStatus.BAD_REQUEST, "유효하지 않은 소셜 로그인 타입입니다."),

    // Naver
    NAVER_TOKEN_REQUEST_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "네이버 Access Token 발급에 실패했습니다."),
    NAVER_UUID_NOT_FOUND_IN_REDIS(HttpStatus.NOT_FOUND, "네이버 UUID를 찾을 수 없습니다."),

    // Social Login
    EMAIL_EXISTS_AS_REGULAR(HttpStatus.CONFLICT, "이미 일반 계정으로 가입된 이메일입니다. 일반 로그인 후 계정을 연동해주세요."),
    EMAIL_EXISTS_AS_SOCIAL(HttpStatus.CONFLICT, "이미 다른 소셜 계정으로 가입된 이메일입니다.");

    private final HttpStatus status;
    private final String message;
}
