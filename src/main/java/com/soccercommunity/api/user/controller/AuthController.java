package com.soccercommunity.api.user.controller;

import com.soccercommunity.api.user.dto.*;
import com.soccercommunity.api.common.exception.CustomException;
import com.soccercommunity.api.common.response.ApiResponse;
import com.soccercommunity.api.common.response.ErrorCode;
import com.soccercommunity.api.common.response.SuccessCode;
import com.soccercommunity.api.user.service.AuthService;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /* 회원가입 */
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<Void>> signUp(@Valid @RequestBody SignUpRequestDto requestDto) {
        authService.signUp(requestDto);
        ApiResponse<Void> response = ApiResponse.success(SuccessCode.SIGN_UP_SUCCESS);
        return new ResponseEntity<>(response, SuccessCode.SIGN_UP_SUCCESS.getStatus());
    }

    /* 로그인 */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponseDto>> login(@Valid @RequestBody LoginRequestDto loginRequestDto) {
        LoginResultDto loginResult = authService.login(loginRequestDto.getEmail(), loginRequestDto.getPassword());

        ResponseCookie cookie = ResponseCookie.from("refreshToken", loginResult.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(1 * 24 * 60 * 60) // 7 days
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(ApiResponse.success(SuccessCode.LOGIN_SUCCESS, loginResult.getLoginResponse()));
    }

    /* 토큰 재발급 */
    @PostMapping("/reissue")
    public ResponseEntity<ApiResponse<LoginResponseDto>> reissue(@CookieValue(name = "refreshToken", required = false) String refreshToken) {
        if (refreshToken == null) {
            throw new CustomException(ErrorCode.REFRESH_TOKEN_NOT_FOUND);
        }
        LoginResultDto loginResult = authService.reissue(refreshToken);

        ResponseCookie cookie = ResponseCookie.from("refreshToken", loginResult.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(1 * 24 * 60 * 60) // 7 days
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(ApiResponse.success(SuccessCode.TOKEN_REISSUED, loginResult.getLoginResponse()));
    }

    /* Naver 인증 redirect */
    @GetMapping("/naver")
    public ResponseEntity<ApiResponse<String>> naverAuth(@RequestParam("code") String code, @RequestParam("state") String state, HttpServletResponse response) throws IOException {
        String naverUUID = authService.naverAuth(code, state);

        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK, naverUUID));
    }

    /* Naver 로그인/회원가입 */
    @PostMapping("/naver/login")
    public ResponseEntity<ApiResponse<LoginResponseDto>> naverLogin(@RequestBody NaverUUIDDto uuid) throws IOException {
        LoginResultDto loginResult = authService.naverLogin(uuid.getUuid(), uuid.getCode());

        ResponseCookie cookie = ResponseCookie.from("refreshToken", loginResult.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(1 * 24 * 60 * 60) // 7 days
                .build();
        
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(ApiResponse.success(SuccessCode.LOGIN_SUCCESS, loginResult.getLoginResponse()));
    }

    /* Naver 계정 연동 */
    @PostMapping("/link/naver")
    public ResponseEntity<ApiResponse<Void>> linkNaver(@RequestBody LinkNaverRequestDto requestDto) {
        authService.linkNaverAccount(requestDto);
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.ACCOUNT_LINK_SUCCESS));
    }

    /* Google 계정 연동 */
    @PostMapping("/link/google")
    public ResponseEntity<ApiResponse<Void>> linkGoogle(@RequestBody LinkGoogleRequestDto request) {
        authService.linkGoogleAccount(request);
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.ACCOUNT_LINK_SUCCESS));
    }

    /* Google 로그인/회원가입 */
    @PostMapping("/google")
    public ResponseEntity<ApiResponse<LoginResponseDto>> googleLogin(@RequestBody GoogleIdTokenDto requestDto) {
        LoginResultDto loginResult = authService.googleLogin(requestDto.getIdToken(), requestDto.getCode());

        ResponseCookie cookie = ResponseCookie.from("refreshToken", loginResult.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(1 * 24 * 60 * 60) // 7 days
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(ApiResponse.success(SuccessCode.LOGIN_SUCCESS, loginResult.getLoginResponse()));
    }

}
