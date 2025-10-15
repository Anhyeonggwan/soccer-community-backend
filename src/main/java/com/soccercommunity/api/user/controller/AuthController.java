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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @GetMapping("/hello")
    public String getMethodName() {
        return "주희야 안녕~";
    }

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
                .maxAge(1 * 24 * 60 * 60) // 1 days
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
        System.out.println("refreshToken >>> " + refreshToken);
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

    /* Naver 로그인/회원가입 */
    @GetMapping("/naver")
    public void naverLogin(@RequestParam("code") String code, @RequestParam("state") String state, HttpServletResponse response) throws IOException {
        TokenDto tokenDto = authService.naverLogin(code, state);
        ResponseCookie cookie = ResponseCookie.from("refreshToken", tokenDto.getRefreshToken())
                .httpOnly(true)
                .path("/")
                .maxAge(86400) // 1 days
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
        // 프론트로 토큰 전달(팝업 닫기 등 화면 처리)
        String redirectUrl = "http://localhost:3000/auth/callback?accessToken=" + tokenDto.getAccessToken();
        response.sendRedirect(redirectUrl);
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
    public ResponseEntity<ApiResponse<TokenDto>> googleLogin(@RequestBody GoogleIdTokenDto requestDto, HttpServletResponse response) {
        TokenDto tokenDto = authService.googleLogin(requestDto.getIdToken());
        ResponseCookie cookie = ResponseCookie.from("refreshToken", tokenDto.getRefreshToken())
                .httpOnly(true)
                .path("/")
                .maxAge(86400) // 1 days
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK, tokenDto));
    }

    /* 로그아웃 */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestHeader("Authorization") String accessToken, HttpServletResponse response) {
        authService.logout(accessToken.substring(7));

        // 브라우저의 refreshToken 쿠키를 삭제하는 로직
        ResponseCookie cookie = ResponseCookie.from("refreshToken", "deleted") // 값은 비어있지 않은 아무 문자열
                .maxAge(0)
                .path("/")
                .build();
        response.addHeader("Set-Cookie", cookie.toString());

        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK));
    }
}
