package com.soccercommunity.api.user.controller;

import com.soccercommunity.api.user.dto.SignUpRequestDto;
import com.soccercommunity.api.user.dto.TokenDto;
import com.soccercommunity.api.common.exception.CustomException;
import com.soccercommunity.api.common.response.ApiResponse;
import com.soccercommunity.api.common.response.ErrorCode;
import com.soccercommunity.api.common.response.SuccessCode;
import com.soccercommunity.api.user.dto.GoogleIdTokenDto;
import com.soccercommunity.api.user.dto.LinkGoogleRequestDto;
import com.soccercommunity.api.user.dto.LinkNaverRequestDto;
import com.soccercommunity.api.user.dto.LoginRequestDto;
import com.soccercommunity.api.user.service.AuthService;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.io.IOException;

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

    /* 회원가입 */
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<Void>> signUp(@Valid @RequestBody SignUpRequestDto requestDto) {
        authService.signUp(requestDto);
        ApiResponse<Void> response = ApiResponse.success(SuccessCode.SIGN_UP_SUCCESS);
        return new ResponseEntity<>(response, SuccessCode.SIGN_UP_SUCCESS.getStatus());
    }

    /* 로그인 */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<TokenDto>> login(@Valid @RequestBody LoginRequestDto loginRequestDto, HttpServletResponse response) {
        TokenDto tokenDto = authService.login(loginRequestDto.getEmail(), loginRequestDto.getPassword());
        ResponseCookie cookie = ResponseCookie.from("refreshToken", tokenDto.getRefreshToken())
                .httpOnly(true)
                .path("/api/auth/reissue")
                .maxAge(604800) // 1 days
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK, tokenDto));
    }

    /* 토큰 재발급 */
    @PostMapping("/reissue")
    public ResponseEntity<ApiResponse<TokenDto>> reissue(@CookieValue(name = "refreshToken", required = false) String refreshToken, HttpServletResponse response) {
        System.out.println("Received refreshToken from cookie >>> " + refreshToken);
        if (refreshToken == null) {
            throw new CustomException(ErrorCode.REFRESH_TOKEN_NOT_FOUND);
        }
        TokenDto tokenDto = authService.reissue(refreshToken);
        ResponseCookie cookie = ResponseCookie.from("refreshToken", tokenDto.getRefreshToken())
                .httpOnly(true)
                .path("/api/auth/reissue")
                .maxAge(604800) // 1 days
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.TOKEN_REISSUED, tokenDto));
    }

    /* Naver 로그인/회원가입 */
    @GetMapping("/naver")
    public void naverLogin(@RequestParam("code") String code, @RequestParam("state") String state, HttpServletResponse response) throws IOException {
        TokenDto tokenDto = authService.naverLogin(code, state);
        ResponseCookie cookie = ResponseCookie.from("refreshToken", tokenDto.getRefreshToken())
                .httpOnly(true)
                .path("/")
                .maxAge(604800) // 1 days
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
    public ResponseEntity<ApiResponse<TokenDto>> googleLogin(@RequestBody GoogleIdTokenDto requestDto) {
        TokenDto tokenDto = authService.googleLogin(requestDto.getIdToken());
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK, tokenDto));
    }

    /* 로그아웃 */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestHeader("Authorization") String accessToken) {
        authService.logout(accessToken.substring(7));
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK));
    }
}
