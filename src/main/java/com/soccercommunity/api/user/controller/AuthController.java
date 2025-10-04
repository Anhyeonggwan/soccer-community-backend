package com.soccercommunity.api.user.controller;

import com.soccercommunity.api.common.response.ApiResponse;
import com.soccercommunity.api.common.response.SuccessCode;
import com.soccercommunity.api.user.dto.GoogleSignUpRequestDto;
import com.soccercommunity.api.user.dto.LoginRequestDto;
import com.soccercommunity.api.user.dto.ReissueRequestDto;
import com.soccercommunity.api.user.dto.SignUpRequestDto;
import com.soccercommunity.api.user.dto.TokenDto;
import com.soccercommunity.api.user.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /* 회원가입 */
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<Void>> signUp(@Valid @RequestBody SignUpRequestDto requestDto) {
        authService.signUp(requestDto);
        ApiResponse<Void> response = ApiResponse.success(SuccessCode.SIGNUP_SUCCESS);
        return new ResponseEntity<>(response, SuccessCode.SIGNUP_SUCCESS.getStatus());
    }

    /* google 회원가입 */
    @PostMapping("/google-signup")
    public ResponseEntity<ApiResponse<Void>> googleSignup(@RequestBody GoogleSignUpRequestDto requestDto) {
        authService.googleSignUp(requestDto);
        ApiResponse<Void> response = ApiResponse.success(SuccessCode.SIGNUP_SUCCESS);
        return new ResponseEntity<>(response, SuccessCode.SIGNUP_SUCCESS.getStatus());
    }

    /* google 로그인 */
    @PostMapping("/google-login")
    public ResponseEntity<ApiResponse<Void>> postMethodName(@RequestBody String entity) {
        //TODO: process POST request
        
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK));
    }

    /* 로그인 */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<TokenDto>> login(@Valid @RequestBody LoginRequestDto loginRequestDto) {
        TokenDto tokenDto = authService.login(loginRequestDto.getEmail(), loginRequestDto.getPassword());
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK, tokenDto));
    }

    /* 토큰 재발급 */
    @PostMapping("/reissue")
    public ResponseEntity<ApiResponse<TokenDto>> reissue(@RequestBody ReissueRequestDto tokenRequestDto) {
        TokenDto newTokenDto = authService.reissue(tokenRequestDto);
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK, newTokenDto));
    }

    /* 로그아웃 */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestHeader("Authorization") String accessToken) {
        authService.logout(accessToken.substring(7));
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK));
    }
}
