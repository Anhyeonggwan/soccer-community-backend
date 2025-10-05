package com.soccercommunity.api.user.controller;

import com.soccercommunity.api.user.dto.ReissueRequestDto;
import com.soccercommunity.api.user.dto.SignUpRequestDto;
import com.soccercommunity.api.user.dto.TokenDto;
import com.soccercommunity.api.common.response.ApiResponse;
import com.soccercommunity.api.common.response.SuccessCode;
import com.soccercommunity.api.user.dto.GoogleIdTokenDto;
import com.soccercommunity.api.user.dto.LinkGoogleRequestDto;
import com.soccercommunity.api.user.dto.LoginRequestDto;
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
        ApiResponse<Void> response = ApiResponse.success(SuccessCode.SIGN_UP_SUCCESS);
        return new ResponseEntity<>(response, SuccessCode.SIGN_UP_SUCCESS.getStatus());
    }

    /* 로그인 */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<TokenDto>> login(@Valid @RequestBody LoginRequestDto loginRequestDto) {
        TokenDto tokenDto = authService.login(loginRequestDto.getEmail(), loginRequestDto.getPassword());
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK, tokenDto));
    }

    /* 토큰 재발급 */
    @PostMapping("/reissue")
    public ApiResponse<TokenDto> reissue(@RequestBody ReissueRequestDto request) {
        return ApiResponse.success(SuccessCode.TOKEN_REISSUED, authService.reissue(request));
    }

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
