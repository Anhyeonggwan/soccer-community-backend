package com.soccercommunity.api.user.controller;

import com.soccercommunity.api.common.response.ApiResponse;
import com.soccercommunity.api.common.response.SuccessCode;
import com.soccercommunity.api.user.dto.LoginResponseDto;
import com.soccercommunity.api.user.dto.ModifyNickNameDto;
import com.soccercommunity.api.user.service.AuthService;
import com.soccercommunity.api.user.service.UserService;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;




@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final AuthService authService;
    private final UserService userService;

    /* 나의 정보 가져오기 */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<LoginResponseDto>> getMe(@RequestHeader("Authorization") String accessToken) {
        LoginResponseDto loginResponseDto = authService.getMe(accessToken.substring(7));
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK, loginResponseDto));
    }

    /* 로그아웃 */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestHeader("Authorization") String accessToken, HttpServletResponse response) {
        authService.logout(accessToken.substring(7));

        // 브라우저의 refreshToken 쿠키를 삭제하는 로직
        ResponseCookie cookie = ResponseCookie.from("refreshToken", "")
                .maxAge(0)
                .path("/")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK));
    }

    /* 닉네임 수정 */
    @PutMapping("/modifyNickname")
    public ResponseEntity<ApiResponse<Void>> modifyNickname(@RequestBody ModifyNickNameDto modifyNickNameDto) {
        userService.modifyNickname(modifyNickNameDto.getEmail(), modifyNickNameDto.getNickname());
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK));
    }

    /* 닉네임 중복 체크 */
    @GetMapping("/check-nickname")
    public ResponseEntity<ApiResponse<Void>> checkNickName(@RequestParam(name = "nickname") String nickname) {
        authService.checkNickName(nickname);
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK));
    }

    /* 이메일 중복 체크 */
    @GetMapping("/check-email")
    public ResponseEntity<ApiResponse<Void>> checkEmail(@RequestParam(name = "email") String email) {
        authService.checkEmail(email);
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK));
    }

}