package com.soccercommunity.api.user.controller;

import com.soccercommunity.api.common.response.ApiResponse;
import com.soccercommunity.api.common.response.SuccessCode;
import com.soccercommunity.api.user.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final AuthService authService;

    /* 닉네임 중복 체크 */
    @GetMapping("/check-nickname")
    public ResponseEntity<ApiResponse<Void>> checkNickName(@RequestParam(name = "nickname") String nickname) {
        // TODO: 닉네임 중복 체크 로직 추가 필요
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK));
    }

    /* 이메일 중복 체크 */
    @GetMapping("/check-email")
    public ResponseEntity<ApiResponse<Void>> checkEmail(@RequestParam(name = "email") String email) {
        authService.checkEmail(email);
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK));
    }

    /* 이메일 인증 요청 */
    @PostMapping("/email-auth")
    public ResponseEntity<ApiResponse<String>> requestEmailAuth(@RequestBody String email) {
        // TODO: 이메일 인증 요청 처리 로직 추가 필요
        // 현재는 요청받은 이메일을 그대로 반환합니다.
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK, email));
    }
}