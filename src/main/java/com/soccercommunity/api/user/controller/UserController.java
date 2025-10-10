package com.soccercommunity.api.user.controller;

import com.soccercommunity.api.common.response.ApiResponse;
import com.soccercommunity.api.common.response.SuccessCode;
import com.soccercommunity.api.user.dto.ModifyNickNameDto;
import com.soccercommunity.api.user.service.AuthService;
import com.soccercommunity.api.user.service.UserService;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;



@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final AuthService authService;
    private final UserService userService;

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